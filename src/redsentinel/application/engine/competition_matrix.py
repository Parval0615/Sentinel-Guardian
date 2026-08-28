"""Two-model, three-seed competition evidence matrix for real OpenManus."""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Literal, TypeAlias
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from redsentinel.application.contracts import AgentRegistration, EvaluationRequest
from redsentinel.application.engine.service import ProductEvaluationService


P1FailureKind: TypeAlias = Literal[
    "none",
    "security_failure",
    "business_failure",
    "model_refusal",
    "environment_failure",
    "runtime_failure",
    "evaluator_failure",
    "not_applicable",
]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ModelSlot(_Model):
    slot_id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    env_prefix: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$")


class CompetitionMatrix(_Model):
    schema_version: Literal["competition-model-matrix-v0.1"]
    matrix_id: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    benchmark_id: str
    benchmark_version: str
    agent_id: str
    image: str
    timeout_seconds: int = Field(ge=1)
    seeds: list[int]
    scenarios: list[str]
    models: list[ModelSlot]

    @model_validator(mode="after")
    def require_2x3x4(self) -> CompetitionMatrix:
        dimensions = (
            ("model slots", self.models, 2, [item.slot_id for item in self.models]),
            ("seeds", self.seeds, 3, self.seeds),
            ("scenarios", self.scenarios, 4, self.scenarios),
        )
        for label, values, expected, identities in dimensions:
            if len(values) != expected or len(set(identities)) != expected:
                raise ValueError(f"competition matrix requires {expected} distinct {label}")
        return self


class CellMeasurements(_Model):
    model: str
    provider_host: str
    failure_kind: P1FailureKind = "none"
    baseline_asr: float | None = Field(default=None, ge=0, le=1)
    guarded_asr: float | None = Field(default=None, ge=0, le=1)
    fpr: float | None = Field(default=None, ge=0, le=1)
    clean_utility: float | None = Field(default=None, ge=0, le=1)
    pair_completeness: float | None = Field(default=None, ge=0, le=1)
    runtime_errors: int = Field(default=0, ge=0)
    refusals: int = Field(default=0, ge=0)
    model_calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    report_ref: str
    evidence_refs: list[str] = Field(default_factory=list)


class MatrixCell(_Model):
    schema_version: Literal["competition-matrix-cell-v0.1"] = (
        "competition-matrix-cell-v0.1"
    )
    cell_id: str
    model_slot: str
    seed: int
    scenarios: list[str]
    status: Literal["completed", "skipped", "failed"]
    failure_kind: P1FailureKind
    model: str | None = None
    provider_host: str | None = None
    baseline_asr: float | None = None
    guarded_asr: float | None = None
    fpr: float | None = None
    clean_utility: float | None = None
    pair_completeness: float | None = None
    runtime_errors: int = 0
    refusals: int = 0
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    report_ref: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    error: str | None = None
    started_at: str
    completed_at: str


class MatrixSummary(_Model):
    schema_version: Literal["competition-matrix-summary-v0.1"] = (
        "competition-matrix-summary-v0.1"
    )
    matrix_id: str
    expected_cells: int
    completed_cells: int
    skipped_cells: int
    failed_cells: int
    resumed_cells: int
    model_aggregates: dict[str, dict[str, Any]]
    cells: list[MatrixCell]
    evidence_index_ref: str
    generated_at: str


@dataclass(frozen=True)
class ModelCredentials:
    api_key: str
    base_url: str
    model: str

    @property
    def provider_host(self) -> str:
        return urlparse(self.base_url).netloc


class MatrixCellError(RuntimeError):
    def __init__(self, kind: P1FailureKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind


CellExecutor = Callable[
    [CompetitionMatrix, ModelSlot, int, ModelCredentials],
    CellMeasurements,
]


class CompetitionMatrixRunner:
    def __init__(self, output_root: str | Path, executor: CellExecutor) -> None:
        self.output_root = Path(output_root)
        self.executor = executor

    def run(
        self,
        matrix: CompetitionMatrix,
        *,
        environment: Mapping[str, str] | None = None,
        resume: bool = True,
    ) -> MatrixSummary:
        environment = environment or os.environ
        root = self.output_root / matrix.matrix_id
        _write_json(root / "matrix-config.json", matrix.model_dump(mode="json"))
        cells: list[MatrixCell] = []
        resumed = 0
        for slot in matrix.models:
            for seed in matrix.seeds:
                path = root / "cells" / f"{slot.slot_id}-seed-{seed}.json"
                previous = _completed_cell(path) if resume else None
                if previous is not None:
                    cells.append(previous)
                    resumed += 1
                    continue
                credentials, missing = _credentials(slot, environment)
                if credentials is None:
                    cell = _failed_cell(
                        matrix,
                        slot,
                        seed,
                        "skipped",
                        "environment_failure",
                        f"missing model environment: {', '.join(missing)}",
                    )
                else:
                    cell = self._execute(matrix, slot, seed, credentials)
                _write_json(path, cell.model_dump(mode="json"))
                cells.append(cell)

        evidence_path = root / "evidence-index.json"
        summary = MatrixSummary(
            matrix_id=matrix.matrix_id,
            expected_cells=len(matrix.models) * len(matrix.seeds),
            completed_cells=sum(item.status == "completed" for item in cells),
            skipped_cells=sum(item.status == "skipped" for item in cells),
            failed_cells=sum(item.status == "failed" for item in cells),
            resumed_cells=resumed,
            model_aggregates={
                slot.slot_id: _aggregate(slot.slot_id, cells) for slot in matrix.models
            },
            cells=cells,
            evidence_index_ref=str(evidence_path),
            generated_at=_now(),
        )
        summary_path = root / "summary.json"
        _write_json(summary_path, summary.model_dump(mode="json"))
        refs = [
            ("matrix_config", root / "matrix-config.json"),
            ("summary", summary_path),
            *[
                ("cell_result", root / "cells" / f"{item.cell_id}.json")
                for item in cells
            ],
            *[
                ("runtime_evidence", Path(ref))
                for item in cells
                for ref in ([item.report_ref] if item.report_ref else []) + item.evidence_refs
            ],
        ]
        _write_json(
            evidence_path,
            {
                "schema_version": "competition-matrix-evidence-index-v0.1",
                "matrix_id": matrix.matrix_id,
                "generated_at": _now(),
                "artifacts": _evidence(refs),
            },
        )
        return summary

    def _execute(
        self,
        matrix: CompetitionMatrix,
        slot: ModelSlot,
        seed: int,
        credentials: ModelCredentials,
    ) -> MatrixCell:
        started = _now()
        try:
            measurements = self.executor(matrix, slot, seed, credentials)
        except subprocess.TimeoutExpired as exc:
            return _failed_cell(
                matrix,
                slot,
                seed,
                "skipped",
                "runtime_failure",
                f"cell timed out after {exc.timeout}s",
                started,
            )
        except MatrixCellError as exc:
            return _failed_cell(
                matrix, slot, seed, "failed", exc.kind, str(exc), started
            )
        except Exception as exc:
            return _failed_cell(
                matrix,
                slot,
                seed,
                "failed",
                "evaluator_failure",
                f"{type(exc).__name__}: {exc}",
                started,
            )
        return MatrixCell(
            cell_id=f"{slot.slot_id}-seed-{seed}",
            model_slot=slot.slot_id,
            seed=seed,
            scenarios=matrix.scenarios,
            status="completed",
            started_at=started,
            completed_at=_now(),
            **measurements.model_dump(mode="python"),
        )


class OpenManusCellExecutor:
    def __init__(self, storage_root: str | Path) -> None:
        self.service = ProductEvaluationService(storage_root=storage_root)

    def __call__(
        self,
        matrix: CompetitionMatrix,
        slot: ModelSlot,
        seed: int,
        credentials: ModelCredentials,
    ) -> CellMeasurements:
        tenant = f"{matrix.matrix_id}-{slot.slot_id}-seed-{seed}"
        with _model_environment(matrix, credentials):
            try:
                agent = self.service.get_agent(matrix.agent_id, tenant)
            except (FileNotFoundError, ValueError):
                agent = self.service.register_agent(
                    AgentRegistration(
                        tenant_id=tenant,
                        username=tenant,
                        agent_id=matrix.agent_id,
                        name=f"OpenManus matrix {slot.slot_id}",
                        framework="OpenManus",
                        adapter_type="openmanus",
                        status="ready",
                        data_boundary={
                            "deployment": "docker_real_runtime",
                            "runtime_mode": "openmanus_real",
                            "no_real_external_attack": True,
                        },
                    )
                )
            status = self.service.run_evaluation(
                EvaluationRequest(
                    tenant_id=tenant,
                    agent_id=agent.agent_id,
                    benchmark_id=matrix.benchmark_id,
                    benchmark_version=matrix.benchmark_version,
                    mode="openmanus_real",
                    defense_enabled=True,
                    seed=seed,
                    scenarios=matrix.scenarios,
                )
            )
            if status.status != "completed" or not status.report_id:
                raise MatrixCellError(
                    "evaluator_failure",
                    status.error or f"evaluation failed: {status.evaluation_id}",
                )
            report = self.service.get_report(status.report_id, tenant_id=tenant)

        summary = report.summary
        runtime_errors = int(summary.get("baseline_runtime_error_count") or 0) + int(
            summary.get("runtime_error_count") or 0
        )
        refusals = int(summary.get("baseline_refusal_count") or 0) + int(
            summary.get("guarded_refusal_count") or 0
        )
        kind: P1FailureKind = "none"
        if runtime_errors:
            kind = "runtime_failure"
        elif refusals:
            kind = "model_refusal"
        elif report.attack_success_rate > 0:
            kind = "security_failure"
        elif report.false_positive_rate > 0:
            kind = "business_failure"
        usage = _runtime_usage(report.artifacts.trajectory_refs)
        return CellMeasurements(
            model=credentials.model,
            provider_host=credentials.provider_host,
            failure_kind=kind,
            baseline_asr=_rate(summary.get("baseline_attack_success_rate")),
            guarded_asr=report.attack_success_rate,
            fpr=report.false_positive_rate,
            clean_utility=1.0 - report.false_positive_rate,
            pair_completeness=_rate(summary.get("pair_completeness")),
            runtime_errors=runtime_errors,
            refusals=refusals,
            report_ref=report.artifacts.report_path,
            evidence_refs=[
                *report.artifacts.trajectory_refs,
                *report.artifacts.audit_refs,
            ],
            **usage,
        )


def load_competition_matrix(path: str | Path) -> CompetitionMatrix:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("competition matrix config must contain one object")
    return CompetitionMatrix.model_validate(payload)


def _credentials(
    slot: ModelSlot, environment: Mapping[str, str]
) -> tuple[ModelCredentials | None, list[str]]:
    names = {
        "api_key": f"{slot.env_prefix}_API_KEY",
        "base_url": f"{slot.env_prefix}_BASE_URL",
        "model": f"{slot.env_prefix}_MODEL",
    }
    values = {key: str(environment.get(name) or "").strip() for key, name in names.items()}
    missing = [name for key, name in names.items() if not values[key]]
    if missing:
        return None, missing
    parsed = urlparse(values["base_url"])
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{names['base_url']} must be an HTTP(S) URL with a host")
    return ModelCredentials(**values), []


@contextmanager
def _model_environment(
    matrix: CompetitionMatrix, credentials: ModelCredentials
) -> Iterator[None]:
    updates = {
        "OPENAI_API_KEY": credentials.api_key,
        "OPENAI_BASE_URL": credentials.base_url,
        "OPENAI_MODEL": credentials.model,
        "RED_SENTINEL_OPENMANUS_IMAGE": matrix.image,
        "RED_SENTINEL_OPENMANUS_TIMEOUT_SECONDS": str(matrix.timeout_seconds),
    }
    previous = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _failed_cell(
    matrix: CompetitionMatrix,
    slot: ModelSlot,
    seed: int,
    status: Literal["skipped", "failed"],
    kind: P1FailureKind,
    error: str,
    started_at: str | None = None,
) -> MatrixCell:
    return MatrixCell(
        cell_id=f"{slot.slot_id}-seed-{seed}",
        model_slot=slot.slot_id,
        seed=seed,
        scenarios=matrix.scenarios,
        status=status,
        failure_kind=kind,
        error=error[:500],
        started_at=started_at or _now(),
        completed_at=_now(),
    )


def _completed_cell(path: Path) -> MatrixCell | None:
    if not path.is_file():
        return None
    try:
        cell = MatrixCell.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return cell if cell.status == "completed" else None


def _aggregate(slot: str, cells: list[MatrixCell]) -> dict[str, Any]:
    selected = [item for item in cells if item.model_slot == slot]
    valid = [
        item
        for item in selected
        if item.status == "completed"
        and item.failure_kind in {"none", "security_failure", "business_failure"}
    ]
    return {
        "completed_cells": sum(item.status == "completed" for item in selected),
        "valid_metric_cells": len(valid),
        "failure_counts": dict(sorted(Counter(item.failure_kind for item in selected).items())),
        **{
            name: _stats(getattr(item, name) for item in valid)
            for name in (
                "baseline_asr",
                "guarded_asr",
                "fpr",
                "clean_utility",
                "pair_completeness",
            )
        },
    }


def _stats(values: Iterator[float | None]) -> dict[str, float | int | None]:
    measured = [value for value in values if value is not None and math.isfinite(value)]
    return {
        "count": len(measured),
        "mean": mean(measured) if measured else None,
        "stddev": pstdev(measured) if measured else None,
        "minimum": min(measured) if measured else None,
        "maximum": max(measured) if measured else None,
    }


def _runtime_usage(refs: list[str]) -> dict[str, int]:
    totals = {"model_calls": 0, "input_tokens": 0, "output_tokens": 0}
    for ref in refs:
        try:
            payload = json.loads(Path(ref).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for run in payload.values() if isinstance(payload, dict) else []:
            meta = run.get("runtime_meta") if isinstance(run, dict) else None
            if not isinstance(meta, dict):
                continue
            totals["model_calls"] += int(meta.get("llm_call_completed_count") or 0)
            totals["input_tokens"] += int(meta.get("llm_input_tokens") or 0)
            totals["output_tokens"] += int(meta.get("llm_output_tokens") or 0)
    return totals


def _evidence(items: list[tuple[str, Path]]) -> list[dict[str, Any]]:
    artifacts, seen = [], set()
    for role, path in items:
        if str(path) in seen:
            continue
        seen.add(str(path))
        available = path.is_file()
        artifacts.append(
            {
                "role": role,
                "path": str(path),
                "available": available,
                "sha256": _sha256(path) if available else None,
            }
        )
    return artifacts


def _rate(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = float(value)
        return value if math.isfinite(value) and 0 <= value <= 1 else None
    return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = [
    "CellMeasurements",
    "CompetitionMatrix",
    "CompetitionMatrixRunner",
    "MatrixCell",
    "MatrixCellError",
    "MatrixSummary",
    "ModelCredentials",
    "ModelSlot",
    "OpenManusCellExecutor",
    "load_competition_matrix",
]
