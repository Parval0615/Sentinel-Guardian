from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from redsentinel.apps.competition_matrix_cli import main
from redsentinel.application.engine.competition_matrix import (
    CellMeasurements,
    CompetitionMatrix,
    CompetitionMatrixRunner,
    ModelCredentials,
    ModelSlot,
    OpenManusCellExecutor,
    load_competition_matrix,
)


CONFIG = (
    Path(__file__).resolve().parents[3]
    / "configs"
    / "experiments"
    / "competition-p1-model-matrix-v1.yaml"
)


def _matrix() -> CompetitionMatrix:
    return load_competition_matrix(CONFIG)


def _environment() -> dict[str, str]:
    return {
        "RED_SENTINEL_MODEL_A_API_KEY": "secret-a",
        "RED_SENTINEL_MODEL_A_BASE_URL": "https://model-a.example.test/v1",
        "RED_SENTINEL_MODEL_A_MODEL": "model-a",
        "RED_SENTINEL_MODEL_B_API_KEY": "secret-b",
        "RED_SENTINEL_MODEL_B_BASE_URL": "https://model-b.example.test/v1",
        "RED_SENTINEL_MODEL_B_MODEL": "model-b",
    }


def test_competition_matrix_config_freezes_2x3x4_shape() -> None:
    matrix = _matrix()

    assert [item.slot_id for item in matrix.models] == ["model_a", "model_b"]
    assert matrix.seeds == [101, 211, 307]
    assert len(matrix.scenarios) == 4

    with pytest.raises(ValueError, match="3 distinct seeds"):
        CompetitionMatrix.model_validate(
            {**matrix.model_dump(), "seeds": [101, 211]}
        )


def test_missing_model_credentials_are_skipped_without_calling_executor(
    tmp_path: Path,
) -> None:
    def fail_if_called(*_args):
        raise AssertionError("executor must not run without model credentials")

    summary = CompetitionMatrixRunner(tmp_path, fail_if_called).run(
        _matrix(),
        environment={},
    )

    assert summary.expected_cells == 6
    assert summary.completed_cells == 0
    assert summary.skipped_cells == 6
    assert summary.failed_cells == 0
    assert all(item.failure_kind == "environment_failure" for item in summary.cells)
    assert Path(summary.evidence_index_ref).is_file()


def test_matrix_resumes_completed_cells_and_retries_timeout(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    timeout_once = {"enabled": True}

    def execute(
        matrix: CompetitionMatrix,
        slot: ModelSlot,
        seed: int,
        credentials: ModelCredentials,
    ) -> CellMeasurements:
        del matrix
        cell_id = f"{slot.slot_id}-seed-{seed}"
        calls.append(cell_id)
        if cell_id == "model_a-seed-211" and timeout_once["enabled"]:
            raise subprocess.TimeoutExpired(["docker", "run"], 300)
        evidence = tmp_path / "runtime" / f"{cell_id}.json"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text('{"runtime": "synthetic"}\n', encoding="utf-8")
        guarded_asr = 0.0 if slot.slot_id == "model_a" else 0.25
        return CellMeasurements(
            model=credentials.model,
            provider_host=credentials.provider_host,
            failure_kind="none" if guarded_asr == 0 else "security_failure",
            baseline_asr=1.0,
            guarded_asr=guarded_asr,
            fpr=0.0,
            clean_utility=1.0,
            pair_completeness=1.0,
            model_calls=12,
            input_tokens=100 + seed,
            output_tokens=20,
            report_ref=str(evidence),
        )

    runner = CompetitionMatrixRunner(tmp_path, execute)
    first = runner.run(_matrix(), environment=_environment())

    assert first.completed_cells == 5
    assert first.skipped_cells == 1
    assert first.model_aggregates["model_a"]["guarded_asr"]["count"] == 2
    assert first.model_aggregates["model_b"]["guarded_asr"]["mean"] == 0.25

    timeout_once["enabled"] = False
    calls.clear()
    second = runner.run(_matrix(), environment=_environment())

    assert calls == ["model_a-seed-211"]
    assert second.completed_cells == 6
    assert second.resumed_cells == 5
    assert second.model_aggregates["model_a"]["guarded_asr"]["count"] == 3
    assert second.model_aggregates["model_a"]["guarded_asr"]["stddev"] == 0.0
    evidence = json.loads(Path(second.evidence_index_ref).read_text(encoding="utf-8"))
    assert all(
        item["sha256"]
        for item in evidence["artifacts"]
        if item["available"]
    )
    serialized = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / _matrix().matrix_id).rglob("*.json")
    )
    assert "secret-a" not in serialized
    assert "secret-b" not in serialized


def test_openmanus_executor_scopes_model_environment_and_extracts_usage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trajectory = tmp_path / "trajectory.json"
    trajectory.write_text(
        json.dumps(
            {
                "baseline": {
                    "runtime_meta": {
                        "llm_call_completed_count": 2,
                        "llm_input_tokens": 80,
                        "llm_output_tokens": 10,
                    }
                },
                "clean": {
                    "runtime_meta": {
                        "llm_call_completed_count": 1,
                        "llm_input_tokens": 30,
                        "llm_output_tokens": 5,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    report = SimpleNamespace(
        summary={
            "baseline_attack_success_rate": 1.0,
            "pair_completeness": 1.0,
            "baseline_runtime_error_count": 0,
            "runtime_error_count": 0,
            "baseline_refusal_count": 0,
            "guarded_refusal_count": 0,
        },
        attack_success_rate=0.0,
        false_positive_rate=0.0,
        artifacts=SimpleNamespace(
            report_path=str(tmp_path / "report.json"),
            trajectory_refs=[str(trajectory)],
            audit_refs=[],
        ),
    )
    seen = {}

    class Service:
        def get_agent(self, agent_id, tenant):
            return SimpleNamespace(agent_id=agent_id)

        def run_evaluation(self, request):
            seen["request"] = request
            seen["model"] = os.environ["OPENAI_MODEL"]
            seen["api_key"] = os.environ["OPENAI_API_KEY"]
            return SimpleNamespace(status="completed", report_id="report-1")

        def get_report(self, report_id, *, tenant_id):
            assert report_id == "report-1"
            assert tenant_id
            return report

    executor = OpenManusCellExecutor(tmp_path)
    executor.service = Service()
    monkeypatch.setenv("OPENAI_MODEL", "previous-model")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    credentials = ModelCredentials(
        api_key="matrix-secret",
        base_url="https://matrix.example.test/v1",
        model="matrix-model",
    )

    result = executor(_matrix(), _matrix().models[0], 101, credentials)

    assert seen["model"] == "matrix-model"
    assert seen["api_key"] == "matrix-secret"
    assert seen["request"].seed == 101
    assert seen["request"].scenarios == _matrix().scenarios
    assert result.model_calls == 3
    assert result.input_tokens == 110
    assert result.output_tokens == 15
    assert os.environ["OPENAI_MODEL"] == "previous-model"
    assert "OPENAI_API_KEY" not in os.environ


def test_cli_writes_environment_skip_summary_without_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for slot in ("A", "B"):
        for suffix in ("API_KEY", "BASE_URL", "MODEL"):
            monkeypatch.delenv(f"RED_SENTINEL_MODEL_{slot}_{suffix}", raising=False)

    exit_code = main(
        [
            "--config",
            str(CONFIG),
            "--output-root",
            str(tmp_path),
        ]
    )

    assert exit_code == 2
    summary = json.loads(
        (tmp_path / _matrix().matrix_id / "summary.json").read_text(encoding="utf-8")
    )
    assert summary["skipped_cells"] == 6
