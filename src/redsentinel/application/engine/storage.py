from __future__ import annotations

import json
import os
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

import fcntl

from redsentinel.application.contracts import AgentLibraryEntry, AuthUserRecord


_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_SECRET_FIELD_NAMES = {
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
    "bearer_token",
    "client_secret",
}


class ProductStorage:
    def __init__(self, storage_root: str | Path = "runs/product") -> None:
        self.root = Path(storage_root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._image_profile_locks: dict[Path, threading.Lock] = {}
        self._image_profile_locks_guard = threading.Lock()

    def tenant_dir(self, tenant_id: str) -> Path:
        return self.root / safe_component(tenant_id, "tenant_id")

    def agent_path(self, tenant_id: str, agent_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "agents" / f"{safe_component(agent_id, 'agent_id')}.json"

    def agent_asset_index_path(self, tenant_id: str, agent_id: str) -> Path:
        return (
            self.tenant_dir(tenant_id)
            / "agent_asset_index"
            / "current"
            / f"{safe_component(agent_id, 'agent_id')}.json"
        )

    def agent_asset_index_version_path(
        self,
        tenant_id: str,
        agent_id: str,
        digest_suffix: str,
    ) -> Path:
        return (
            self.tenant_dir(tenant_id)
            / "agent_asset_index"
            / "versions"
            / safe_component(agent_id, "agent_id")
            / f"{safe_component(digest_suffix, 'digest_suffix')}.json"
        )

    def agent_asset_index_errors_path(self, tenant_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "agent_asset_index" / "errors.json"

    def agent_asset_suppression_path(self, tenant_id: str, agent_id: str) -> Path:
        return (
            self.tenant_dir(tenant_id)
            / "agent_asset_index"
            / "suppressed"
            / f"{safe_component(agent_id, 'agent_id')}.json"
        )

    def managed_agent_assets_dir(self, tenant_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "managed_agent_assets"

    def managed_agent_asset_dir(
        self,
        tenant_id: str,
        agent_id: str,
        digest_suffix: str,
    ) -> Path:
        return (
            self.managed_agent_assets_dir(tenant_id)
            / safe_component(agent_id, "agent_id")
            / safe_component(digest_suffix, "digest_suffix")
        )

    def image_profile_dir(
        self,
        tenant_id: str,
        agent_id: str,
        digest_suffix: str,
    ) -> Path:
        return (
            self.tenant_dir(tenant_id)
            / "image_profiles"
            / safe_component(agent_id, "agent_id")
            / safe_component(digest_suffix, "digest_suffix")
        )

    def image_profile_status_path(
        self,
        tenant_id: str,
        agent_id: str,
        digest_suffix: str,
    ) -> Path:
        return self.image_profile_dir(tenant_id, agent_id, digest_suffix) / "status.json"

    def image_profile_latest_path(self, tenant_id: str, agent_id: str) -> Path:
        return (
            self.tenant_dir(tenant_id)
            / "image_profiles"
            / safe_component(agent_id, "agent_id")
            / "latest.json"
        )

    def image_profile_checkpoint_path(
        self,
        tenant_id: str,
        agent_id: str,
        digest_suffix: str,
        stage: str,
    ) -> Path:
        return (
            self.image_profile_dir(tenant_id, agent_id, digest_suffix)
            / "checkpoints"
            / f"{safe_component(stage, 'stage')}.json"
        )

    def image_profile_artifact_path(
        self,
        tenant_id: str,
        agent_id: str,
        digest_suffix: str,
        name: str,
    ) -> Path:
        return (
            self.image_profile_dir(tenant_id, agent_id, digest_suffix)
            / "artifacts"
            / f"{safe_component(name, 'artifact_name')}.json"
        )

    def image_profile_unpack_root(
        self,
        tenant_id: str,
        agent_id: str,
        digest_suffix: str,
    ) -> Path:
        return self.image_profile_dir(tenant_id, agent_id, digest_suffix) / "unpack"

    def image_profile_lease_path(
        self,
        tenant_id: str,
        agent_id: str,
        digest_suffix: str,
    ) -> Path:
        return self.image_profile_dir(tenant_id, agent_id, digest_suffix) / "lease.json"

    @contextmanager
    def image_profile_lease(
        self,
        tenant_id: str,
        agent_id: str,
        digest_suffix: str,
    ) -> Iterator[bool]:
        path = self.image_profile_lease_path(tenant_id, agent_id, digest_suffix)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._image_profile_locks_guard:
            process_lock = self._image_profile_locks.setdefault(
                path,
                threading.Lock(),
            )
        if not process_lock.acquire(blocking=False):
            yield False
            return
        handle = path.open("a+", encoding="utf-8")
        try:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            acquired_at = datetime.now(timezone.utc).isoformat()
            handle.seek(0)
            handle.truncate()
            json.dump(
                {
                    "schema_version": "image-profile-lease-v0.1",
                    "pid": os.getpid(),
                    "acquired_at": acquired_at,
                    "released_at": None,
                },
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            handle.flush()
            os.fsync(handle.fileno())
            try:
                yield True
            finally:
                handle.seek(0)
                handle.truncate()
                json.dump(
                    {
                        "schema_version": "image-profile-lease-v0.1",
                        "pid": os.getpid(),
                        "acquired_at": acquired_at,
                        "released_at": datetime.now(timezone.utc).isoformat(),
                    },
                    handle,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                handle.flush()
                os.fsync(handle.fileno())
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
            process_lock.release()

    def user_path(self, user_id: str) -> Path:
        return self.root / "users" / f"{safe_component(user_id, 'user_id')}.json"

    def user_paths(self) -> list[Path]:
        return sorted((self.root / "users").glob("*.json"))

    def material_path(self, tenant_id: str, material_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "materials" / f"{safe_component(material_id, 'material_id')}.json"

    def profile_path(self, tenant_id: str, profile_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "profiles" / f"{safe_component(profile_id, 'profile_id')}.json"

    def benchmark_path(self, benchmark_id: str) -> Path:
        return self.root / "benchmarks" / f"{safe_component(benchmark_id, 'benchmark_id')}.json"

    def benchmark_version_path(self, benchmark_id: str, version: str) -> Path:
        return (
            self.root
            / "benchmarks"
            / safe_component(benchmark_id, "benchmark_id")
            / "versions"
            / f"{safe_component(version, 'version')}.json"
        )

    def benchmark_paths(self) -> list[Path]:
        return sorted((self.root / "benchmarks").glob("*.json"))

    def benchmark_version_paths(self, benchmark_id: str) -> list[Path]:
        return sorted(
            (
                self.root
                / "benchmarks"
                / safe_component(benchmark_id, "benchmark_id")
                / "versions"
            ).glob("*.json")
        )

    def agent_library_path(self, agent_id: str) -> Path:
        return self.root / "agent_library" / f"{safe_component(agent_id, 'agent_id')}.json"

    def agent_library_paths(self) -> list[Path]:
        return sorted((self.root / "agent_library").glob("*.json"))

    def session_path(self, tenant_id: str, session_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "sessions" / f"{safe_component(session_id, 'session_id')}.json"

    def evaluation_dir(self, tenant_id: str, evaluation_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "evaluations" / safe_component(evaluation_id, "evaluation_id")





































    def audit_dir(self, tenant_id: str, audit_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "audits" / safe_component(audit_id, "audit_id")

    def audit_record_path(self, tenant_id: str, audit_id: str) -> Path:
        return self.audit_dir(tenant_id, audit_id) / "audit.json"

    def audit_task_path(self, tenant_id: str, audit_id: str) -> Path:
        return self.audit_dir(tenant_id, audit_id) / "task.json"

    def audit_plan_path(self, tenant_id: str, audit_id: str) -> Path:
        return self.audit_dir(tenant_id, audit_id) / "plan.json"

    def audit_planner_call_path(self, tenant_id: str, audit_id: str) -> Path:
        return self.audit_dir(tenant_id, audit_id) / "planner-call.json"

    def audit_defense_plan_path(self, tenant_id: str, audit_id: str) -> Path:
        return self.audit_dir(tenant_id, audit_id) / "defense-plan.json"

    def audit_remediation_bundle_path(self, tenant_id: str, audit_id: str) -> Path:
        return self.audit_dir(tenant_id, audit_id) / "remediation-bundle.json"

    def audit_remediation_policy_path(self, tenant_id: str, audit_id: str) -> Path:
        return self.audit_dir(tenant_id, audit_id) / "sandbox" / "remediation-policy.json"

    def audit_remediation_installation_path(self, tenant_id: str, audit_id: str) -> Path:
        return self.audit_dir(tenant_id, audit_id) / "remediation-installation.json"

    def audit_decision_path(self, tenant_id: str, audit_id: str) -> Path:
        return self.audit_dir(tenant_id, audit_id) / "release-decision.json"

    def audit_evidence_index_path(self, tenant_id: str, audit_id: str) -> Path:
        return self.audit_dir(tenant_id, audit_id) / "evidence-index.json"

    def audit_record_paths(self, tenant_id: str) -> list[Path]:
        return sorted((self.tenant_dir(tenant_id) / "audits").glob("*/audit.json"))

    def evaluation_record_path(self, tenant_id: str, evaluation_id: str) -> Path:
        return self.evaluation_dir(tenant_id, evaluation_id) / "evaluation.json"

    def result_path(self, tenant_id: str, evaluation_id: str, result_id: str) -> Path:
        return self.evaluation_dir(tenant_id, evaluation_id) / "results" / f"{safe_component(result_id, 'result_id')}.json"

    def report_path(self, tenant_id: str, report_id: str) -> Path:
        return self.evaluation_dir(tenant_id, report_id) / "agent-security-report-v0.1.json"

    def report_record_path(self, tenant_id: str, report_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "reports" / f"{safe_component(report_id, 'report_id')}.json"

    def metric_snapshot_path(self, tenant_id: str, snapshot_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "metric_snapshots" / f"{safe_component(snapshot_id, 'snapshot_id')}.json"

    def report_record_paths(self, tenant_id: str) -> list[Path]:
        return sorted((self.tenant_dir(tenant_id) / "reports").glob("*.json"))

    def metric_snapshot_paths(self, tenant_id: str) -> list[Path]:
        return sorted((self.tenant_dir(tenant_id) / "metric_snapshots").glob("*.json"))

    def comparison_dir(self, tenant_id: str, comparison_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "comparisons" / safe_component(comparison_id, "comparison_id")

    def uploaded_trajectory_path(self, tenant_id: str, trajectory_id: str) -> Path:
        return self.tenant_dir(tenant_id) / "uploaded_trajectories" / f"{safe_component(trajectory_id, 'trajectory_id')}.json"

    def find_report_path(self, report_id: str, *, tenant_id: str | None = None) -> Path:
        report_id = safe_component(report_id, "report_id")
        if tenant_id is not None:
            path = self.report_path(tenant_id, report_id)
            if not path.exists():
                raise ValueError(f"Report not found: {tenant_id}/{report_id}")
            return path

        matches = sorted(self.root.glob(f"*/evaluations/{report_id}/agent-security-report-v0.1.json"))
        if not matches:
            raise ValueError(f"Report not found: {report_id}")
        if len(matches) > 1:
            raise ValueError("tenant_id is required when report_id is not globally unique.")
        return matches[0]

    def read_json(self, path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    def write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            temporary.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def write_user(self, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        document = dict(payload)
        document.setdefault("user_id", user_id)
        if document["user_id"] != user_id:
            raise ValueError("User ID mismatch.")

        user = AuthUserRecord.model_validate(document).model_dump(mode="json")
        self.ensure_user_unique(user["username"], user["email"], exclude_user_id=user["user_id"])
        self.write_json(self.user_path(user["user_id"]), user)
        return user

    def read_user(self, user_id: str) -> dict[str, Any]:
        return AuthUserRecord.model_validate(self.read_json(self.user_path(user_id))).model_dump(mode="json")

    def find_user_by_username(self, username: str) -> dict[str, Any] | None:
        target = normalize_lookup(username)
        for user in self._iter_users():
            if normalize_lookup(user["username"]) == target:
                return user
        return None

    def find_user_by_email(self, email: str) -> dict[str, Any] | None:
        target = normalize_lookup(email)
        for user in self._iter_users():
            if normalize_lookup(user["email"]) == target:
                return user
        return None

    def ensure_user_unique(
        self,
        username: str,
        email: str,
        *,
        exclude_user_id: str | None = None,
    ) -> None:
        existing_username = self.find_user_by_username(username)
        if existing_username is not None and existing_username["user_id"] != exclude_user_id:
            raise ValueError("Username already exists.")

        existing_email = self.find_user_by_email(email)
        if existing_email is not None and existing_email["user_id"] != exclude_user_id:
            raise ValueError("Email already exists.")

    def _iter_users(self) -> list[dict[str, Any]]:
        return [
            AuthUserRecord.model_validate(self.read_json(path)).model_dump(mode="json")
            for path in self.user_paths()
        ]

    def write_agent(self, tenant_id: str, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        path = self.agent_path(tenant_id, agent_id)
        return self._write_document(
            path,
            payload,
            schema_version="agent-v0.1",
            tenant_id=tenant_id,
            username=tenant_id,
            agent_id=agent_id,
        )

    def read_agent(self, tenant_id: str, agent_id: str) -> dict[str, Any]:
        return self.read_json(self.agent_path(tenant_id, agent_id))

    def write_material(
        self,
        tenant_id: str,
        agent_id: str,
        material_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        path = self.material_path(tenant_id, material_id)
        return self._write_document(
            path,
            payload,
            schema_version="agent-material-v0.1",
            tenant_id=tenant_id,
            agent_id=agent_id,
            material_id=material_id,
        )

    def read_material(self, tenant_id: str, material_id: str) -> dict[str, Any]:
        return self.read_json(self.material_path(tenant_id, material_id))

    def write_profile(
        self,
        tenant_id: str,
        agent_id: str,
        profile_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        path = self.profile_path(tenant_id, profile_id)
        return self._write_document(
            path,
            payload,
            schema_version="agent-profile-v0.1",
            tenant_id=tenant_id,
            agent_id=agent_id,
            profile_id=profile_id,
        )

    def read_profile(self, tenant_id: str, profile_id: str) -> dict[str, Any]:
        return self.read_json(self.profile_path(tenant_id, profile_id))


























































    def write_audit(self, tenant_id: str, audit_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._write_document(
            self.audit_record_path(tenant_id, audit_id),
            payload,
            schema_version="audit-run-v0.1",
            tenant_id=tenant_id,
            audit_id=audit_id,
        )

    def read_audit(self, tenant_id: str, audit_id: str) -> dict[str, Any]:
        return self.read_json(self.audit_record_path(tenant_id, audit_id))

    def list_audits(self, tenant_id: str) -> list[dict[str, Any]]:
        return [self.read_json(path) for path in self.audit_record_paths(tenant_id)]

    def write_audit_task(self, tenant_id: str, audit_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._write_document(
            self.audit_task_path(tenant_id, audit_id),
            payload,
            schema_version="audit-task-v0.1",
            tenant_id=tenant_id,
            audit_id=audit_id,
        )

    def read_audit_task(self, tenant_id: str, audit_id: str) -> dict[str, Any]:
        return self.read_json(self.audit_task_path(tenant_id, audit_id))

    def write_audit_plan(self, tenant_id: str, audit_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        document = sanitize_secret_fields(payload)
        self.write_json(self.audit_plan_path(tenant_id, audit_id), document)
        return document

    def read_audit_plan(self, tenant_id: str, audit_id: str) -> dict[str, Any]:
        return self.read_json(self.audit_plan_path(tenant_id, audit_id))

    def write_audit_planner_call(
        self,
        tenant_id: str,
        audit_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._write_document(
            self.audit_planner_call_path(tenant_id, audit_id),
            payload,
            schema_version="audit-planner-call-evidence-v0.1",
            tenant_id=tenant_id,
            audit_id=audit_id,
        )

    def read_audit_planner_call(self, tenant_id: str, audit_id: str) -> dict[str, Any]:
        return self.read_json(self.audit_planner_call_path(tenant_id, audit_id))

    def write_audit_defense_plan(
        self,
        tenant_id: str,
        audit_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        document = sanitize_secret_fields(payload)
        self.write_json(self.audit_defense_plan_path(tenant_id, audit_id), document)
        return document

    def read_audit_defense_plan(self, tenant_id: str, audit_id: str) -> dict[str, Any]:
        return self.read_json(self.audit_defense_plan_path(tenant_id, audit_id))

    def write_audit_remediation_bundle(
        self,
        tenant_id: str,
        audit_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        document = sanitize_secret_fields(payload)
        self.write_json(self.audit_remediation_bundle_path(tenant_id, audit_id), document)
        return document

    def read_audit_remediation_bundle(
        self,
        tenant_id: str,
        audit_id: str,
    ) -> dict[str, Any]:
        return self.read_json(self.audit_remediation_bundle_path(tenant_id, audit_id))

    def write_audit_remediation_installation(
        self,
        tenant_id: str,
        audit_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        document = sanitize_secret_fields(payload)
        self.write_json(
            self.audit_remediation_installation_path(tenant_id, audit_id),
            document,
        )
        return document

    def read_audit_remediation_installation(
        self,
        tenant_id: str,
        audit_id: str,
    ) -> dict[str, Any]:
        return self.read_json(
            self.audit_remediation_installation_path(tenant_id, audit_id)
        )

    def write_audit_decision(
        self,
        tenant_id: str,
        audit_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._write_document(
            self.audit_decision_path(tenant_id, audit_id),
            payload,
            schema_version="release-decision-v0.1",
            audit_id=audit_id,
        )

    def read_audit_decision(self, tenant_id: str, audit_id: str) -> dict[str, Any]:
        return self.read_json(self.audit_decision_path(tenant_id, audit_id))

    def write_audit_evidence_index(
        self,
        tenant_id: str,
        audit_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        document = sanitize_secret_fields(payload)
        self.write_json(self.audit_evidence_index_path(tenant_id, audit_id), document)
        return document

    def read_audit_evidence_index(self, tenant_id: str, audit_id: str) -> dict[str, Any]:
        return self.read_json(self.audit_evidence_index_path(tenant_id, audit_id))

    def write_benchmark(self, benchmark_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        path = self.benchmark_path(benchmark_id)
        return self._write_document(path, payload, schema_version="benchmark-v0.1", benchmark_id=benchmark_id)

    def read_benchmark(self, benchmark_id: str) -> dict[str, Any]:
        return self.read_json(self.benchmark_path(benchmark_id))

    def write_benchmark_version(self, benchmark_id: str, version: str, payload: dict[str, Any]) -> dict[str, Any]:
        path = self.benchmark_version_path(benchmark_id, version)
        return self._write_document(
            path,
            payload,
            schema_version="benchmark-version-v0.1",
            benchmark_id=benchmark_id,
            version=version,
        )

    def read_benchmark_version(self, benchmark_id: str, version: str) -> dict[str, Any]:
        return self.read_json(self.benchmark_version_path(benchmark_id, version))

    def write_agent_library_entry(self, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        entry = AgentLibraryEntry.model_validate({**payload, "agent_id": agent_id}).model_dump(mode="json")
        self.write_json(self.agent_library_path(agent_id), entry)
        return entry

    def read_agent_library_entry(self, agent_id: str) -> dict[str, Any]:
        return AgentLibraryEntry.model_validate(self.read_json(self.agent_library_path(agent_id))).model_dump(mode="json")

    def list_agent_library_entries(self) -> list[dict[str, Any]]:
        return [
            AgentLibraryEntry.model_validate(self.read_json(path)).model_dump(mode="json")
            for path in self.agent_library_paths()
        ]

    def write_evaluation(
        self,
        tenant_id: str,
        agent_id: str,
        evaluation_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        path = self.evaluation_record_path(tenant_id, evaluation_id)
        return self._write_document(
            path,
            payload,
            schema_version="evaluation-v0.1",
            tenant_id=tenant_id,
            agent_id=agent_id,
            evaluation_id=evaluation_id,
        )

    def read_evaluation(self, tenant_id: str, evaluation_id: str) -> dict[str, Any]:
        return self.read_json(self.evaluation_record_path(tenant_id, evaluation_id))

    def write_result(
        self,
        tenant_id: str,
        evaluation_id: str,
        result_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        path = self.result_path(tenant_id, evaluation_id, result_id)
        return self._write_document(
            path,
            payload,
            schema_version="evaluation-result-v0.1",
            evaluation_id=evaluation_id,
            result_id=result_id,
        )

    def read_result(self, tenant_id: str, evaluation_id: str, result_id: str) -> dict[str, Any]:
        return self.read_json(self.result_path(tenant_id, evaluation_id, result_id))

    def write_report_record(
        self,
        tenant_id: str,
        agent_id: str,
        evaluation_id: str,
        report_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        path = self.report_record_path(tenant_id, report_id)
        return self._write_document(
            path,
            payload,
            schema_version="report-v0.1",
            tenant_id=tenant_id,
            agent_id=agent_id,
            evaluation_id=evaluation_id,
            report_id=report_id,
        )

    def read_report_record(self, tenant_id: str, report_id: str) -> dict[str, Any]:
        return self.read_json(self.report_record_path(tenant_id, report_id))

    def write_metric_snapshot(
        self,
        tenant_id: str,
        agent_id: str,
        snapshot_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        path = self.metric_snapshot_path(tenant_id, snapshot_id)
        return self._write_document(
            path,
            payload,
            schema_version="metric-snapshot-v0.1",
            tenant_id=tenant_id,
            agent_id=agent_id,
            snapshot_id=snapshot_id,
        )

    def read_metric_snapshot(self, tenant_id: str, snapshot_id: str) -> dict[str, Any]:
        return self.read_json(self.metric_snapshot_path(tenant_id, snapshot_id))

    def _write_document(
        self,
        path: Path,
        payload: dict[str, Any],
        *,
        schema_version: str,
        **ids: str,
    ) -> dict[str, Any]:
        document = document_payload(payload, schema_version=schema_version, **ids)
        self.write_json(path, document)
        return document


def safe_component(value: str, label: str) -> str:
    if value in {".", ".."} or not _SAFE_COMPONENT.match(value):
        raise ValueError(f"Unsafe {label}: {value}")
    return value


def normalize_lookup(value: str) -> str:
    return value.casefold()


def document_payload(payload: dict[str, Any], *, schema_version: str, **ids: str) -> dict[str, Any]:
    document = sanitize_secret_fields(payload)
    document.setdefault("schema_version", schema_version)
    document.setdefault("created_at", utc_now_iso())
    for key, value in ids.items():
        document.setdefault(key, value)
    return document


def sanitize_secret_fields(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if _is_secret_field(key):
                continue
            sanitized[key] = sanitize_secret_fields(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_secret_fields(item) for item in value]
    return value


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_secret_field(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if normalized in {"has_api_key", "masked_api_key"}:
        return False
    return normalized in _SECRET_FIELD_NAMES or normalized.endswith("_api_key")


__all__ = [
    "ProductStorage",
    "document_payload",
    "normalize_lookup",
    "safe_component",
    "sanitize_secret_fields",
]
