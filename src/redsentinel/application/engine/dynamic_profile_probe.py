from __future__ import annotations

import hashlib
import importlib.resources
import json
import re
import subprocess
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from redsentinel.application.image_profile_contracts import (
    AnalysisError,
    AnalysisLimitation,
    AnalysisStageState,
    ImageAgentProfile,
    ProfileEdge,
    ProfileEvidence,
    ProfileNode,
)
from redsentinel.application.engine.image_profile_redaction import (
    redact_image_profile_text,
    sanitize_image_profile_log,
)
from redsentinel.runtime.engine.sandbox.docker.capture import (
    DEFAULT_MAX_OUTPUT_BYTES,
    BoundedCaptureResult,
    run_bounded_capture,
)


DynamicProbeEventType = Literal[
    "startup",
    "import_succeeded",
    "import_failed",
    "import_skipped",
    "invocation_started",
    "invocation_completed",
    "invocation_failed",
    "coverage_target",
    "agent_invoked",
    "tool_called",
    "guard_decision",
    "output_observed",
    "agent_registered",
    "tool_registered",
    "mcp_registered",
    "guard_registered",
    "route",
    "call_plan",
]
_REGISTRATION_TYPES = {
    "agent_invoked": "agent",
    "agent_registered": "agent",
    "tool_called": "tool",
    "tool_registered": "tool",
    "mcp_registered": "mcp",
    "guard_decision": "guard",
    "guard_registered": "guard",
}
_STRUCTURE_EVENT_TYPES = {*_REGISTRATION_TYPES, "route", "call_plan"}
_BEHAVIOR_EVENT_TYPES = {
    "agent_invoked",
    "tool_called",
    "guard_decision",
    "output_observed",
}
_DIRECT_EVIDENCE_METHODS = {"image_config", "package_metadata", "static", "framework"}
_SENSITIVE_KEY = re.compile(r"(?i)(api.?key|authorization|credential|password|secret|token)")
_SENSITIVE_VALUE = re.compile(r"(?i)\b(api.?key|authorization|credential|password|secret|token)\b\s*[:=]\s*[^\s,;]+")
_SAFE_ID = re.compile(r"[^A-Za-z0-9_.:-]+")
_EVENT_PREFIX = b"REDSENTINEL_DYNAMIC_EVENT:"


class DynamicProbeError(ValueError):
    """Raised when dynamic probe output is malformed or exceeds a safety limit."""


class DynamicProbeEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["dynamic-probe-event-v0.1"] = "dynamic-probe-event-v0.1"
    event_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    event_type: DynamicProbeEventType
    timestamp: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    node_type: str | None = Field(default=None, max_length=40)
    static_node_id: str | None = Field(
        default=None,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    source_node_id: str | None = Field(default=None, min_length=1, max_length=200)
    target_node_id: str | None = Field(default=None, min_length=1, max_length=200)
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    trust_level: Literal["attested", "observed"] = "attested"

    @field_validator("details")
    @classmethod
    def limit_details(
        cls, value: dict[str, str | int | float | bool | None]
    ) -> dict[str, str | int | float | bool | None]:
        if len(value) > 24:
            raise ValueError("dynamic probe event details exceed the field limit")
        if any(len(key) > 80 for key in value):
            raise ValueError("dynamic probe event detail key is too long")
        if any(isinstance(item, str) and len(item) > 500 for item in value.values()):
            raise ValueError("dynamic probe event detail value is too long")
        return value

    @model_validator(mode="after")
    def validate_shape(self) -> DynamicProbeEvent:
        expected_type = _REGISTRATION_TYPES.get(self.event_type)
        if expected_type is not None and self.node_type not in {None, expected_type}:
            raise ValueError(f"{self.event_type} requires node_type={expected_type}")
        if self.event_type in {"route", "call_plan"} and not (self.source_node_id and self.target_node_id):
            raise ValueError(f"{self.event_type} requires source_node_id and target_node_id")
        if self.event_type == "call_plan" and self.details.get("executed") is not False:
            raise ValueError("call_plan must explicitly state executed=false")
        if self.event_type == "tool_called":
            if not (self.source_node_id and self.target_node_id):
                raise ValueError("tool_called requires source_node_id and target_node_id")
            if self.details.get("executed") is not True:
                raise ValueError("tool_called must explicitly state executed=true")
        return self


@dataclass(frozen=True)
class DynamicProbeLimits:
    timeout_seconds: float = 30.0
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    max_event_file_bytes: int = 512 * 1024
    max_event_line_bytes: int = 16 * 1024
    max_events: int = 500
    memory_limit: str = "512m"
    cpus: str = "0.5"
    pids_limit: int = 128
    tmpfs_size: str = "64m"

    def __post_init__(self) -> None:
        numeric = {
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_event_file_bytes": self.max_event_file_bytes,
            "max_event_line_bytes": self.max_event_line_bytes,
            "max_events": self.max_events,
            "pids_limit": self.pids_limit,
        }
        if any(value <= 0 for value in numeric.values()):
            raise ValueError("dynamic probe limits must be positive")


@dataclass(frozen=True)
class DynamicProbeRisk:
    phase: str = "dynamic_verify"
    requires_privileged: bool = False
    required_host_mounts: tuple[str, ...] = ()


@dataclass(frozen=True)
class DynamicProbeGateIssue:
    code: str
    message: str
    retryable: bool = False


@dataclass(frozen=True)
class DynamicProbeResult:
    profile: ImageAgentProfile
    events: tuple[DynamicProbeEvent, ...] = ()
    command: tuple[str, ...] = ()
    gate_issues: tuple[DynamicProbeGateIssue, ...] = ()
    error: str | None = None
    timed_out: bool = False

    @property
    def succeeded(self) -> bool:
        return not self.gate_issues and self.error is None


CaptureRunner = Callable[..., BoundedCaptureResult]
CleanupRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass
class DynamicProfileProbe:
    artifact_root: Path
    docker_binary: str = "docker"
    limits: DynamicProbeLimits = field(default_factory=DynamicProbeLimits)
    supported_platforms: tuple[str, ...] = ("linux/amd64", "linux/arm64")
    capture_runner: CaptureRunner = run_bounded_capture
    cleanup_runner: CleanupRunner = subprocess.run

    def run(
        self,
        profile: ImageAgentProfile,
        *,
        image_ref: str,
        risk: DynamicProbeRisk | None = None,
        target_module: str | None = None,
    ) -> DynamicProbeResult:
        effective_risk = risk or DynamicProbeRisk()
        module = target_module or _entrypoint_module(profile)
        issues = self.assess(profile, image_ref=image_ref, risk=effective_risk, target_module=module)
        if issues:
            issue = issues[0]
            return DynamicProbeResult(
                profile=_partial_profile(profile, issue.code, issue.message, issue.retryable),
                gate_issues=tuple(issues),
                error=issue.message,
            )

        command: list[str] = []
        run_dir: Path | None = None
        try:
            run_dir = self._prepare_artifacts()
            events_path = run_dir / "events.jsonl"
            packaged_runtime = importlib.resources.files("redsentinel.profiling.image").joinpath("probe_runtime.py")
            runtime_source = Path(str(packaged_runtime)).resolve()
            if not runtime_source.is_file():
                runtime_source = run_dir / "probe_runtime.py"
                runtime_source.write_bytes(packaged_runtime.read_bytes())
            container_name = f"redsentinel-profile-probe-{uuid.uuid4().hex[:12]}"
            command = self.build_command(
                profile,
                image_ref=image_ref,
                run_dir=run_dir,
                runtime_source=runtime_source,
                container_name=container_name,
                target_module=module,
            )
            result = self.capture_runner(
                command,
                timeout=self.limits.timeout_seconds,
                max_output_bytes=self.limits.max_output_bytes,
                stdout_path=run_dir / "stdout.log",
                stderr_path=run_dir / "stderr.log",
            )
        except Exception as exc:
            if run_dir is not None:
                sanitize_image_profile_log(run_dir / "stdout.log")
                sanitize_image_profile_log(run_dir / "stderr.log")
            message = redact_image_profile_text(f"dynamic probe could not start: {type(exc).__name__}: {exc}")
            return DynamicProbeResult(
                profile=_partial_profile(profile, "dynamic_probe_start_failed", message, True),
                command=tuple(command),
                error=message,
            )
        if result.timed_out:
            self._cleanup(container_name)

        try:
            events = _read_dynamic_probe_stdout(
                result.stdout_path,
                max_bytes=self.limits.max_event_file_bytes,
                max_line_bytes=self.limits.max_event_line_bytes,
                max_events=self.limits.max_events,
            )
            _write_dynamic_probe_events(events_path, events)
        except DynamicProbeError as exc:
            events_path.unlink(missing_ok=True)
            sanitize_image_profile_log(result.stdout_path)
            sanitize_image_profile_log(result.stderr_path)
            return DynamicProbeResult(
                profile=_partial_profile(profile, "invalid_probe_output", str(exc), False),
                command=tuple(command),
                error=str(exc),
                timed_out=result.timed_out,
            )
        sanitize_image_profile_log(result.stdout_path)
        sanitize_image_profile_log(result.stderr_path)

        failure = _capture_failure(result)
        event_types = {event.event_type for event in events}
        required_events = {
            "startup",
            "import_succeeded",
            "coverage_target",
            "invocation_started",
            "agent_invoked",
            "output_observed",
            "invocation_completed",
        }
        if failure is None and not required_events.issubset(event_types):
            missing = ", ".join(sorted(required_events - event_types))
            failure = f"dynamic probe did not emit required behavioral events: {missing}"
        merged = align_dynamic_events(profile, events) if failure is None else None
        if failure is None and merged is not None and not _has_structural_observation(merged, events):
            failure = "dynamic probe did not emit an effective structural observation"
        if failure is None and not event_types.intersection(_BEHAVIOR_EVENT_TYPES):
            failure = "dynamic probe did not emit an effective behavioral observation"
        if failure is not None:
            code = (
                "dynamic_probe_timeout"
                if result.timed_out
                else "incomplete_probe_output"
                if result.returncode == 0
                else "dynamic_probe_failed"
            )
            return DynamicProbeResult(
                profile=_partial_profile(profile, code, failure, result.timed_out),
                events=tuple(events),
                command=tuple(command),
                error=failure,
                timed_out=result.timed_out,
            )

        assert merged is not None
        return DynamicProbeResult(profile=_completed_profile(merged), events=tuple(events), command=tuple(command))

    def assess(
        self,
        profile: ImageAgentProfile,
        *,
        image_ref: str,
        risk: DynamicProbeRisk,
        target_module: str | None,
    ) -> list[DynamicProbeGateIssue]:
        issues: list[DynamicProbeGateIssue] = []
        if risk.phase != "dynamic_verify":
            issues.append(DynamicProbeGateIssue("invalid_probe_phase", "probe may run only in dynamic_verify"))
        incomplete = [
            stage.stage for stage in profile.analysis.stages[:6] if stage.status not in {"completed", "skipped"}
        ]
        if incomplete:
            issues.append(
                DynamicProbeGateIssue(
                    "static_profile_incomplete",
                    f"static profile stages are incomplete: {', '.join(incomplete)}",
                    True,
                )
            )
        platform = _normalized_platform(profile.image.os, profile.image.architecture)
        if platform not in self.supported_platforms:
            issues.append(
                DynamicProbeGateIssue(
                    "unsupported_platform",
                    f"dynamic probe does not support platform {platform}",
                )
            )
        if risk.requires_privileged:
            issues.append(
                DynamicProbeGateIssue(
                    "privileged_runtime_required",
                    "image requires privileged execution; dynamic verification was refused",
                )
            )
        if risk.required_host_mounts:
            issues.append(
                DynamicProbeGateIssue(
                    "dangerous_mount_required",
                    "image requires host mounts outside the controlled probe artifact directory",
                )
            )
        if not image_ref.strip() or image_ref.startswith("-") or any(char.isspace() for char in image_ref):
            issues.append(DynamicProbeGateIssue("invalid_image_reference", "image reference is invalid"))
        if target_module is None or not _valid_module_name(target_module):
            issues.append(
                DynamicProbeGateIssue(
                    "unsupported_entrypoint",
                    "a safe import module could not be derived from the image entrypoint",
                )
            )
        return issues

    def build_command(
        self,
        profile: ImageAgentProfile,
        *,
        image_ref: str,
        run_dir: Path,
        runtime_source: Path | None = None,
        container_name: str,
        target_module: str,
    ) -> list[str]:
        platform = _normalized_platform(profile.image.os, profile.image.architecture)
        mount_source = str(run_dir.resolve())
        if "," in mount_source:
            raise DynamicProbeError("controlled artifact path cannot contain a comma")
        runtime_mount = str((runtime_source or run_dir / "probe_runtime.py").resolve())
        return [
            self.docker_binary,
            "run",
            "--rm",
            "--name",
            container_name,
            "--platform",
            platform,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(self.limits.pids_limit),
            "--memory",
            self.limits.memory_limit,
            "--cpus",
            self.limits.cpus,
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={self.limits.tmpfs_size}",
            "--mount",
            f"type=bind,src={runtime_mount},dst=/redsentinel-probe.py,readonly",
            "--env",
            "REDSENTINEL_DYNAMIC_PROBE=1",
            "--env",
            "HOME=/tmp",
            "--env",
            "XDG_CONFIG_HOME=/tmp/.config",
            "--env",
            "XDG_CACHE_HOME=/tmp/.cache",
            "--entrypoint",
            "python",
            image_ref,
            "/redsentinel-probe.py",
            "--module",
            target_module,
        ]

    def _prepare_artifacts(self) -> Path:
        root = self.artifact_root.expanduser()
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise DynamicProbeError("probe artifact root must be a real directory")
        run_dir = root.resolve() / f"dynamic-probe-{uuid.uuid4().hex}"
        run_dir.mkdir(mode=0o700)
        return run_dir

    def _cleanup(self, container_name: str) -> None:
        try:
            self.cleanup_runner(
                [self.docker_binary, "rm", "-f", container_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except Exception:
            pass


def read_dynamic_probe_events(
    path: str | Path,
    *,
    max_bytes: int = 512 * 1024,
    max_line_bytes: int = 16 * 1024,
    max_events: int = 500,
) -> list[DynamicProbeEvent]:
    event_path = Path(path)
    if not event_path.exists():
        return []
    if event_path.is_symlink() or not event_path.is_file():
        raise DynamicProbeError("dynamic probe event path must be a regular file")
    if event_path.stat().st_size > max_bytes:
        raise DynamicProbeError("dynamic probe event file exceeds the size limit")

    raw_lines = [raw_line for raw_line in event_path.read_bytes().splitlines() if raw_line.strip()]
    if any(len(raw_line) > max_line_bytes for raw_line in raw_lines):
        raise DynamicProbeError("dynamic probe event line exceeds the size limit")
    if len(raw_lines) > max_events:
        raise DynamicProbeError("dynamic probe event count exceeds the limit")
    return _parse_dynamic_probe_event_lines(raw_lines)


def _parse_dynamic_probe_event_lines(
    raw_lines: Iterable[bytes],
    *,
    allow_observed: bool = True,
) -> list[DynamicProbeEvent]:
    events: list[DynamicProbeEvent] = []
    event_ids: set[str] = set()
    for raw_line in raw_lines:
        try:
            payload = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DynamicProbeError("dynamic probe event is not valid UTF-8 JSON") from exc
        if not isinstance(payload, dict):
            raise DynamicProbeError("dynamic probe event must be a JSON object")
        sanitized = _redact_event_payload(payload)
        try:
            event = DynamicProbeEvent.model_validate(sanitized)
        except ValueError as exc:
            raise DynamicProbeError(f"dynamic probe event does not match the contract: {exc}") from exc
        if not allow_observed and event.trust_level == "observed":
            event = event.model_copy(update={"trust_level": "attested"})
        if event.event_id in event_ids:
            raise DynamicProbeError(f"duplicate dynamic probe event id: {event.event_id}")
        event_ids.add(event.event_id)
        events.append(event)
    return events


def _read_dynamic_probe_stdout(
    path: str | Path,
    *,
    max_bytes: int,
    max_line_bytes: int,
    max_events: int,
) -> list[DynamicProbeEvent]:
    stdout_path = Path(path)
    if stdout_path.is_symlink() or not stdout_path.is_file():
        raise DynamicProbeError("dynamic probe stdout path must be a regular file")

    event_lines: list[bytes] = []
    event_bytes = 0
    for raw_line in stdout_path.read_bytes().splitlines():
        if not raw_line.startswith(_EVENT_PREFIX):
            continue
        payload = raw_line[len(_EVENT_PREFIX) :]
        if len(payload) > max_line_bytes:
            raise DynamicProbeError("dynamic probe event line exceeds the size limit")
        event_bytes += len(payload) + 1
        if event_bytes > max_bytes:
            raise DynamicProbeError("dynamic probe events exceed the size limit")
        if len(event_lines) >= max_events:
            raise DynamicProbeError("dynamic probe event count exceeds the limit")
        event_lines.append(payload)

    return _parse_dynamic_probe_event_lines(event_lines, allow_observed=False)


def _write_dynamic_probe_events(path: Path, events: Iterable[DynamicProbeEvent]) -> None:
    path.unlink(missing_ok=True)
    path.write_text(
        "".join(
            json.dumps(event.model_dump(mode="json"), ensure_ascii=True, separators=(",", ":")) + "\n"
            for event in events
        ),
        encoding="utf-8",
    )


def align_dynamic_events(
    profile: ImageAgentProfile,
    events: Iterable[DynamicProbeEvent],
) -> ImageAgentProfile:
    payload = profile.model_dump(mode="json")
    evidence = list(payload["evidence"])
    nodes = list(payload["nodes"])
    edges = list(payload["edges"])
    controls = list(payload["controls"])
    limitations = list(payload["limitations"])
    evidence_methods = {item["evidence_id"]: item["method"] for item in evidence}
    evidence_trust = {item["evidence_id"]: item["trust_level"] for item in evidence}
    node_indexes = {item["node_id"]: index for index, item in enumerate(nodes)}

    for event in events:
        event_evidence = _event_evidence(profile, event)
        evidence_id = event_evidence["evidence_id"]
        if evidence_id in evidence_methods:
            limitations.append(
                _limitation(
                    "dynamic_event_collision",
                    f"dynamic event {event.event_id} collides with existing evidence",
                    [evidence_id],
                )
            )
            continue
        evidence.append(event_evidence)
        evidence_methods[evidence_id] = "dynamic"
        evidence_trust[evidence_id] = event_evidence["trust_level"]

        expected_type = _REGISTRATION_TYPES.get(event.event_type)
        if expected_type is not None:
            matched_id = _match_node(event, nodes, node_indexes)
            if matched_id is not None:
                index = node_indexes[matched_id]
                if nodes[index]["node_type"] != expected_type or nodes[index]["verification_status"] == "rejected":
                    limitations.append(
                        _limitation(
                            "dynamic_static_conflict",
                            (
                                f"dynamic event {event.event_id} conflicts with static claim "
                                f"{matched_id} ({nodes[index]['node_type']}, "
                                f"{nodes[index]['verification_status']})"
                            ),
                            [evidence_id, *nodes[index]["evidence_refs"]],
                        )
                    )
                    continue
                nodes[index] = _corroborate_claim(
                    nodes[index],
                    evidence_id,
                    evidence_methods,
                    evidence_trust,
                )
            else:
                node_id = _dynamic_node_id(expected_type, event.name, node_indexes)
                node = ProfileNode(
                    node_id=node_id,
                    node_type=expected_type,
                    name=event.name,
                    evidence_refs=[evidence_id],
                    confidence=0.75,
                    verification_status="supported",
                ).model_dump(mode="json")
                node_indexes[node_id] = len(nodes)
                nodes.append(node)
                limitations.append(
                    _limitation(
                        "dynamic_only_node",
                        f"node {node_id} was observed dynamically but has no static match",
                        [evidence_id],
                    )
                )
            if event.event_type in {"guard_registered", "guard_decision"}:
                control_matches = _corroborate_control(
                    controls,
                    event,
                    evidence_id,
                    evidence_methods,
                    evidence_trust,
                )
                if control_matches > 1:
                    limitations.append(
                        _limitation(
                            "dynamic_control_ambiguous",
                            (f"dynamic event {event.event_id} matches multiple static controls"),
                            [evidence_id],
                        )
                    )

        if event.event_type in {"route", "call_plan", "tool_called"}:
            source = _resolve_node_reference(event.source_node_id, nodes, node_indexes)
            target = _resolve_node_reference(
                event.target_node_id,
                nodes,
                node_indexes,
                edges=edges,
                connected_to=source,
            )
            if source is None or target is None:
                limitations.append(
                    _limitation(
                        "dynamic_edge_unresolved",
                        f"dynamic event {event.event_id} could not be aligned to both endpoint nodes",
                        [evidence_id],
                    )
                )
                continue
            edge_type = "routes_to" if event.event_type == "route" else "calls"
            edge_indexes = [
                index
                for index, edge in enumerate(edges)
                if edge["source_node_id"] == source
                and edge["target_node_id"] == target
                and edge["edge_type"] == edge_type
            ]
            if len(edge_indexes) == 1:
                edge_index = edge_indexes[0]
                edges[edge_index] = _corroborate_claim(
                    edges[edge_index],
                    evidence_id,
                    evidence_methods,
                    evidence_trust,
                )
            elif edge_indexes:
                limitations.append(
                    _limitation(
                        "dynamic_edge_ambiguous",
                        f"dynamic event {event.event_id} matches multiple static edges",
                        [evidence_id],
                    )
                )
            else:
                edge_id = _dynamic_edge_id(edge_type, source, target, {item["edge_id"] for item in edges})
                edges.append(
                    ProfileEdge(
                        edge_id=edge_id,
                        edge_type=edge_type,
                        source_node_id=source,
                        target_node_id=target,
                        evidence_refs=[evidence_id],
                        confidence=0.72,
                        verification_status="supported",
                    ).model_dump(mode="json")
                )
                limitations.append(
                    _limitation(
                        "dynamic_only_edge",
                        f"edge {edge_id} was observed dynamically but has no static match",
                        [evidence_id],
                    )
                )

    payload.update(
        {
            "evidence": evidence,
            "nodes": nodes,
            "edges": edges,
            "controls": controls,
            "limitations": _deduplicate_limitations(limitations),
        }
    )
    return synchronize_profile_derivations(ImageAgentProfile.model_validate(payload))


def synchronize_profile_derivations(profile: ImageAgentProfile) -> ImageAgentProfile:
    """Keep evidence-backed derived claims closed over the final graph."""
    payload = profile.model_dump(mode="json")
    node_ids = {item["node_id"] for item in payload["nodes"]}
    edge_index = {item["edge_id"]: item for item in payload["edges"]}

    capabilities = [item for item in payload["capabilities"] if item["node_ids"] and set(item["node_ids"]) <= node_ids]
    capability_ids = {item["capability_id"] for item in capabilities}
    permissions = [
        item
        for item in payload["permissions"]
        if item["node_ids"] and set(item["node_ids"]) <= node_ids and set(item["capability_ids"]) <= capability_ids
    ]
    permission_ids = {item["permission_id"] for item in permissions}
    controls = [item for item in payload["controls"] if item["node_ids"] and set(item["node_ids"]) <= node_ids]
    control_ids = {item["control_id"] for item in controls}

    for node in payload["nodes"]:
        node_id = node["node_id"]
        node["capability_ids"] = [item["capability_id"] for item in capabilities if node_id in item["node_ids"]]
        node["permission_ids"] = [item["permission_id"] for item in permissions if node_id in item["node_ids"]]
        node["control_ids"] = [item["control_id"] for item in controls if node_id in item["node_ids"]]

    risk_paths = [
        item
        for item in payload["risk_paths"]
        if _risk_path_matches_graph(item, node_ids, edge_index)
        and set(item["capability_ids"]) <= capability_ids
        and set(item["permission_ids"]) <= permission_ids
        and set(item["control_ids"]) <= control_ids
    ]
    payload.update(
        {
            "capabilities": capabilities,
            "permissions": permissions,
            "controls": controls,
            "risk_paths": risk_paths,
        }
    )
    return ImageAgentProfile.model_validate(payload)


def _risk_path_matches_graph(
    path: dict[str, Any],
    node_ids: set[str],
    edge_index: dict[str, dict[str, Any]],
) -> bool:
    path_nodes = path["node_ids"]
    path_edges = path["edge_ids"]
    if set(path_nodes) - node_ids or len(path_edges) != len(path_nodes) - 1:
        return False
    return all(
        edge_id in edge_index
        and edge_index[edge_id]["source_node_id"] == path_nodes[index]
        and edge_index[edge_id]["target_node_id"] == path_nodes[index + 1]
        for index, edge_id in enumerate(path_edges)
    )


def _has_structural_observation(
    profile: ImageAgentProfile,
    events: Iterable[DynamicProbeEvent],
) -> bool:
    structural_evidence = {
        f"dynamic:{event.event_id}" for event in events if event.event_type in _STRUCTURE_EVENT_TYPES
    }
    claims = [*profile.nodes, *profile.edges, *profile.controls]
    return any(structural_evidence.intersection(claim.evidence_refs) for claim in claims)


def _redact_event_payload(payload: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(payload)
    details = sanitized.get("details")
    if isinstance(details, dict):
        sanitized["details"] = {
            str(key)[:80]: (
                "[REDACTED]"
                if _SENSITIVE_KEY.search(str(key))
                else _redact_text(value)
                if isinstance(value, str)
                else value
            )
            for key, value in list(details.items())[:25]
        }
    for key in ("name", "source_node_id", "target_node_id"):
        if isinstance(sanitized.get(key), str):
            sanitized[key] = _redact_text(sanitized[key])
    return sanitized


def _redact_text(value: str) -> str:
    return redact_image_profile_text(value)


def _event_evidence(profile: ImageAgentProfile, event: DynamicProbeEvent) -> dict[str, Any]:
    content = json.dumps(event.model_dump(mode="json"), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return ProfileEvidence(
        evidence_id=f"dynamic:{event.event_id}",
        artifact_digest=profile.image.digest,
        locator={"event_id": event.event_id},
        extractor="offline_dynamic_profile_probe",
        method="dynamic",
        trust_level=event.trust_level,
        content_sha256=hashlib.sha256(content.encode()).hexdigest(),
        summary=f"{event.event_type}: {event.name}"[:500],
    ).model_dump(mode="json")


def _corroborate_claim(
    claim: dict[str, Any],
    evidence_id: str,
    evidence_methods: dict[str, str],
    evidence_trust: dict[str, str],
) -> dict[str, Any]:
    updated = dict(claim)
    refs = list(dict.fromkeys([*updated["evidence_refs"], evidence_id]))
    methods = {evidence_methods[ref] for ref in refs}
    has_static = bool(methods & _DIRECT_EVIDENCE_METHODS)
    updated["evidence_refs"] = refs
    has_observed_dynamic = any(
        evidence_methods[ref] == "dynamic" and evidence_trust.get(ref) == "observed" for ref in refs
    )
    if has_static and has_observed_dynamic:
        updated["verification_status"] = "verified"
        updated["confidence"] = max(float(updated["confidence"]), 0.95)
    return updated


def _corroborate_control(
    controls: list[dict[str, Any]],
    event: DynamicProbeEvent,
    evidence_id: str,
    evidence_methods: dict[str, str],
    evidence_trust: dict[str, str],
) -> int:
    event_name = _normalize_name(event.name)
    matches = [index for index, control in enumerate(controls) if _normalize_name(control["name"]) == event_name]
    if len(matches) == 1:
        index = matches[0]
        controls[index] = _corroborate_claim(
            controls[index],
            evidence_id,
            evidence_methods,
            evidence_trust,
        )
    return len(matches)


def _match_node(
    event: DynamicProbeEvent,
    nodes: list[dict[str, Any]],
    indexes: dict[str, int],
) -> str | None:
    if event.static_node_id in indexes:
        return event.static_node_id
    return _unique_node_name_match(event.name, nodes, node_type=_REGISTRATION_TYPES[event.event_type])


def _resolve_node_reference(
    value: str | None,
    nodes: list[dict[str, Any]],
    indexes: dict[str, int],
    *,
    edges: list[dict[str, Any]] | None = None,
    connected_to: str | None = None,
) -> str | None:
    if value in indexes:
        return value
    matched = _unique_node_name_match(value or "", nodes)
    if matched is not None or edges is None or connected_to is None:
        return matched
    normalized = _normalize_name(value or "")
    candidates = {node["node_id"] for node in nodes if _normalize_name(node["name"]) == normalized}
    connected = {
        edge["target_node_id"]
        for edge in edges
        if edge["source_node_id"] == connected_to and edge["target_node_id"] in candidates
    }
    return next(iter(connected)) if len(connected) == 1 else None


def _dynamic_node_id(node_type: str, name: str, indexes: dict[str, int]) -> str:
    base = _safe_identifier(f"node:dynamic:{node_type}:{name}")
    return _unique_id(base, indexes)


def _dynamic_edge_id(edge_type: str, source: str, target: str, existing: set[str]) -> str:
    base = _safe_identifier(f"edge:dynamic:{edge_type}:{source}:{target}")
    return _unique_id(base, existing)


def _safe_identifier(value: str) -> str:
    normalized = _SAFE_ID.sub("_", value).strip("_")
    if len(normalized) <= 140:
        return normalized
    digest = hashlib.sha256(normalized.encode()).hexdigest()[:12]
    return f"{normalized[:127]}:{digest}"


def _unique_id(base: str, existing: Iterable[str]) -> str:
    used = set(existing)
    if base not in used:
        return base
    index = 2
    while f"{base}:{index}" in used:
        index += 1
    return f"{base}:{index}"


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _unique_node_name_match(
    value: str,
    nodes: list[dict[str, Any]],
    *,
    node_type: str | None = None,
) -> str | None:
    normalized = _normalize_name(value)
    if not normalized:
        return None
    candidates = [node for node in nodes if (node_type is None or node["node_type"] == node_type)]
    exact = [node["node_id"] for node in candidates if _normalize_name(node["name"]) == normalized]
    if len(exact) == 1:
        return exact[0]
    if exact:
        return None

    aliased = [node["node_id"] for node in candidates if _node_name_alias(node["name"]) == normalized]
    return aliased[0] if len(aliased) == 1 else None


def _node_name_alias(value: str) -> str:
    lowered = value.casefold()
    for prefix in ("call ", "tool sink "):
        if lowered.startswith(prefix):
            lowered = lowered[len(prefix) :]
            break
    if "." in lowered:
        lowered = lowered.rsplit(".", 1)[-1]
    return _normalize_name(lowered)


def _limitation(code: str, message: str, refs: list[str] | None = None) -> dict[str, Any]:
    return AnalysisLimitation(
        code=code,
        message=message,
        evidence_refs=list(dict.fromkeys(refs or [])),
    ).model_dump(mode="json")


def _deduplicate_limitations(limitations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for limitation in limitations:
        key = (limitation["code"], limitation["message"])
        if key not in seen:
            seen.add(key)
            result.append(limitation)
    return result


def _entrypoint_module(profile: ImageAgentProfile) -> str | None:
    command = [*profile.image.entrypoint, *profile.image.command]
    for index, value in enumerate(command[:-1]):
        if value == "-m":
            return command[index + 1] if _valid_module_name(command[index + 1]) else None
    python_index = next(
        (index for index, value in enumerate(command) if Path(value).name.startswith("python")),
        None,
    )
    if python_index is None or python_index + 1 >= len(command):
        return None
    script = command[python_index + 1]
    if not script.endswith(".py") or script.startswith("-"):
        return None
    working_dir = profile.image.working_directory.rstrip("/") or "/"
    if script.startswith(f"{working_dir}/"):
        script = script[len(working_dir) + 1 :]
    else:
        script = Path(script).name
    module = script[:-3].replace("/", ".")
    return module if _valid_module_name(module) else None


def _valid_module_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", value))


def _normalized_platform(os_name: str, architecture: str) -> str:
    aliases = {"x86_64": "amd64", "aarch64": "arm64"}
    return f"{os_name.lower()}/{aliases.get(architecture.lower(), architecture.lower())}"


def _capture_failure(result: BoundedCaptureResult) -> str | None:
    if result.error:
        return redact_image_profile_text(result.error)
    if result.returncode != 0:
        return f"dynamic probe container exited with code {result.returncode}"
    return None


def _stage_payloads(
    profile: ImageAgentProfile,
    *,
    dynamic_status: Literal["completed", "failed"],
) -> list[AnalysisStageState]:
    now = datetime.now(timezone.utc).isoformat()
    result: list[AnalysisStageState] = []
    for state in profile.analysis.stages:
        if state.stage == "dynamic_verify":
            result.append(AnalysisStageState(stage=state.stage, status=dynamic_status, completed_at=now))
        elif state.stage == "finalize":
            result.append(AnalysisStageState(stage=state.stage, status="completed", completed_at=now))
        else:
            result.append(state)
    return result


def _completed_profile(profile: ImageAgentProfile) -> ImageAgentProfile:
    payload = profile.model_dump(mode="json")
    existing_errors = [error for error in profile.analysis.errors if error.stage != "dynamic_verify"]
    payload["analysis"] = {
        **profile.analysis.model_dump(mode="json"),
        "status": "completed",
        "stages": [item.model_dump(mode="json") for item in _stage_payloads(profile, dynamic_status="completed")],
        "errors": [item.model_dump(mode="json") for item in existing_errors],
    }
    return ImageAgentProfile.model_validate(payload)


def _partial_profile(
    profile: ImageAgentProfile,
    code: str,
    message: str,
    retryable: bool,
) -> ImageAgentProfile:
    message = redact_image_profile_text(message)
    payload = profile.model_dump(mode="json")
    existing_errors = [error for error in profile.analysis.errors if error.stage != "dynamic_verify"]
    error = AnalysisError(
        error_id=f"error:dynamic:{_safe_identifier(code)}",
        stage="dynamic_verify",
        code=code,
        message=message,
        retryable=retryable,
    )
    payload["analysis"] = {
        **profile.analysis.model_dump(mode="json"),
        "status": "partial",
        "stages": [item.model_dump(mode="json") for item in _stage_payloads(profile, dynamic_status="failed")],
        "errors": [
            *(item.model_dump(mode="json") for item in existing_errors),
            error.model_dump(mode="json"),
        ],
    }
    payload["limitations"] = _deduplicate_limitations(
        [
            *payload["limitations"],
            _limitation(code, message),
        ]
    )
    return ImageAgentProfile.model_validate(payload)


__all__ = [
    "DynamicProbeError",
    "DynamicProbeEvent",
    "DynamicProbeGateIssue",
    "DynamicProbeLimits",
    "DynamicProbeResult",
    "DynamicProbeRisk",
    "DynamicProfileProbe",
    "align_dynamic_events",
    "read_dynamic_probe_events",
]
