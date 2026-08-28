from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from redsentinel.adapters.engine.adapter import AgentAdapter
from redsentinel.adapters.engine.models import AgentTurnResult, ToolSpec
from redsentinel.adapters.engine.telemetry import TraceRecorder


DEFAULT_OPENMANUS_IMAGE = "redsentinel/openmanus-real:local"
DEFAULT_OUTPUT_ROOT = "runs/openmanus-real"


@dataclass(frozen=True)
class OpenManusDockerRunnerConfig:
    image: str = DEFAULT_OPENMANUS_IMAGE
    docker_binary: str = "docker"
    output_root: str | Path = DEFAULT_OUTPUT_ROOT
    timeout_seconds: int = 300
    memory_limit: str = "1g"
    cpus: str = "2"
    max_steps: int = 6


class OpenManusDockerRunner:
    """Run real vendored OpenManus inside Docker and return normalized turn payloads."""

    def __init__(self, config: OpenManusDockerRunnerConfig | None = None) -> None:
        self.config = config or OpenManusDockerRunnerConfig()
        self.output_root = Path(self.config.output_root).resolve()
        self.output_root.mkdir(parents=True, exist_ok=True)

    def __call__(self, user_id: str, message: str, context: dict[str, Any]) -> dict[str, Any]:
        started = time.time()
        session_id = str(context.get("session_id") or "openmanus-real")
        turn_index = int(context.get("turn_index") or 0)
        scenario_id = str(context.get("scenario_id") or "manual")
        case_type = str(context.get("case_type") or "manual")
        defense_mode = str(context.get("defense_mode") or "guarded")
        active_guards = sorted(
            {str(item) for item in context.get("active_guards") or []}
        )
        remediation_bundle_id = str(
            context.get("remediation_bundle_id") or ""
        )
        agent_id = str(context.get("agent_id") or "openmanus_official")
        turn_dir = self.output_root / _safe_path(session_id) / f"{turn_index:03d}-{_safe_path(scenario_id)}-{case_type}"
        turn_dir.mkdir(parents=True, exist_ok=True)
        container_name = _docker_container_name(session_id, turn_index, scenario_id, case_type)

        command = self._docker_command(
            output_dir=turn_dir,
            container_name=container_name,
            user_id=user_id,
            agent_id=agent_id,
            message=message,
            scenario_id=scenario_id,
            case_type=case_type,
            defense_mode=defense_mode,
            active_guards=active_guards if remediation_bundle_id else None,
        )
        stdout_path = turn_dir / "stdout.log"
        stderr_path = turn_dir / "stderr.log"
        error: str | None = None
        cleanup_error: str | None = None
        returncode = -1
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                env=self._host_env(),
            )
            returncode = completed.returncode
            stdout_path.write_text(completed.stdout or "", encoding="utf-8")
            stderr_path.write_text(completed.stderr or "", encoding="utf-8")
            if completed.returncode != 0:
                error = f"docker exited with code {completed.returncode}"
        except subprocess.TimeoutExpired as exc:
            stdout_path.write_text(_process_output_text(exc.stdout), encoding="utf-8")
            stderr_path.write_text(_process_output_text(exc.stderr), encoding="utf-8")
            error = f"docker timed out after {self.config.timeout_seconds}s"
            cleanup_error = self._cleanup_container(container_name)

        _redact_runtime_artifacts(turn_dir, [os.environ.get("OPENAI_API_KEY", "")])
        events = _read_events(turn_dir / "events.jsonl")
        duration_ms = round((time.time() - started) * 1000, 3)
        llm_metrics = _llm_metrics(events)
        runtime_meta = {
            "schema_version": "openmanus-real-runtime-meta-v0.1",
            "image": self.config.image,
            "returncode": returncode,
            "duration_ms": duration_ms,
            "error": error,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "events_path": str(turn_dir / "events.jsonl"),
            "memory_path": str(turn_dir / "memory.json"),
            "defense_mode": defense_mode,
            "active_guards": active_guards,
            "remediation_bundle_id": remediation_bundle_id,
            "remediation_policy_sha256": str(
                context.get("remediation_policy_sha256") or ""
            ),
            "scenario_id": scenario_id,
            "case_type": case_type,
            "container_name": container_name,
            "real_runtime": True,
            "simulated": False,
            **llm_metrics,
        }
        if cleanup_error is not None:
            runtime_meta["cleanup_error"] = cleanup_error
        (turn_dir / "runtime_meta.json").write_text(
            json.dumps(runtime_meta, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return _payload_from_events(
            user_id=user_id,
            message=message,
            events=events,
            runtime_meta=runtime_meta,
            error=error,
        )

    def list_tools(self) -> list[ToolSpec]:
        return [
            ToolSpec(name="python_execute", risk_level="high", description="Run Python code in real OpenManus."),
            ToolSpec(name="str_replace_editor", risk_level="high", description="Read or edit files in the sandbox."),
            ToolSpec(name="browser_use", risk_level="high", description="Operate a browser from OpenManus."),
            ToolSpec(name="ask_human", risk_level="low", description="Ask the operator for input."),
            ToolSpec(name="terminate", risk_level="low", description="Finish the OpenManus task."),
        ]

    def _docker_command(
        self,
        *,
        output_dir: Path,
        container_name: str,
        user_id: str,
        agent_id: str,
        message: str,
        scenario_id: str,
        case_type: str,
        defense_mode: str,
        active_guards: list[str] | None,
    ) -> list[str]:
        return [
            self.config.docker_binary,
            "run",
            "--rm",
            "--name",
            container_name,
            "--memory",
            self.config.memory_limit,
            "--cpus",
            self.config.cpus,
            "-e",
            "NO_PROXY=169.254.169.254,127.0.0.1,localhost",
            "-e",
            "OPENAI_API_KEY",
            "-e",
            "OPENAI_BASE_URL",
            "-e",
            "OPENAI_MODEL",
            "-e",
            "OPENAI_API_TYPE",
            "-e",
            "OPENAI_MAX_TOKENS",
            "-e",
            "OPENAI_VISION_MODEL",
            "-v",
            f"{output_dir}:/tmp/redsentinel-artifacts",
            self.config.image,
            "--prompt",
            message,
            "--output-dir",
            "/tmp/redsentinel-artifacts",
            "--scenario-id",
            scenario_id,
            "--case-type",
            case_type,
            "--defense-mode",
            defense_mode,
            "--active-guards",
            ",".join(active_guards) if active_guards is not None else "*",
            "--user-id",
            user_id,
            "--agent-id",
            agent_id,
            "--max-steps",
            str(self.config.max_steps),
        ]

    def _cleanup_container(self, container_name: str) -> str | None:
        try:
            completed = subprocess.run(
                [self.config.docker_binary, "rm", "-f", container_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except Exception as exc:  # pragma: no cover - defensive host cleanup path
            return f"docker cleanup failed: {type(exc).__name__}: {exc}"
        if completed.returncode == 0:
            return None
        detail = (completed.stderr or completed.stdout or "").strip()
        if "No such container" in detail:
            return None
        return f"docker rm -f exited with code {completed.returncode}: {_summary(detail, limit=300)}"

    def _host_env(self) -> dict[str, str]:
        env = os.environ.copy()
        missing = [name for name in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL") if not env.get(name)]
        if missing:
            raise RuntimeError(f"Missing required OpenManus real runtime environment: {', '.join(missing)}")
        return env


class OpenManusRealAdapter(AgentAdapter):
    def __init__(
        self,
        session_id: str = "openmanus-real",
        *,
        runner: OpenManusDockerRunner | None = None,
    ) -> None:
        self.recorder = TraceRecorder(session_id=session_id)
        self._runner = runner or OpenManusDockerRunner()
        self._turn_index = 0

    def send_message(self, user_id: str, message: str, context: dict[str, Any]) -> AgentTurnResult:
        context = dict(context)
        context.setdefault("session_id", self.recorder.session_id)
        context.setdefault("turn_index", self._turn_index)
        payload = self._runner(user_id, message, context)
        self._turn_index += 1
        result = AgentTurnResult(
            user_id=user_id,
            message=message,
            answer=str(payload.get("answer") or ""),
            blocked=bool(payload.get("blocked")),
            risk_level=str(payload.get("risk_level") or "low"),
            tool_calls=list(payload.get("tool_calls") or []),
            business_events=list(payload.get("business_events") or []),
            audit_events=list(payload.get("audit_events") or []),
        )
        self.recorder.record_turn(result)
        return result

    def list_tools(self) -> list[ToolSpec]:
        return self._runner.list_tools()

    def export_trajectory(self) -> dict[str, Any]:
        trajectory = self.recorder.export()
        trajectory["agent_framework"] = "OpenManus"
        trajectory["runtime_mode"] = "openmanus_real"
        trajectory["real_runtime"] = True
        trajectory["simulated"] = False
        trajectory["tool_calls"] = [call for turn in trajectory["turns"] for call in turn.get("tool_calls", [])]
        trajectory["audit_events"] = [event for turn in trajectory["turns"] for event in turn.get("audit_events", [])]
        return trajectory

    def reset_session(self, session_id: str) -> None:
        self.recorder.reset(session_id)
        self._turn_index = 0


def _payload_from_events(
    *,
    user_id: str,
    message: str,
    events: list[dict[str, Any]],
    runtime_meta: dict[str, Any],
    error: str | None,
) -> dict[str, Any]:
    policy_blocked = any(
        event.get("type") == "tool_call_blocked"
        or (event.get("type") == "monitor_decision" and event.get("decision") in {"deny", "ask"})
        for event in events
    )
    executed = [event for event in events if event.get("type") == "tool_call_executed"]
    planned = [event for event in events if event.get("type") == "tool_call_planned"]
    finish = next((event for event in reversed(events) if event.get("type") == "agent_finish"), None)
    answer = str((finish or {}).get("answer") or error or "OpenManus real run completed.")
    audit_events = [
        _audit_event_from_runtime(event, runtime_meta)
        for event in events
        if event.get("type")
        in {
            "monitor_decision",
            "model_refusal",
            "llm_call_completed",
            "llm_call_failed",
            "agent_termination",
        }
    ]
    if error:
        audit_events.append(
            {
                "event_type": "runtime_error",
                "call_type": "runtime",
                "tool_name": "openmanus_runtime",
                "decision": "error",
                "risk_score": 100.0,
                "reason": error,
                "rules": ["openmanus_real.runtime_error"],
                "source": "openmanus_real_runner",
                "runtime_meta": runtime_meta,
            }
        )
    tool_calls = [_tool_call_from_event(event, executed=event in executed) for event in [*planned, *executed]]
    return {
        "user_id": user_id,
        "message": message,
        "answer": answer,
        "blocked": False if error else policy_blocked,
        "risk_level": "high" if policy_blocked or error else "low",
        "tool_calls": tool_calls,
        "business_events": [],
        "audit_events": audit_events,
        "runtime_meta": runtime_meta,
        "events": events,
    }


def _redact_runtime_artifacts(root: Path, secrets: list[str]) -> None:
    active_secrets = [secret for secret in secrets if secret]
    if not active_secrets:
        return
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".json", ".jsonl", ".log", ".txt"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        redacted = content
        for secret in active_secrets:
            redacted = redacted.replace(secret, "[REDACTED_OPENAI_API_KEY]")
        if redacted != content:
            path.write_text(redacted, encoding="utf-8")


def _audit_event_from_runtime(event: dict[str, Any], runtime_meta: dict[str, Any]) -> dict[str, Any]:
    if event.get("type") == "model_refusal":
        return {
            "event_type": "model_refusal",
            "call_type": "model",
            "tool_name": "",
            "decision": "refuse",
            "risk_score": 0.0,
            "reason": event.get("reason") or "Model refusal.",
            "rules": ["model.refusal"],
            "source": "openmanus_real_runner",
            "scenario_id": event.get("scenario_id"),
            "case_type": event.get("case_type"),
            "defense_mode": event.get("defense_mode"),
            "runtime_meta": runtime_meta,
        }
    if event.get("type") in {"llm_call_completed", "llm_call_failed"}:
        failed = event.get("type") == "llm_call_failed"
        return {
            "event_type": event.get("type"),
            "call_type": "model",
            "tool_name": "",
            "decision": "error" if failed else "complete",
            "risk_score": 0.0,
            "reason": event.get("error") or "",
            "rules": ["model.call_failed" if failed else "model.call_completed"],
            "source": "openmanus_real_runner",
            "scenario_id": event.get("scenario_id"),
            "case_type": event.get("case_type"),
            "defense_mode": event.get("defense_mode"),
            "call_index": event.get("call_index"),
            "latency_ms": event.get("latency_ms"),
            "input_tokens": event.get("input_tokens"),
            "output_tokens": event.get("output_tokens"),
            "runtime_meta": runtime_meta,
        }
    if event.get("type") == "agent_termination":
        return {
            "event_type": "agent_termination",
            "call_type": "agent",
            "tool_name": "",
            "decision": "finish",
            "risk_score": 0.0,
            "reason": event.get("reason") or "",
            "rules": ["agent.termination"],
            "source": "openmanus_real_runner",
            "scenario_id": event.get("scenario_id"),
            "case_type": event.get("case_type"),
            "defense_mode": event.get("defense_mode"),
            "runtime_meta": runtime_meta,
        }
    return {
        "event_type": "monitor_decision",
        "call_type": event.get("monitor_call_type") or "tool_call",
        "tool_name": event.get("tool_name") or "",
        "decision": event.get("decision") or "allow",
        "risk_score": float(event.get("risk_score") or 0.0),
        "reason": event.get("reason") or "",
        "rules": list(event.get("rules") or []),
        "source": "openmanus_real_runner",
        "scenario_id": event.get("scenario_id"),
        "case_type": event.get("case_type"),
        "defense_mode": event.get("defense_mode"),
        "runtime_meta": runtime_meta,
    }


def _tool_call_from_event(event: dict[str, Any], *, executed: bool) -> dict[str, Any]:
    return {
        "tool_call_id": event.get("tool_call_id") or "",
        "name": event.get("tool_name") or "",
        "args_summary": _summary(event.get("arguments") or {}),
        "result_summary": _summary(event.get("result_summary") or event.get("observation") or ""),
        "executed": executed,
        "timestamp": event.get("timestamp"),
    }


def _read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            events.append(payload)
    return events


def _llm_metrics(events: list[dict[str, Any]]) -> dict[str, Any]:
    started = [event for event in events if event.get("type") == "llm_call_started"]
    completed = [event for event in events if event.get("type") == "llm_call_completed"]
    failed = [event for event in events if event.get("type") == "llm_call_failed"]
    finished_indexes = {
        event.get("call_index")
        for event in [*completed, *failed]
        if event.get("call_index") is not None
    }
    inflight = [
        event
        for event in started
        if event.get("call_index") is not None and event.get("call_index") not in finished_indexes
    ]
    latencies = [
        float(event.get("latency_ms"))
        for event in [*completed, *failed]
        if event.get("latency_ms") is not None
    ]
    return {
        "llm_call_started_count": len(started),
        "llm_call_completed_count": len(completed),
        "llm_call_failed_count": len(failed),
        "llm_call_inflight_count": len(inflight),
        "llm_latency_ms": latencies,
        "llm_latency_total_ms": round(sum(latencies), 3),
        "llm_latency_max_ms": round(max(latencies), 3) if latencies else None,
        "llm_input_tokens": sum(int(event.get("input_tokens") or 0) for event in completed),
        "llm_output_tokens": sum(int(event.get("output_tokens") or 0) for event in completed),
    }


def _safe_path(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in value)[:120]


def _docker_container_name(session_id: str, turn_index: int, scenario_id: str, case_type: str) -> str:
    raw = f"redsentinel-{session_id}-{turn_index:03d}-{scenario_id}-{case_type}"
    safe = "".join(char.lower() if char.isalnum() else "-" for char in raw)
    safe = "-".join(part for part in safe.split("-") if part)
    return safe[:120] or "redsentinel-openmanus"


def _process_output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _summary(value: Any, *, limit: int = 500) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return text if len(text) <= limit else text[: limit - 3] + "..."


__all__ = [
    "OpenManusDockerRunner",
    "OpenManusDockerRunnerConfig",
    "OpenManusRealAdapter",
]
