"""Unified allow/deny/ask monitor for Agent execution boundaries."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, cast
from uuid import uuid4

from redsentinel.defenses.guards import check_malicious_input, check_output_compliance
from redsentinel.defenses.engine.security.exec_guard import (
    CodeExecutionRequest,
    evaluate_code_execution,
)
from redsentinel.defenses.policy.engine import check_policy

# Trajectory anomaly scoring remains optional during the defense migration. It
# is imported from the established implementation to preserve score semantics.
from redsentinel.defenses.engine.security.trajectory_anomaly import score_payload_trajectory

DecisionValue = Literal["allow", "deny", "ask"]
CallType = Literal[
    "llm_input",
    "llm_output",
    "tool_call",
    "tool_result",
    "code_execution",
    "file_access",
]

SUPPORTED_CALL_TYPES = {
    "llm_input",
    "llm_output",
    "tool_call",
    "tool_result",
    "code_execution",
    "file_access",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Decision:
    decision: DecisionValue
    reason: str
    risk_score: float
    confidence: float
    rules: list[str] = field(default_factory=list)
    event_id: str = field(default_factory=lambda: f"evt_{uuid4().hex[:12]}")
    timestamp: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def intercept(call_type: CallType | str, payload: dict[str, Any] | str | None = None) -> Decision:
    """Evaluate one monitored boundary and preserve the three-state decision."""
    normalized_call_type = str(call_type)
    normalized_payload = _normalize_payload(payload)

    if normalized_call_type not in SUPPORTED_CALL_TYPES:
        return _decision(
            "deny",
            f"Unsupported monitor call_type: {normalized_call_type}",
            80.0,
            0.95,
            ["monitor_plugin.unsupported_call_type"],
        )

    if normalized_call_type == "llm_input":
        return _intercept_llm_input(normalized_payload)
    if normalized_call_type == "code_execution":
        return _intercept_code_execution(normalized_payload)
    if normalized_call_type in {"llm_output", "tool_result"}:
        decision = _intercept_text_boundary(normalized_call_type, normalized_payload)
        return _apply_trajectory_anomaly(normalized_call_type, normalized_payload, decision)
    if normalized_call_type == "tool_call":
        decision = _intercept_tool_call(normalized_payload)
        return _apply_trajectory_anomaly(normalized_call_type, normalized_payload, decision)
    if normalized_call_type == "file_access":
        decision = _intercept_file_access(normalized_payload)
        return _apply_trajectory_anomaly(normalized_call_type, normalized_payload, decision)

    return _decision("allow", "Monitor call allowed.", 0.0, 0.9, [f"{normalized_call_type}.allowed"])


def safe_refusal(decision: Decision) -> dict[str, Any]:
    """Build a runtime-neutral response for a deny or human-approval pause."""
    blocked = decision.decision == "deny"
    pending = decision.decision == "ask"
    if blocked:
        message = "安全策略已拒绝本次调用。"
    elif pending:
        message = "安全策略要求人工确认后才能继续。"
    else:
        message = "安全策略允许本次调用。"

    return {
        "blocked": blocked,
        "pending": pending,
        "decision": decision.decision,
        "message": message,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "event_id": decision.event_id,
    }


def _intercept_llm_input(payload: dict[str, Any]) -> Decision:
    blocked, reason = check_malicious_input(_payload_text(payload))
    if blocked:
        return _decision("deny", reason, 80.0, 0.9, ["input_guard.malicious_input"])
    return _decision("allow", "LLM input allowed.", 0.0, 0.9, ["llm_input.allowed"])


def _intercept_text_boundary(call_type: str, payload: dict[str, Any]) -> Decision:
    compliant, reason = check_output_compliance(_payload_text(payload))
    if not compliant:
        return _decision("deny", reason, 80.0, 0.85, [f"{call_type}.output_compliance"])
    return _decision("allow", f"{call_type} allowed.", 0.0, 0.9, [f"{call_type}.allowed"])


def _intercept_code_execution(payload: dict[str, Any]) -> Decision:
    code = _payload_text(payload).strip()
    if not code:
        return _decision(
            "deny",
            "Code execution payload is missing code.",
            80.0,
            0.95,
            ["exec_guard.missing_code"],
        )
    guard = evaluate_code_execution(
        CodeExecutionRequest(
            code=code,
            language=str(payload.get("language") or "python"),
            entrypoint=_first_str(payload, "entrypoint") or None,
            working_dir=_first_str(payload, "working_dir") or None,
        )
    )
    decision = _decision(
        guard.decision,
        guard.reason,
        _risk_score_from_level(guard.risk_level),
        0.95,
        ["exec_guard.code_execution"],
    )
    return _apply_trajectory_anomaly("code_execution", payload, decision)


def _intercept_tool_call(payload: dict[str, Any]) -> Decision:
    tool_name = _first_str(payload, "tool_name", "name", "tool")
    if not tool_name:
        return _decision(
            "deny",
            "Tool call payload is missing tool_name.",
            80.0,
            0.95,
            ["monitor_plugin.tool_call.missing_tool_name"],
        )
    arguments = _payload_arguments(payload)
    state = payload.get("state") if isinstance(payload.get("state"), dict) else None
    allowed, reason, detail = check_policy(tool_name, arguments, state)
    return _policy_decision(allowed, reason, detail, allowed_reason="Policy allowed tool call.")


def _intercept_file_access(payload: dict[str, Any]) -> Decision:
    arguments = _payload_arguments(payload)
    if not arguments:
        arguments = {"path": payload.get("path", ""), "action": payload.get("action", "read")}
    state = payload.get("state") if isinstance(payload.get("state"), dict) else None
    allowed, reason, detail = check_policy("file_operation", arguments, state)
    return _policy_decision(allowed, reason, detail, allowed_reason="Policy allowed file access.")


def _policy_decision(allowed: bool, reason: str, detail: dict[str, Any] | None, *, allowed_reason: str) -> Decision:
    detail = dict(detail or {})
    decision = detail.get("decision")
    if decision not in {"allow", "deny", "ask"}:
        decision = "allow" if allowed else "deny"
    return _decision(
        decision,
        reason or allowed_reason,
        _risk_score_from_level(str(detail.get("risk_level", "low"))),
        0.7 if decision == "ask" else 0.95,
        [rule for rule in [detail.get("rule_name")] if rule],
    )


def _apply_trajectory_anomaly(call_type: str, payload: dict[str, Any], current: Decision) -> Decision:
    if current.decision == "deny":
        return current
    anomaly = score_payload_trajectory(call_type, payload)
    if anomaly is None:
        return current
    if current.decision == "ask" and anomaly.decision != "deny":
        return current
    return _decision(
        anomaly.decision,
        anomaly.reason,
        anomaly.risk_score,
        0.75,
        [*current.rules, *[rule for rule in anomaly.rules if rule not in current.rules]],
    )


def _decision(
    decision: DecisionValue | str,
    reason: str,
    risk_score: float,
    confidence: float,
    rules: list[str],
) -> Decision:
    normalized = cast(DecisionValue, decision) if decision in {"allow", "deny", "ask"} else "deny"
    return Decision(
        decision=normalized,
        reason=reason,
        risk_score=float(risk_score),
        confidence=float(confidence),
        rules=list(rules),
    )


def _normalize_payload(payload: dict[str, Any] | str | None) -> dict[str, Any]:
    if isinstance(payload, dict):
        return dict(payload)
    if payload is None:
        return {}
    return {"content": str(payload)}


def _payload_text(payload: dict[str, Any]) -> str:
    for key in ("content", "text", "input", "output", "result", "response", "prompt", "code", "command"):
        value = payload.get(key)
        if value is not None:
            return str(value)
    return str(payload) if payload else ""


def _payload_arguments(payload: dict[str, Any]) -> dict[str, Any]:
    for key in ("arguments", "args", "tool_args"):
        value = payload.get(key)
        if isinstance(value, dict):
            return dict(value)
    return {}


def _first_str(payload: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if value:
            return str(value)
    return ""


def _risk_score_from_level(risk_level: str) -> float:
    return {
        "normal": 0.0,
        "low": 25.0,
        "medium": 50.0,
        "high": 80.0,
        "critical": 100.0,
    }.get(risk_level, 0.0)


__all__ = [
    "CallType",
    "Decision",
    "DecisionValue",
    "SUPPORTED_CALL_TYPES",
    "intercept",
    "safe_refusal",
]
