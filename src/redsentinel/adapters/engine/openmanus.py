from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redsentinel.adapters.engine.adapter import AgentAdapter
from redsentinel.adapters.engine.models import AgentTurnResult, ToolSpec
from redsentinel.adapters.engine.telemetry import TraceRecorder


OpenManusRunner = Callable[[str, str, dict[str, Any]], dict[str, Any]]
MonitorIntercept = Callable[[str, dict[str, Any]], Any]


@dataclass(frozen=True)
class InferredToolCall:
    call_type: str
    tool_name: str
    arguments: dict[str, Any]
    payload: dict[str, Any]


class OpenManusAdapter(AgentAdapter):
    def __init__(
        self,
        session_id: str = "openmanus-offline",
        *,
        runner: OpenManusRunner | None = None,
        monitor_intercept: MonitorIntercept | None = None,
        fixture_path: str | Path | None = None,
    ) -> None:
        self.recorder = TraceRecorder(session_id=session_id)
        self._runner = runner
        self._monitor_intercept = monitor_intercept
        self._fixture = _load_fixture(fixture_path)

    def send_message(self, user_id: str, message: str, context: dict[str, Any]) -> AgentTurnResult:
        inferred = _infer_tool_call(message)
        decision = _decision_to_dict(
            self._intercept(inferred.call_type, inferred.payload, context)
        )
        blocked = decision["decision"] in {"deny", "ask"}
        payload = {} if blocked else self._run(user_id, message, context)
        redacted_message = _redact(message)
        answer = _answer_for_decision(payload, inferred, decision, redacted_message)
        tool_calls = [] if blocked else [_simulated_tool_call(inferred, decision)]
        audit_events = [_audit_event(inferred, decision, user_id=user_id, session_id=self.recorder.session_id)]
        audit_events.extend(_normalise_audit_event(item) for item in payload.get("audit_events") or [])
        result = AgentTurnResult(
            user_id=user_id,
            message=redacted_message,
            answer=answer,
            blocked=blocked,
            risk_level=_risk_level_from_score(decision["risk_score"]),
            tool_calls=tool_calls,
            business_events=[] if blocked else list(payload.get("business_events") or []),
            audit_events=audit_events,
        )
        self.recorder.record_turn(result)
        return result

    def list_tools(self) -> list[ToolSpec]:
        source = getattr(self._runner, "list_tools", None)
        tools = source() if callable(source) else self._fixture.get("tools", [])
        return [_normalise_tool_spec(item) for item in tools]

    def export_trajectory(self) -> dict[str, Any]:
        trajectory = self.recorder.export()
        turns = trajectory["turns"]
        trajectory["agent_framework"] = "OpenManus"
        trajectory["tool_calls"] = [call for turn in turns for call in turn.get("tool_calls", [])]
        trajectory["audit_events"] = [event for turn in turns for event in turn.get("audit_events", [])]
        return trajectory

    def reset_session(self, session_id: str) -> None:
        self.recorder.reset(session_id)

    def _run(self, user_id: str, message: str, context: dict[str, Any]) -> dict[str, Any]:
        if self._runner is None:
            return {}
        payload = self._runner(user_id, message, context)
        if not isinstance(payload, dict):
            raise TypeError("OpenManus runner must return a dict payload.")
        return payload

    def _intercept(
        self,
        call_type: str,
        payload: dict[str, Any],
        context: dict[str, Any],
    ) -> Any:
        if context.get("defense_mode") == "baseline":
            return _allow_without_guard(call_type)
        if context.get("remediation_bundle_id"):
            active_guards = {
                str(item) for item in context.get("active_guards") or []
            }
            if not active_guards.intersection(_guards_for_call_type(call_type)):
                return _allow_without_guard(call_type)
        intercept = self._monitor_intercept or _default_monitor_intercept()
        return intercept(call_type, payload)


def _guards_for_call_type(call_type: str) -> set[str]:
    return {
        "llm_input": {"input_firewall", "goal_guard", "monitor_policy"},
        "code_execution": {"tool_policy", "file_policy", "network_policy", "monitor_policy"},
        "file_access": {"file_policy", "tool_policy", "monitor_policy"},
        "tool_call": {
            "tool_policy",
            "network_policy",
            "permission_guard",
            "monitor_policy",
        },
        "llm_output": {"output_filter", "monitor_policy"},
    }.get(call_type, {"monitor_policy"})


def _allow_without_guard(call_type: str) -> dict[str, Any]:
    return {
        "decision": "allow",
        "reason": "remediation_guard_not_installed",
        "risk_score": 0.0,
        "confidence": 1.0,
        "rules": ["remediation.guard_not_installed"],
        "call_type": call_type,
    }


def _default_monitor_intercept() -> MonitorIntercept:
    from redsentinel.defenses.engine.monitor_plugin import intercept

    return intercept


def _load_fixture(fixture_path: str | Path | None) -> dict[str, Any]:
    path = Path(fixture_path) if fixture_path is not None else _default_fixture_path()
    return json.loads(path.read_text(encoding="utf-8"))


def _default_fixture_path() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "third_party" / "OpenManus" / "fixtures" / "offline_turn.json"
        if candidate.exists():
            return candidate
    raise FileNotFoundError("OpenManus offline fixture not found.")


def _normalise_tool_spec(item: Any) -> ToolSpec:
    if isinstance(item, ToolSpec):
        return item
    if hasattr(item, "to_dict"):
        item = item.to_dict()
    if not isinstance(item, dict):
        raise TypeError("OpenManus tool spec must be a dict or ToolSpec.")
    return ToolSpec(
        name=str(item.get("name") or "openmanus_tool"),
        risk_level=str(item.get("risk_level") or "medium"),
        description=str(item.get("description") or "OpenManus tool."),
    )


def _infer_tool_call(message: str) -> InferredToolCall:
    text = str(message or "").strip()
    lower = text.lower()

    if _looks_like_python_execution(lower):
        code = _extract_python_code(text)
        return _tool_call(
            call_type="code_execution",
            tool_name="python_execute",
            arguments={"code": code},
            extra_payload={"code": code},
        )

    if _looks_like_email(text, lower):
        recipient = _first_match(text, _EMAIL_RE) or "external@example.com"
        return _tool_call(
            call_type="tool_call",
            tool_name="send_email",
            arguments={
                "to": recipient,
                "subject": _extract_subject(text),
                "body": text,
            },
        )

    if _looks_like_sql(lower):
        sql = _extract_sql(text)
        return _tool_call(
            call_type="tool_call",
            tool_name="db_query",
            arguments={"sql": sql},
        )

    if _looks_like_api_call(text, lower):
        url = _first_url(text) or _extract_after_marker(text, ("api", "接口", "endpoint")) or text
        return _tool_call(
            call_type="tool_call",
            tool_name="api_call",
            arguments={
                "method": _extract_http_method(text),
                "endpoint": url,
            },
        )

    url = _first_url(text)
    if url:
        return _tool_call(
            call_type="tool_call",
            tool_name="browser_search",
            arguments={"query": url},
        )

    if _looks_like_browser_search(lower):
        return _tool_call(
            call_type="tool_call",
            tool_name="browser_search",
            arguments={"query": text},
        )

    if _looks_like_file_operation(text, lower):
        action = _extract_file_action(lower)
        path = _first_path(text) or text
        return _tool_call(
            call_type="file_access",
            tool_name="file_operation",
            arguments={"action": action, "path": path},
            extra_payload={"action": action, "path": path},
        )

    if _looks_like_prompt_attack(text, lower):
        return _tool_call(
            call_type="llm_input",
            tool_name="prompt_input",
            arguments={"message": text},
            extra_payload={"message": text},
        )

    return _tool_call(
        call_type="llm_input",
        tool_name="prompt_input",
        arguments={"message": text},
        extra_payload={"message": text},
    )


def _tool_call(
    *,
    call_type: str,
    tool_name: str,
    arguments: dict[str, Any],
    extra_payload: dict[str, Any] | None = None,
) -> InferredToolCall:
    payload = {
        "tool_name": tool_name,
        "arguments": dict(arguments),
        "source": "openmanus_adapter",
    }
    if extra_payload:
        payload.update(extra_payload)
    return InferredToolCall(call_type=call_type, tool_name=tool_name, arguments=dict(arguments), payload=payload)


def _decision_to_dict(decision: Any) -> dict[str, Any]:
    if hasattr(decision, "to_dict"):
        data = decision.to_dict()
    elif isinstance(decision, dict):
        data = dict(decision)
    else:
        data = {
            "decision": getattr(decision, "decision", None),
            "reason": getattr(decision, "reason", None),
            "risk_score": getattr(decision, "risk_score", None),
            "rules": getattr(decision, "rules", None),
            "event_id": getattr(decision, "event_id", None),
            "timestamp": getattr(decision, "timestamp", None),
        }

    value = str(data.get("decision") or "deny")
    if value not in {"allow", "deny", "ask"}:
        value = "deny"
    rules = data.get("rules")
    if not isinstance(rules, list):
        rules = [] if rules is None else [str(rules)]
    return {
        "decision": value,
        "reason": str(data.get("reason") or "Monitor decision did not include a reason."),
        "risk_score": _float_or_default(data.get("risk_score"), 80.0 if value in {"deny", "ask"} else 0.0),
        "rules": [str(rule) for rule in rules],
        "event_id": str(data.get("event_id") or ""),
        "timestamp": str(data.get("timestamp") or _utc_now_iso()),
    }


def _answer_for_decision(
    payload: dict[str, Any],
    inferred: InferredToolCall,
    decision: dict[str, Any],
    redacted_message: str,
) -> str:
    if decision["decision"] == "deny":
        return _redact(f"安全策略已拒绝 {inferred.tool_name} 调用：{decision['reason']}")
    if decision["decision"] == "ask":
        return _redact(f"安全策略要求人工确认后才能继续 {inferred.tool_name} 调用：{decision['reason']}")

    answer = payload.get("answer")
    if answer:
        return _redact(str(answer)).replace("{message}", redacted_message)
    return _redact(
        f"OpenManus simulated {inferred.tool_name} execution after monitor allow: {decision['reason']}"
    )


def _simulated_tool_call(inferred: InferredToolCall, decision: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool_call_id": f"openmanus_{inferred.tool_name}_0",
        "name": inferred.tool_name,
        "args_summary": _summary(inferred.arguments),
        "result_summary": _summary(f"Allowed by monitor: {decision['reason']}"),
        "timestamp": _utc_now_iso(),
    }


def _audit_event(
    inferred: InferredToolCall,
    decision: dict[str, Any],
    *,
    user_id: str,
    session_id: str,
) -> dict[str, Any]:
    event = {
        "event_type": inferred.call_type,
        "call_type": inferred.call_type,
        "tool_name": inferred.tool_name,
        "source": "openmanus_adapter",
        "user_id": user_id,
        "session_id": session_id,
        "args_summary": _summary(inferred.arguments),
        "decision": decision["decision"],
        "risk_score": decision["risk_score"],
        "reason": decision["reason"],
        "rules": list(decision["rules"]),
        "timestamp": decision["timestamp"],
    }
    if decision["event_id"]:
        event["event_id"] = decision["event_id"]
    return event


def _normalise_audit_event(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {"event_type": "openmanus_audit", "summary": _summary(item), "timestamp": _utc_now_iso()}
    payload = {str(key): _redact(value) if isinstance(value, str) else value for key, value in item.items()}
    for key in ("decision", "risk_score", "reason", "rules"):
        payload.pop(key, None)
    payload.setdefault("timestamp", _utc_now_iso())
    return payload


_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_URL_RE = re.compile(r"https?://[^\s'\"<>，。；、)）]+", re.IGNORECASE)
_HTTP_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\b", re.IGNORECASE)
_PATH_RE = re.compile(
    r"(?<!:)(?:\.\./)+(?:[\w.-]+/)*[\w.-]+|(?<!:)~?/(?:[\w.-]+/)*[\w.-]+|[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\?)+"
)


def _looks_like_python_execution(lower: str) -> bool:
    return any(
        marker in lower
        for marker in (
            "python:",
            "python_execute",
            "```python",
            "执行代码",
            "代码执行",
            "运行代码",
            "执行 python",
            "执行python",
            "python 命令",
            "python命令",
            "运行 python",
            "读取环境变量",
            "环境变量",
            "run python",
            "run code",
            "os.system",
            "subprocess",
        )
    )


def _looks_like_email(text: str, lower: str) -> bool:
    return bool(_EMAIL_RE.search(text)) or any(marker in lower for marker in ("send_email", "send email", "发邮件", "发送邮件", "发到"))


def _looks_like_sql(lower: str) -> bool:
    return bool(
        re.search(
            r"\b(select|show|describe|explain|drop|delete|update|insert|truncate|alter|create)\b",
            lower,
        )
    ) or "sql" in lower


def _looks_like_api_call(text: str, lower: str) -> bool:
    return bool(_HTTP_METHOD_RE.search(text)) or any(
        marker in lower
        for marker in ("api_call", "api ", "http request", "接口", "调用api", "调用 api", "curl ")
    )


def _looks_like_browser_search(lower: str) -> bool:
    return any(
        marker in lower
        for marker in (
            "browser_search",
            "search ",
            "search for",
            "look up",
            "browse ",
            "搜索",
            "检索",
            "查询",
            "查找",
            "访问",
            "浏览",
            "查一下",
            "搜一下",
            "查手机号",
        )
    )


def _looks_like_file_operation(text: str, lower: str) -> bool:
    return bool(_PATH_RE.search(text)) or any(
        marker in lower
        for marker in ("file_operation", "file access", "读取文件", "写入文件", "删除文件", "读取路径", "read file", "write file")
    )


def _looks_like_prompt_attack(text: str, lower: str) -> bool:
    return bool(text) and any(
        marker in lower
        for marker in (
            "忽略",
            "无视",
            "忘记",
            "忘掉",
            "越狱",
            "dan",
            "解除限制",
            "无限制",
            "扮演",
            "角色扮演",
            "假装",
            "你现在是",
            "系统提示词",
            "提示词",
            "初始指令",
            "设定",
            "ignore",
            "disregard",
            "jailbreak",
            "act as",
            "pretend",
        )
    )


def _extract_python_code(text: str) -> str:
    fenced = re.search(r"```(?:python)?\s*([\s\S]*?)```", text, re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip()
    return _extract_after_marker(text, ("python:", "python_execute", "执行代码", "运行代码", "run code")) or text


def _extract_subject(text: str) -> str:
    match = re.search(r"(?:subject|主题)[:：]\s*([^\n。]+)", text, re.IGNORECASE)
    return match.group(1).strip()[:80] if match else "OpenManus notification"


def _extract_sql(text: str) -> str:
    match = re.search(
        r"\b(select|show|describe|explain|drop|delete|update|insert|truncate|alter|create)\b[\s\S]*",
        text,
        re.IGNORECASE,
    )
    return match.group(0).strip() if match else text


def _extract_http_method(text: str) -> str:
    match = _HTTP_METHOD_RE.search(text)
    if match:
        return match.group(1).upper()
    return "POST" if "curl " in text.lower() and " -d " in text.lower() else "GET"


def _extract_file_action(lower: str) -> str:
    if any(marker in lower for marker in ("delete", "删除", "rm ")):
        return "delete"
    if any(marker in lower for marker in ("write", "append", "写入", "追加", "保存")):
        return "write"
    if any(marker in lower for marker in ("list", "ls ", "列出")):
        return "list"
    if any(marker in lower for marker in ("stat", "状态")):
        return "stat"
    return "read"


def _extract_after_marker(text: str, markers: tuple[str, ...]) -> str:
    lower = text.lower()
    for marker in markers:
        index = lower.find(marker.lower())
        if index >= 0:
            return text[index + len(marker) :].strip(" ：:，,\n\t")
    return ""


def _first_url(text: str) -> str:
    return _first_match(text, _URL_RE)


def _first_path(text: str) -> str:
    return _first_match(text, _PATH_RE)


def _first_match(text: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(text)
    return match.group(0).strip() if match else ""


def _float_or_default(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _risk_level_from_score(score: float) -> str:
    if score >= 95:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _summary(value: Any, *, limit: int = 240) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    text = _redact(text)
    return text if len(text) <= limit else f"{text[: limit - 3]}..."


def _redact(text: str) -> str:
    return re.sub(r"\b(1[3-9]\d)(\d{4})(\d{4})\b", r"\1****\3", text)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
