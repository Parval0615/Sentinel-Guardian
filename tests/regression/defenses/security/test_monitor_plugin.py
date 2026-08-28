from redsentinel.defenses.engine.monitor_plugin import Decision, intercept, safe_refusal
from redsentinel.defenses.engine.security.policy.engine import reset_policy_rules


REQUIRED_DECISION_FIELDS = {
    "decision",
    "reason",
    "risk_score",
    "confidence",
    "rules",
    "event_id",
    "timestamp",
}


def setup_function() -> None:
    reset_policy_rules()


def test_monitor_plugin_allows_supported_call_types() -> None:
    cases = [
        ("llm_input", {"content": "请总结这份订单。"}),
        ("llm_output", {"content": "订单摘要已生成。"}),
        ("tool_call", {"tool_name": "db_query", "arguments": {"sql": "SELECT * FROM users"}}),
        ("tool_result", {"result": "查询完成。"}),
        ("file_access", {"path": "/tmp/red-sentinel-report.txt", "action": "read"}),
    ]

    for call_type, payload in cases:
        decision = intercept(call_type, payload)

        assert isinstance(decision, Decision)
        assert decision.decision == "allow"
        assert decision.reason
        assert decision.rules


def test_monitor_plugin_allows_arithmetic_and_denies_dangerous_code() -> None:
    benign = intercept("code_execution", {"code": "print(17 * 23)"})
    dangerous = intercept(
        "code_execution",
        {"code": "import os; os.system('cat /etc/passwd')"},
    )

    assert benign.decision == "allow"
    assert benign.rules == ["exec_guard.code_execution"]
    assert dangerous.decision == "deny"
    assert dangerous.risk_score == 100.0
    assert dangerous.rules == ["exec_guard.code_execution"]


def test_monitor_plugin_denies_tool_call_and_builds_safe_refusal() -> None:
    decision = intercept(
        "tool_call",
        {"tool_name": "db_query", "arguments": {"sql": "DROP TABLE users"}},
    )

    assert decision.decision == "deny"
    assert decision.risk_score == 100.0
    assert decision.confidence == 0.95
    assert decision.rules == ["db_query.block_sql_keywords"]

    refusal = safe_refusal(decision)

    assert refusal["blocked"] is True
    assert refusal["pending"] is False
    assert refusal["decision"] == "deny"
    assert refusal["event_id"] == decision.event_id
    assert "拒绝" in refusal["message"]
    assert refusal["reason"] == decision.reason


def test_monitor_plugin_returns_ask_for_file_access_write() -> None:
    decision = intercept(
        "file_access",
        {"path": "/tmp/red-sentinel-report.txt", "action": "write"},
    )

    assert decision.decision == "ask"
    assert decision.risk_score == 50.0
    assert decision.confidence == 0.7
    assert decision.rules == ["file_operation.ask_actions"]

    refusal = safe_refusal(decision)
    assert refusal["blocked"] is False
    assert refusal["pending"] is True
    assert "人工确认" in refusal["message"]


def test_monitor_plugin_returns_ask_for_external_send_email() -> None:
    decision = intercept(
        "tool_call",
        {
            "tool_name": "send_email",
            "arguments": {
                "to": "customer@example.com",
                "subject": "Order ord_1001 support summary",
                "body": "Hello, here is the status summary for your order.",
            },
        },
    )

    assert decision.decision == "ask"
    assert decision.risk_score == 50.0
    assert decision.confidence == 0.7
    assert decision.rules == ["send_email.block_external_recipients"]


def test_monitor_plugin_denies_metadata_browser_search_and_allows_clean_search() -> None:
    decision = intercept(
        "tool_call",
        {
            "tool_name": "browser_search",
            "arguments": {"query": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        },
    )

    assert decision.decision == "deny"
    assert decision.risk_score == 80.0
    assert decision.rules == ["browser_search.block_metadata_endpoint"]

    clean = intercept(
        "tool_call",
        {
            "tool_name": "browser_search",
            "arguments": {"query": "RedSentinel OpenManus security benchmark"},
        },
    )

    assert clean.decision == "allow"
    assert clean.rules == ["browser_search.passed"]


def test_monitor_plugin_denies_browser_file_scheme() -> None:
    decision = intercept(
        "tool_call",
        {
            "tool_name": "browser_search",
            "arguments": {"query": "file:///workspace/private/redsentinel_canary.txt"},
        },
    )

    assert decision.decision == "deny"
    assert decision.rules == ["browser_search.block_uri_scheme"]


def test_monitor_plugin_denies_metadata_api_call() -> None:
    decision = intercept(
        "tool_call",
        {
            "tool_name": "api_call",
            "arguments": {"method": "GET", "endpoint": "http://169.254.169.254/latest/meta-data/"},
        },
    )

    assert decision.decision == "deny"
    assert decision.risk_score == 80.0
    assert decision.rules == ["api_call.block_metadata_endpoint"]


def test_monitor_plugin_decision_fields_are_complete() -> None:
    decision = intercept("llm_input", {"content": "正常请求"})
    data = decision.to_dict()

    assert set(data) == REQUIRED_DECISION_FIELDS
    assert data["decision"] in {"allow", "deny", "ask"}
    assert isinstance(data["reason"], str) and data["reason"]
    assert 0.0 <= data["risk_score"] <= 100.0
    assert 0.0 <= data["confidence"] <= 1.0
    assert isinstance(data["rules"], list)
    assert data["event_id"].startswith("evt_")
    assert data["timestamp"].endswith("Z")
