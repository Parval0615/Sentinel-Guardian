from __future__ import annotations

from html.parser import HTMLParser
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from redsentinel.application.contracts import (
    AgentSecurityReport,
    Finding,
    ReportArtifacts,
    ScenarioResult,
)


class _DashboardDOMParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.inputs: list[dict[str, str]] = []
        self.select_options: dict[str, list[dict[str, str]]] = {}
        self.data_method_panels: set[str] = set()
        self.data_profile_fields: set[str] = set()
        self.data_stages: set[str] = set()
        self.labels: dict[str, str] = {}
        self._current_label_for: str | None = None
        self._current_label_text: list[str] = []
        self._current_select_id: str | None = None
        self._current_option_attrs: dict[str, str] | None = None
        self._current_option_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name: value or "" for name, value in attrs}
        if element_id := attr_map.get("id"):
            self.ids.add(element_id)
        if tag == "input":
            self.inputs.append(attr_map)
        if panel := attr_map.get("data-method-panel"):
            self.data_method_panels.add(panel)
        if field := attr_map.get("data-profile-field"):
            self.data_profile_fields.add(field)
        if stage := attr_map.get("data-stage"):
            self.data_stages.add(stage)
        if tag == "select":
            self._current_select_id = attr_map.get("id") or attr_map.get("name")
            if self._current_select_id:
                self.select_options.setdefault(self._current_select_id, [])
        if tag == "option" and self._current_select_id:
            self._current_option_attrs = dict(attr_map)
            self._current_option_text = []
        if tag == "label" and attr_map.get("for"):
            self._current_label_for = attr_map["for"]
            self._current_label_text = []

    def handle_data(self, data: str) -> None:
        if self._current_label_for:
            self._current_label_text.append(data)
        if self._current_option_attrs is not None:
            self._current_option_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if (
            tag == "option"
            and self._current_select_id
            and self._current_option_attrs is not None
        ):
            option = dict(self._current_option_attrs)
            option["text"] = "".join(self._current_option_text).strip()
            self.select_options.setdefault(self._current_select_id, []).append(option)
            self._current_option_attrs = None
            self._current_option_text = []
        if tag == "select":
            self._current_select_id = None
        if tag == "label" and self._current_label_for:
            self.labels[self._current_label_for] = "".join(self._current_label_text).strip()
            self._current_label_for = None
            self._current_label_text = []


def _dashboard_index_html() -> str:
    return (Path(__file__).resolve().parents[1] / "index.html").read_text(encoding="utf-8")


def _parse_dashboard_index() -> _DashboardDOMParser:
    parser = _DashboardDOMParser()
    parser.feed(_dashboard_index_html())
    return parser


def test_public_homepage_contains_required_sections_and_workspace_ctas() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    for element_id in {
        "public-home",
        "public-home-nav",
        "home-hero",
        "home-hero-title",
        "home-capabilities",
        "home-flow",
        "home-trust",
        "home-cta",
        "home-footer",
        "home-nav-workspace-link",
        "home-hero-workspace-link",
        "home-cta-workspace-link",
        "product-workspace",
    }:
        assert element_id in dom.ids

    for label in {
        "Autonomous Agent Security Audit",
        "核心能力",
        "使用流程",
        "信任信息",
        "查看审计工作区",
        "自主测试规划",
        "隔离攻击与加固",
        "上线决策与证据",
        "下一轮攻击",
        "租户上下文",
        "密钥不落盘",
    }:
        assert label in html

    assert 'href="#product-workspace"' in html
    assert "--home-primary: #1F2A24" in html
    assert "--home-accent: #8A7A5E" in html
    assert "--color-background: #F7F4EE" in html
    assert "background: var(--home-primary)" in html
    assert "border-radius: 30px" in html
    assert ".home-link:focus-visible" in html
    assert "outline: 3px solid var(--home-focus-ring)" in html

    for workspace_id in {
        "agent-onboarding",
        "go-evaluation-entry",
        "start-evaluation-button",
        "next-round-button",
        "evaluation-logs",
    }:
        assert workspace_id in dom.ids


def test_auth_views_contain_login_register_controls_and_errors() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()
    inputs_by_id = {input_attrs.get("id"): input_attrs for input_attrs in dom.inputs}

    for element_id in {
        "login",
        "login-form",
        "login-account",
        "login-password",
        "login-password-toggle",
        "login-remember",
        "login-form-error",
        "login-account-error",
        "login-password-error",
        "login-submit",
        "login-register-link",
        "register",
        "register-form",
        "register-username",
        "register-email",
        "register-password",
        "register-confirm-password",
        "register-terms",
        "register-form-error",
        "register-username-error",
        "register-email-error",
        "register-password-error",
        "register-confirm-password-error",
        "register-terms-error",
        "register-submit",
        "register-login-link",
        "workspace-session",
        "workspace-user",
        "logout-button",
    }:
        assert element_id in dom.ids

    assert dom.labels["login-account"] == "账号"
    assert dom.labels["login-password"] == "密码"
    assert dom.labels["login-remember"] == "记住登录状态"
    assert dom.labels["register-username"] == "用户名"
    assert dom.labels["register-email"] == "邮箱"
    assert dom.labels["register-password"] == "密码"
    assert dom.labels["register-confirm-password"] == "确认密码"
    assert "我已阅读并同意 RedSentinel 工作区使用协议。" in html

    assert inputs_by_id["login-password"]["type"] == "password"
    assert inputs_by_id["login-remember"]["type"] == "checkbox"
    assert inputs_by_id["register-email"]["type"] == "email"
    assert inputs_by_id["register-terms"]["type"] == "checkbox"
    assert "显示密码" in html
    assert "隐藏密码" in html
    assert "立即注册" in html
    assert "返回登录" in html


def test_auth_scripts_validate_store_logout_and_authorize_workspace_requests() -> None:
    html = _dashboard_index_html()

    for snippet in {
        "function validateLoginForm()",
        "function validateRegisterForm()",
        "function isValidUsername(value)",
        "function isValidLoginAccount(value)",
        "function isValidEmail(value)",
        "function isStrongPassword(value)",
        "values.password !== values.confirmPassword",
        "if (!values.terms) errors.terms = '请先确认使用协议。';",
        "async function handleLoginSubmit(event)",
        "async function handleRegisterSubmit(event)",
        "postAuthJson('/v1/auth/login'",
        "postAuthJson('/v1/auth/register'",
        "async function postAuthJson(url, payload)",
        "function persistAuthToken(token, rememberMe)",
        "if (rememberMe) {",
        "window.localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, token)",
        "window.sessionStorage.setItem(AUTH_TOKEN_STORAGE_KEY, token)",
        "function clearStoredAuthToken()",
        "async function handleLogoutClick()",
        "fetch('/v1/auth/logout'",
        "window.location.hash = '#public-home'",
        "function authHeaders(headers = {})",
        "Authorization: 'Bearer ' + authToken",
        "function requireAuthenticatedWorkspace(message = '请先登录后进入工作区。')",
        "promptLoginForWorkspace(message)",
        "headers: authHeaders({ 'Content-Type': 'application/json' })",
        "headers: authHeaders()",
    }:
        assert snippet in html

    assert "localStorage.setItem('password'" not in html
    assert 'localStorage.setItem("password"' not in html
    assert "sessionStorage.setItem('password'" not in html
    assert 'sessionStorage.setItem("password"' not in html


def test_login_form_client_validation_blocks_empty_invalid_account_and_empty_password() -> None:
    html = _dashboard_index_html()

    for snippet in {
        "if (!values.account) {\n"
        "        errors.account = '请输入账号。';\n"
        "      } else if (!isValidLoginAccount(values.account)) {\n"
        "        errors.account = '请输入有效用户名或邮箱。';\n"
        "      }",
        "if (!values.password) errors.password = '请输入密码。';",
        "function isValidLoginAccount(value) {\n"
        "      return isValidUsername(value) || isValidEmail(value);\n"
        "    }",
        "applyAuthFieldErrors('login', errors);",
        "const firstErrorInputId = errors.account ? 'login-account' : errors.password ? 'login-password' : '';",
        "if (firstErrorInput) firstErrorInput.focus({ preventScroll: true });",
    }:
        assert snippet in html

    assert html.index("if (!result.isValid) return;") < html.index("postAuthJson('/v1/auth/login'")


def test_generate_dashboard_html() -> None:
    report = AgentSecurityReport(
        tenant_id="test_tenant",
        agent_id="test_agent",
        benchmark="test-benchmark",
        overall_score=80,
        risk_level="medium",
        findings=[
            Finding(
                finding_id="F001",
                scenario_id="test-scenario-1",
                severity="high",
                title="Test finding",
                description="Test description",
                business_impact="Test impact",
                recommendation="Test recommendation",
            )
        ],
        scenario_results=[
            ScenarioResult(
                scenario_id="test-scenario-1",
                category="test",
                severity="high",
                expected_decision="block",
                actual_decision="block",
                clean_decision="allow",
                passed=True,
                business_impact="None",
                trajectory_ref="trajectory-1.json",
            )
        ],
        artifacts=ReportArtifacts(
            trajectory_refs=["trajectory-1.json"],
            audit_refs=["audit-1.log"],
            report_path="reports/test.json",
        ),
        attack_success_rate=0.2,
        false_positive_rate=0.05,
    )

    from frontend.generator import generate_dashboard_html

    html = generate_dashboard_html(report)

    assert "<html" in html.lower()
    assert "<head>" in html.lower()
    assert "<body>" in html.lower()
    assert "RedSentinel" in html
    assert "test_agent" in html
    assert "test_tenant" in html
    assert "80" in html
    assert "medium" in html.lower()


def test_generate_dashboard_html_escapes_dynamic_report_fields() -> None:
    payload = '<script>alert("xss")</script>'
    report = AgentSecurityReport(
        tenant_id=f"tenant-{payload}",
        agent_id=f"agent-{payload}",
        benchmark=f"benchmark-{payload}",
        overall_score=80,
        risk_level="high",
        findings=[
            Finding(
                finding_id="F001",
                scenario_id=f"finding-scenario-{payload}",
                severity="high",
                title=f"title-{payload}",
                description=f"description-{payload}",
                business_impact=f"finding-impact-{payload}",
                recommendation=f"recommendation-{payload}",
            )
        ],
        scenario_results=[
            ScenarioResult(
                scenario_id=f"scenario-{payload}",
                category=f"category-{payload}",
                severity="high",
                expected_decision="block",
                actual_decision="allow",
                clean_decision="allow",
                passed=False,
                business_impact=f"scenario-impact-{payload}",
                trajectory_ref=f"trajectory-{payload}.json",
            )
        ],
        artifacts=ReportArtifacts(
            trajectory_refs=[f"trajectory-{payload}.json"],
            audit_refs=[],
            report_path="reports/test.json",
        ),
        attack_success_rate=1.0,
        false_positive_rate=0.0,
    )

    from frontend.generator import generate_dashboard_html

    html = generate_dashboard_html(report)

    assert payload not in html
    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html
    assert "\\u003cscript\\u003ealert" in html
    assert "function escapeHtml(value)" in html
    assert "safeCssToken(s.severity, 'medium')" in html
    assert "escapeHtml(s.scenario_id || '--')" in html
    assert "escapeHtml(f.title || '-')" in html
    assert "escapeHtml(node)" in html
    assert "escapeHtml(s.output_content || '(empty)')" in html
    assert "escapeHtml(JSON.stringify(s.arguments || {}))" in html
    assert "${s.scenario_id}" not in html
    assert "${f.title}" not in html
    assert "${s.output_content || '(empty)'}" not in html


def test_write_dashboard_html(tmp_path: Path) -> None:
    report = AgentSecurityReport(
        tenant_id="test_tenant",
        agent_id="test_agent",
        benchmark="test-benchmark",
        overall_score=90,
        risk_level="low",
        findings=[],
        scenario_results=[],
        artifacts=ReportArtifacts(
            trajectory_refs=[],
            audit_refs=[],
            report_path="reports/test.json",
        ),
        attack_success_rate=0.0,
        false_positive_rate=0.0,
    )

    from frontend.generator import write_dashboard_html

    output_path = tmp_path / "dashboard.html"
    write_dashboard_html(report, output_path)

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    assert "<html" in content.lower()
    assert "90" in content
    assert "low" in content.lower()


def test_render_markdown_report() -> None:
    from redsentinel.reporting.engine.reports import render_markdown_report

    report = AgentSecurityReport(
        tenant_id="test_tenant",
        agent_id="test_agent",
        benchmark="test-benchmark",
        overall_score=75,
        risk_level="medium",
        findings=[],
        scenario_results=[],
        artifacts=ReportArtifacts(
            trajectory_refs=[],
            audit_refs=[],
            report_path="reports/test.json",
        ),
        attack_success_rate=0.3,
        false_positive_rate=0.1,
    )

    md = render_markdown_report(report)

    assert "# Agent Security Report" in md
    assert "test_agent" in md
    assert "test_tenant" in md
    assert "75" in md
    assert "medium" in md


def test_write_report_artifacts_with_dashboard(tmp_path: Path) -> None:
    from redsentinel.reporting.engine.reports import write_report_artifacts

    report = AgentSecurityReport(
        tenant_id="test_tenant",
        agent_id="test_agent",
        benchmark="test-benchmark",
        overall_score=85,
        risk_level="low",
        findings=[],
        scenario_results=[],
        artifacts=ReportArtifacts(
            trajectory_refs=[],
            audit_refs=[],
            report_path="reports/test.json",
        ),
        attack_success_rate=0.15,
        false_positive_rate=0.02,
    )

    report_path = tmp_path / "report.json"
    md_path = tmp_path / "report.md"
    dashboard_path = tmp_path / "dashboard.html"

    write_report_artifacts(report, report_path, md_path, dashboard_path)

    assert report_path.exists()
    assert md_path.exists()
    assert dashboard_path.exists()

    report_data = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_data["agent_id"] == "test_agent"
    assert report_data["overall_score"] == 85


def test_risk_level_from_findings() -> None:
    from redsentinel.reporting.engine.reports import risk_level_from_findings

    assert risk_level_from_findings([]) == "low"
    assert risk_level_from_findings([Finding(finding_id="F1", scenario_id="S1", severity="low", title="t", description="d", business_impact="i", recommendation="r")]) == "low"
    assert risk_level_from_findings([Finding(finding_id="F1", scenario_id="S1", severity="medium", title="t", description="d", business_impact="i", recommendation="r")]) == "medium"
    assert risk_level_from_findings([Finding(finding_id="F1", scenario_id="S1", severity="high", title="t", description="d", business_impact="i", recommendation="r")]) == "high"
    assert risk_level_from_findings([Finding(finding_id="F1", scenario_id="S1", severity="critical", title="t", description="d", business_impact="i", recommendation="r")]) == "critical"
    assert risk_level_from_findings([
        Finding(finding_id="F1", scenario_id="S1", severity="low", title="t", description="d", business_impact="i", recommendation="r"),
        Finding(finding_id="F2", scenario_id="S2", severity="critical", title="t", description="d", business_impact="i", recommendation="r"),
    ]) == "critical"


def test_score_from_findings() -> None:
    from redsentinel.reporting.engine.reports import score_from_findings

    assert score_from_findings([]) == 100
    assert score_from_findings([Finding(finding_id="F1", scenario_id="S1", severity="low", title="t", description="d", business_impact="i", recommendation="r")]) == 95
    assert score_from_findings([Finding(finding_id="F1", scenario_id="S1", severity="medium", title="t", description="d", business_impact="i", recommendation="r")]) == 90
    assert score_from_findings([Finding(finding_id="F1", scenario_id="S1", severity="high", title="t", description="d", business_impact="i", recommendation="r")]) == 80
    assert score_from_findings([Finding(finding_id="F1", scenario_id="S1", severity="critical", title="t", description="d", business_impact="i", recommendation="r")]) == 70
    assert score_from_findings([
        Finding(finding_id="F1", scenario_id="S1", severity="critical", title="t", description="d", business_impact="i", recommendation="r"),
        Finding(finding_id="F2", scenario_id="S2", severity="critical", title="t", description="d", business_impact="i", recommendation="r"),
        Finding(finding_id="F3", scenario_id="S3", severity="critical", title="t", description="d", business_impact="i", recommendation="r"),
        Finding(finding_id="F4", scenario_id="S4", severity="critical", title="t", description="d", business_impact="i", recommendation="r"),
    ]) == 0


def test_agent_onboarding_dom_contains_source_only_fields() -> None:
    dom = _parse_dashboard_index()

    assert "agent-onboarding-form" in dom.ids
    assert "agent-onboarding" in dom.ids
    assert {
        input_attrs.get("value")
        for input_attrs in dom.inputs
        if input_attrs.get("name") == "integration_type"
    } == {"source"}
    assert dom.data_method_panels == {"source"}

    for field_id, label in {
        "onboard-username": "用户名",
        "onboard-agent-name": "Agent 名称",
        "onboard-agent-id": "Agent ID",
        "onboard-domain": "业务领域",
        "onboard-framework": "框架类型",
        "onboard-remarks": "备注",
        "onboard-source-path": "源码目录",
        "onboard-build-manifest-path": "沙箱构建清单",
    }.items():
        assert field_id in dom.ids
        assert dom.labels[field_id] == label

    assert "onboard-docker-files" not in dom.ids
    assert "onboard-endpoint-url" not in dom.ids
    assert "onboard-api-key" not in dom.ids


def test_agent_onboarding_autogen_option_is_scaffold_only() -> None:
    dom = _parse_dashboard_index()

    framework_options = {
        option.get("value"): option
        for option in dom.select_options.get("onboard-framework", [])
    }
    autogen_option = framework_options["autogen"]

    assert "disabled" in autogen_option
    assert "unsupported scaffold" in autogen_option["text"].lower()


def test_agent_onboarding_loading_profile_and_username_dom() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    assert "onboarding-progress" in dom.ids
    assert dom.data_stages == {
        "source_snapshot",
        "profile_analysis",
        "sandbox_build_plan",
    }
    assert "源码快照" in html
    assert "画像分析" in html
    assert "沙箱构建计划" in html

    assert "agent-profile-card" in dom.ids
    assert "profile-tenant-id" in dom.ids
    assert "tenant_id" in dom.data_profile_fields
    assert '<div class="profile-label">用户名</div>' in html


def test_agent_onboarding_script_covers_source_loading_profile_and_fallback() -> None:
    html = _dashboard_index_html()

    assert "function switchOnboardingType(type)" not in html
    assert "panel.hidden = panel.dataset.methodPanel !== type" not in html
    assert "async function handleAgentOnboardingSubmit(event)" in html
    assert "source_path: readFieldValue('onboard-source-path')" in html
    assert "build_manifest_path: readFieldValue('onboard-build-manifest-path')" in html
    assert "setOnboardingStageStatus('source_snapshot', 'running')" in html
    assert "await runOnboardingProgress(responseData.stages)" in html
    assert "fetch('/v1/agents/onboard'" in html
    assert "function buildOfflineOnboardingResponse(payload, error)" in html
    assert "status: 'failed'" in html
    assert "ready: false" in html
    assert "source_snapshot_verified: false" in html
    assert "endpoint_url:" not in html
    assert "api_key:" not in html
    assert "docker_image:" not in html
    assert "首页安全统计未被改写" in html
    assert "setText('profile-tenant-id'" in html


def test_dashboard_summary_cards_chart_empty_state_and_navigation() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    assert html.count('class="metric-card"') == 4
    for element_id in {
        "overall-score",
        "risk-level",
        "attack-success-rate",
        "false-positive-rate",
        "dashboard-empty-state",
        "asr-chart",
        "chart-empty-state",
        "go-evaluation-entry",
        "logs-entry-link",
        "evaluation-logs",
    }:
        assert element_id in dom.ids

    assert "当前安全分数" in html
    assert "风险等级" in html
    assert "最近 ASR" in html
    assert "最近 FPR" in html
    assert "去评测" in html
    assert "查日志" in html
    assert "暂无评测数据" in html

    assert "fetch('/v1/dashboard/summary?agent_id=' + encodeURIComponent(agentId)" in html
    assert "summary.current_security_score" in html
    assert "summary.current_risk_level" in html
    assert "summary.recent_asr" in html
    assert "summary.recent_fpr" in html
    assert "renderASRFPRChart(summary.trend || [])" in html
    assert "label: 'ASR (%)'" in html
    assert "label: 'FPR (%)'" in html
    assert "dashboard summary 接口暂不可用或当前 Agent 未注册，未展示任何伪造指标。" in html
    assert "renderMetrics()" not in html
    assert "reportData.overall_score ?? 0" not in html


def test_evaluation_logs_list_detail_metrics_and_node_markers() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    for element_id in {
        "evaluation-logs",
        "evaluation-logs-title",
        "logs-refresh-button",
        "logs-status",
        "logs-empty-state",
        "logs-table-wrap",
        "logs-table",
        "logs-body",
        "log-detail-card",
        "log-detail-empty-state",
        "log-detail-content",
    }:
        assert element_id in dom.ids

    for label in {
        "评测日志",
        "评测得分",
        "ASR",
        "FPR",
        "Agent 最薄弱环节",
        "Benchmark 版本",
        "评测时间",
        "状态",
        "测试用例总数",
        "测试用例 Prompt",
        "RAG 文档",
        "主要测试节点",
        "被绕过节点",
        "关键节点拦截状态",
        "成功拦截",
        "未成功拦截",
    }:
        assert label in html

    assert "function initEvaluationLogs()" in html
    assert "showEvaluationLogs()" in html
    assert "async function loadEvaluationLogs(options = {})" in html
    assert "fetch('/v1/logs?agent_id=' + encodeURIComponent(agentId) + '&tenant_id=' + encodeURIComponent(tenantId), {" in html
    assert "sortLogsByEvaluatedAtDesc" in html
    assert "logTimestamp(right) - logTimestamp(left)" in html
    assert "renderEvaluationLogs(evaluationLogs)" in html

    assert "item.score" in html
    assert "item.asr" in html
    assert "item.fpr" in html
    assert "item.weakest_link" in html
    assert "item.benchmark_version" in html
    assert "item.evaluated_at" in html
    assert "item.status" in html

    assert "async function toggleLogDetail(evaluationId)" in html
    assert "const tenantId = getCurrentTenantId()" in html
    assert "fetch('/v1/logs/' + encodeURIComponent(evaluationId) + '?tenant_id=' + encodeURIComponent(tenantId), {" in html
    assert "function logDetailCacheKey(evaluationId, tenantId = getCurrentTenantId())" in html
    assert "const cacheKey = logDetailCacheKey(evaluationId, tenantId)" in html
    assert "logDetailsById[cacheKey]" in html
    assert "detail.metrics || {}" in html
    assert "metrics.dsr" in html
    assert "detail.total_case_count" in html
    assert "detail.prompts" in html
    assert "detail.rag_documents" in html
    assert "detail.target_nodes" in html
    assert "detail.bypassed_nodes" in html
    assert "detail.critical_node_blocked" in html
    assert "renderCriticalNodeBlocked(detail.critical_node_blocked)" in html
    assert "日志接口暂不可用，未展示任何伪造日志。" in html
    assert "日志详情接口暂不可用，未展示任何伪造详情。" in html


def test_supervision_panel_events_summary_refresh_and_ask_controls() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    for element_id in {
        "supervision-entry-link",
        "supervision-panel",
        "supervision-title",
        "supervision-refresh-button",
        "supervision-demo-seed-button",
        "supervision-status",
        "supervision-last-update",
        "supervision-summary-allow",
        "supervision-summary-deny",
        "supervision-summary-ask",
        "supervision-summary-high-risk",
        "supervision-empty-state",
        "supervision-events-list",
    }:
        assert element_id in dom.ids

    for label in {
        "监督端",
        "刷新监督事件",
        "生成演示事件",
        "放行",
        "阻断",
        "询问",
        "高风险",
        "allow / deny / ask",
        "监督事件暂不可用，未展示伪造事件。",
        "批准",
        "拒绝",
    }:
        assert label in html

    for snippet in {
        "function initSupervisionPanel()",
        "function showSupervisionPanel()",
        "function startSupervisionPolling()",
        "async function loadSupervisionLatest(options = {})",
        "async function seedSupervisionDemoEvents()",
        "function renderSupervisionSnapshot(snapshot = {})",
        "function renderSupervisionEvents(events)",
        "function renderSupervisionEventCard(event)",
        "async function respondToSupervisionAsk(eventId, action)",
        "fetch('/v1/supervision/latest'",
        "fetch('/v1/supervision/demo-seed'",
        "fetch('/v1/supervision/ask/' + encodeURIComponent(eventId) + '/respond'",
        "headers: authHeaders({ 'Content-Type': 'application/json' })",
        "data-supervision-action=\"approve\"",
        "data-supervision-action=\"reject\"",
        "event.decision === 'ask' && event.status === 'pending'",
        "window.setInterval",
        "initSupervisionPanel();",
    }:
        assert snippet in html


def test_experiment_summary_and_attack_trace_timeline_rendering_hooks() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    for element_id in {
        "experiment-summary-section",
        "experiment-summary-title",
        "experiment-summary-status",
        "experiment-summary-empty-state",
        "experiment-summary-content",
        "experiment-asr-before",
        "experiment-asr-after",
        "experiment-fpr",
        "experiment-blocked",
        "experiment-asked",
        "experiment-asr-bars",
        "attack-trace-timeline",
        "attack-trace-title",
        "attack-trace-empty-state",
        "attack-trace-timeline-list",
    }:
        assert element_id in dom.ids

    for label in {
        "防御前后 ASR 对照",
        "ASR Before",
        "ASR After",
        "FPR",
        "Blocked",
        "Asked",
        "告警 → 工具调用 → payload id",
        "暂无防御前后 ASR 对照数据。未展示任何伪造指标。",
        "未展示任何伪造指标",
        "暂无溯源事件",
    }:
        assert label in html

    for snippet in {
        "async function loadExperimentSummary()",
        "async function loadExperimentSummaryFallback()",
        "function renderExperimentSummary(summary)",
        "function renderAttackTraceTimeline(events = [])",
        "function normalizeAttackTraceEvents(events)",
        "fetch('/v1/experiments/summary'",
        "fetch('experiments/results/latest/asr_before_after.json')",
        "await loadExperimentSummary();",
        "renderAttackTraceTimeline(traces)",
        "if (events.length) renderAttackTraceTimeline(events);",
    }:
        assert snippet in html

    for field in {
        "event_id",
        "agent_id",
        "call_type",
        "rule_name",
        "payload_id",
        "case_id",
        "decision",
    }:
        assert field in html


def test_security_events_loader_uses_monitor_api_and_mock_events_fallback() -> None:
    html = _dashboard_index_html()
    mock_events_path = Path(__file__).resolve().parents[1] / "data" / "mock_events.json"
    mock_events = json.loads(mock_events_path.read_text(encoding="utf-8"))

    assert [event["decision"] for event in mock_events] == ["allow", "deny", "ask"]
    for snippet in {
        "async function loadSecurityEvents(options = {})",
        "new URLSearchParams()",
        "params.set('agent_id', agentId)",
        "params.set('decision', options.decision)",
        "params.set('session_id', sessionId)",
        "params.set('limit', String(options.limit))",
        "fetch('/v1/monitor/events' + (query ? '?' + query : '')",
        "fetch('data/mock_events.json')",
    }:
        assert snippet in html


def test_benchmark_selection_versions_details_and_case_markers() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    for element_id in {
        "benchmark-selection",
        "benchmark-select",
        "benchmark-version-select",
        "benchmark-status",
        "benchmark-list",
        "benchmark-detail-card",
        "benchmark-empty-state",
    }:
        assert element_id in dom.ids

    assert dom.labels["benchmark-select"] == "Benchmark"
    assert dom.labels["benchmark-version-select"] == "版本"
    assert "读取预设基准测试集" in html
    assert "ecommerce-security-v0.1" in html
    assert "fetch('/v1/benchmarks')" in html
    assert "fetch('/v1/benchmarks/' + encodeURIComponent(benchmarkId) + '/versions')" in html
    assert "fetch('/v1/benchmarks/' + encodeURIComponent(benchmarkId) + '/versions/' + encodeURIComponent(version))" in html
    assert "loadBenchmarks()" in html
    assert "section.hidden = false" in html

    assert "展开测试集详情" in html
    assert "用例总数" in html
    assert "目标节点" in html
    assert "caseItem.prompt" in html
    assert "caseItem.rag_document_summary" in html
    assert "caseItem.target_node" in html
    assert "caseItem.case_type === 'clean'" in html
    assert ".case-type.attack" in html
    assert ".case-type.clean" in html


def test_benchmark_evaluation_start_progress_and_next_round_binding() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    for element_id in {
        "start-evaluation-button",
        "evaluation-progress-card",
        "evaluation-progress-text",
        "evaluation-progress-bar",
        "evaluation-progress-fill",
        "evaluation-progress-completed",
        "evaluation-progress-total",
        "evaluation-progress-percent",
        "evaluation-current-case",
        "evaluation-current-node",
        "evaluation-mode",
        "evaluation-report-summary",
    }:
        assert element_id in dom.ids

    assert "启动评测" in html
    assert "completed_cases" in html
    assert "total_cases" in html
    assert "percent" in html
    assert "current_case" in html
    assert "current_node" in html
    assert '<div class="benchmark-summary-label">模式</div>' in html
    assert "查看报告摘要" in html
    assert "需要先接入 Agent，填写 Agent ID 后再启动评测。" in html
    assert "评测接口暂不可用，未展示伪造结果。" in html

    assert "function getCurrentEvaluationId()" in html
    assert "return currentEvaluationId || getUrlParam('evaluation_id')" in html
    assert "function getEvaluationAgentId()" in html
    assert "async function handleStartEvaluationClick()" in html
    assert "function buildEvaluationPayload()" in html
    assert "agent_id: agentId" in html
    assert "tenant_id: tenantId" in html
    assert "benchmark_id: benchmarkId" in html
    assert "benchmark_version: benchmarkVersion" in html
    assert "mode: getEvaluationMode()" in html
    assert "function getEvaluationMode()" in html
    assert "currentAgentSandboxAdapter === 'openmanus' ? 'openmanus_real' : 'sdk'" in html

    assert "fetch('/v1/evaluations', {" in html
    assert "method: 'POST'" in html
    assert "body: JSON.stringify(payload)" in html
    assert "fetch('/v1/evaluations/' + encodeURIComponent(evaluationId), {" in html
    assert "async function loadGeneratedReport(status, tenantId)" in html
    assert "fetch('/v1/reports/' + encodeURIComponent(reportId)" in html
    assert "reportData = await response.json()" in html
    assert "renderEvaluationReportSummary(finalStatus, reportLoaded ? 'loaded' : 'error')" in html
    assert "评测完成，真实报告摘要已刷新。" in html
    assert "评测完成，但报告详情暂不可用。" in html
    assert "评测完成，正在加载报告详情。" in html
    assert "runtime_mode:" in html
    assert "real_runtime:" in html
    assert "simulated:" in html
    assert "real_tool_executions:" in html
    assert "currentEvaluationId = finalStatus.evaluation_id" in html
    assert "await loadDashboardSummary(payload.agent_id, payload.tenant_id)" in html
    assert "syncNextRoundControl()" in html
    assert "button.dataset.evaluationId = evaluationId" in html

    assert "progress.completed_cases" in html
    assert "progress.total_cases" in html
    assert "progress.percent" in html
    assert "progress.current_case" in html
    assert "progress.current_node" in html
    assert "status?.mode || getEvaluationMode()" in html
    assert "setText('evaluation-mode', evaluationMode)" in html

    assert "escapeHtml(scenarioId)" in html
    assert "escapeHtml(finding.title || '-')" in html
    assert "escapeHtml(step.output_content || '(empty)')" in html


def test_next_round_attack_control_status_api_and_prompt_refresh_logic() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    for element_id in {
        "next-round-section",
        "next-round-title",
        "next-round-button",
        "next-round-status",
        "next-round-result",
    }:
        assert element_id in dom.ids

    assert "生成下一轮攻击" in html
    assert "生成中..." in html
    assert "function getCurrentEvaluationId()" in html
    assert "reportData?.evaluation_id" in html
    assert "dashboardSummaryData?.latest_evaluation_id" in html
    assert "下一轮攻击不可用：当前报告缺少 evaluation_id，无法调用后端生成真实版本。" in html
    assert "下一轮攻击不可用：后端 /v1/evaluations/{evaluation_id}/next-round 暂不可达，未生成新版本。" in html

    assert "async function handleNextRoundClick()" in html
    assert "fetch('/v1/evaluations/' + encodeURIComponent(evaluationId) + '/next-round'" in html
    assert "method: 'POST'" in html
    assert "setNextRoundGenerating(true)" in html
    assert "setNextRoundStatus('正在生成下一轮攻击。', 'info')" in html

    assert "async function refreshBenchmarkAfterNextRound(result)" in html
    assert "next-round response missing benchmark version" in html
    assert "renderBenchmarkVersions(benchmarkVersionsById[result.benchmark_id], result.benchmark_version)" in html
    assert "renderBenchmarkDetail(result.version)" in html
    assert "setBenchmarkStatus('已切换到新版本 ' + result.benchmark_version + '，prompt 已刷新。', 'success')" in html
    assert "result.updated_prompt_count ?? result.version?.case_count ?? result.version?.cases?.length" in html
    assert "defense_suggestions" in html














def test_c2_audit_plan_page_exposes_real_plan_context_and_empty_state() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    required_ids = {
        "audit-plan-entry-link",
        "audit-plan",
        "audit-plan-id-input",
        "audit-plan-load-button",
        "audit-plan-state",
        "audit-plan-status",
        "audit-plan-empty-state",
        "audit-plan-content",
        "audit-plan-items",
        "audit-plan-budget",
        "audit-plan-normal-tasks",
        "audit-plan-stop-conditions",
        "audit-plan-warnings",
    }
    assert required_ids <= dom.ids
    assert 'id="audit-plan" aria-labelledby="audit-plan-title" hidden' in html
    assert "C2 / Autonomous Planning" in html
    assert "function initAuditPlan()" in html
    assert "function showAuditPlan()" in html
    assert "function loadAuditPlan()" in html
    assert "function renderAuditPlan(view)" in html
    assert "function renderAuditPolicyList(targetId, values)" in html
    assert "fetch('/v1/audits/' + encodeURIComponent(auditId) + '/plan', {" in html
    assert "未展示演示计划或伪造场景。" in html
    assert "escapeHtml(item.scenario_id" in html
    assert "escapeHtml(item.rationale" in html


def test_c5_audit_workspace_renders_real_checkpoint_sections() -> None:
    html = _dashboard_index_html()
    dom = _parse_dashboard_index()

    required_ids = {
        "audit-workspace-entry-link",
        "audit-workspace-c5",
        "audit-workspace-id-input",
        "audit-workspace-select",
        "audit-workspace-load-button",
        "audit-workspace-create",
        "audit-workspace-create-button",
        "audit-create-agent-id",
        "audit-create-normal-task",
        "audit-create-success-criteria",
        "audit-create-security-goals",
        "audit-create-risk-surfaces",
        "audit-workspace-state",
        "audit-workspace-status",
        "audit-workspace-empty-state",
        "audit-workspace-content",
        "audit-workspace-assets",
        "audit-workspace-stages",
        "audit-workspace-risks",
        "audit-workspace-scores",
        "audit-workspace-timeline",
        "audit-workspace-traces",
        "audit-workspace-decision",
        "audit-workspace-evidence",
    }
    assert required_ids <= dom.ids
    assert (
        'id="audit-workspace-c5" aria-labelledby="audit-workspace-title" hidden'
        in html
    )
    assert "C5 / Audit Workspace" in html
    assert "function initAuditWorkspace()" in html
    assert "function showAuditWorkspace()" in html
    assert "function loadAuditWorkspaceList()" in html
    assert "function loadAuditWorkspace()" in html
    assert "function createAuditFromWorkspace()" in html
    assert "function renderAuditWorkspace(view)" in html
    assert "function renderAuditWorkspaceScores(view)" in html
    assert "function renderAuditWorkspaceTimeline(view)" in html
    assert "function renderAuditWorkspaceTraces(traces)" in html
    assert "auditWorkspaceMetric(baseline, 'asr', 'attack_success_rate')" in html
    assert "escapeHtml(event.summary)" in html
    assert "escapeHtml(trace.trajectory_ref || '--')" in html
    assert "fetch('/v1/audits', { headers: authHeaders() })" in html
    assert "method: 'POST'" in html
    assert "body: JSON.stringify(payload)" in html
    assert (
        "fetch('/v1/audits/' + encodeURIComponent(auditId) + '/workspace', {"
        in html
    )
    assert "未展示示例结论或伪造证据。" in html
    assert "auditDecisionLabel(decision.decision)" in html
    assert "escapeHtml(item.ref || '--')" in html
