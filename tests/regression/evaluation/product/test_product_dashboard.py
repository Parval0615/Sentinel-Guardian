from pathlib import Path

from redsentinel.application.contracts import (
    AgentSecurityReport,
    Finding,
    ReportArtifacts,
    ScenarioResult,
)
from redsentinel.reporting.engine.reports import render_html_dashboard, write_report_artifacts


def test_render_html_dashboard_escapes_report_content() -> None:
    report = AgentSecurityReport(
        tenant_id="tenant_001",
        agent_id="agent_001",
        benchmark="ecommerce-security-v0.1",
        overall_score=80,
        risk_level="high",
        findings=[
            Finding(
                finding_id="finding_001",
                scenario_id="scenario_001",
                severity="high",
                title="<script>alert(1)</script>",
                description="Controlled attack was allowed.",
                business_impact="unauthorized_order_access",
                recommendation="Add order ownership checks.",
            )
        ],
        scenario_results=[
            ScenarioResult(
                scenario_id="scenario_001",
                category="cross_user_access",
                severity="high",
                expected_decision="block",
                actual_decision="allow",
                clean_decision="allow",
                passed=False,
                business_impact="unauthorized_order_access",
                trajectory_ref="runs/product/trace.json",
            )
        ],
        attack_success_rate=1.0,
        business_impact={"unauthorized_order_access": 1},
        artifacts=ReportArtifacts(
            trajectory_refs=["runs/product/trace.json"],
            audit_refs=["runs/product/audit-events.json"],
            report_path="runs/product/report.json",
        ),
    )

    html = render_html_dashboard(report)

    assert "RedSentinel" in html
    assert "Agent 上线安全审计报告" in html
    assert 'id="dashboard-data"' in html
    assert "function renderScenarios" in html
    assert "runs/product/audit-events.json" in html
    assert "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e" in html
    assert "<script>alert(1)</script>" not in html
    assert "FAIL" in html


def test_write_report_artifacts_writes_dashboard(tmp_path: Path) -> None:
    report = AgentSecurityReport(
        tenant_id="tenant_001",
        agent_id="agent_001",
        benchmark="ecommerce-security-v0.1",
        overall_score=100,
        risk_level="low",
        summary={"api_key": "sk-raw-secret", "masked_api_key": "sk-r...cret"},
        artifacts=ReportArtifacts(
            report_path=str(tmp_path / "agent-security-report-v0.1.json"),
            markdown_path=str(tmp_path / "agent-security-report-v0.1.md"),
            dashboard_path=str(tmp_path / "agent-security-dashboard-v0.1.html"),
        ),
    )

    write_report_artifacts(
        report,
        tmp_path / "agent-security-report-v0.1.json",
        tmp_path / "agent-security-report-v0.1.md",
        tmp_path / "agent-security-dashboard-v0.1.html",
    )

    assert (tmp_path / "agent-security-report-v0.1.json").exists()
    assert (tmp_path / "agent-security-report-v0.1.md").exists()
    assert (tmp_path / "agent-security-dashboard-v0.1.html").exists()
    assert "sk-raw-secret" not in (tmp_path / "agent-security-report-v0.1.json").read_text(encoding="utf-8")
    assert "sk-raw-secret" not in (tmp_path / "agent-security-dashboard-v0.1.html").read_text(encoding="utf-8")
