from pathlib import Path

import yaml


def test_product_openapi_contract_covers_hosted_api_surface() -> None:
    spec = yaml.safe_load(Path("docs/api/openapi.yaml").read_text(encoding="utf-8"))

    assert spec["openapi"] == "3.1.0"
    assert {
        "/v1/agents/onboard",
        "/v1/agents",
        "/v1/agents/{agent_id}/sessions",
        "/v1/evaluations",
        "/v1/evaluations/{evaluation_id}",
        "/v1/reports/{report_id}",
        "/v1/comparisons",
        "/v1/trajectories",
        "/v1/audits",
        "/v1/audits/{audit_id}",
        "/v1/audits/{audit_id}/execute",
        "/v1/runtime/audit-preflight/{agent_id}",
        "/v1/audits/{audit_id}/plan",
        "/v1/audits/{audit_id}/status",
        "/v1/audits/{audit_id}/evidence",
        "/v1/audits/{audit_id}/decision",
        "/v1/audits/{audit_id}/workspace",
        "/v1/audits/{audit_id}/resume",
    } <= set(spec["paths"])

    schemas = spec["components"]["schemas"]
    assert {
        "AgentOnboardingRequest",
        "AgentOnboardingResponse",
        "AgentMaterial",
        "AgentRegistration",
        "EvaluationRequest",
        "EvaluationStatus",
        "AgentSecurityReport",
        "AgentSecurityComparisonReport",
        "AuditTask",
        "AuditPlan",
        "AuditPlanItem",
        "AuditPlanView",
        "AuditStageRecord",
        "AuditStatusView",
        "AuditPreflightCheck",
        "AuditPreflightStatus",
        "AuditRun",
        "ReleaseDecision",
        "AuditWorkspaceView",
        "AuditTraceEvent",
        "AuditScenarioTrace",
    } <= set(schemas)
    assert schemas["AuditWorkspaceView"]["properties"]["traces"]["items"] == {
        "$ref": "#/components/schemas/AuditScenarioTrace"
    }
    assert "attack_review" in schemas["AuditRun"]["properties"]["state"]["enum"]
    assert spec["paths"]["/v1/audits/{audit_id}/plan"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AuditPlanView"
    }
    assert spec["paths"]["/v1/audits/{audit_id}/status"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AuditStatusView"
    }
    assert "pilot_preset" in schemas["EvaluationRequest"]["properties"]
    assert schemas["AgentOnboardingRequest"]["properties"]["integration_type"][
        "const"
    ] == "source"
    assert "build_manifest_path" in schemas["AgentOnboardingRequest"]["required"]
    assert "source_snapshot_sha256" in schemas["AuditRun"]["required"]
    assert schemas["AgentOnboardingRequest"]["properties"]["integration_type"][
        "const"
    ] == "source"
    assert "build_manifest_path" in schemas["AgentOnboardingRequest"]["required"]
    assert "source_snapshot_sha256" in schemas["AuditRun"]["required"]
    assert schemas["AgentOnboardingRequest"]["properties"]["integration_type"][
        "const"
    ] == "source"
    assert "build_manifest_path" in schemas["AgentOnboardingRequest"]["required"]
    assert "source_snapshot_sha256" in schemas["AuditRun"]["required"]
    assert schemas["AgentOnboardingRequest"]["properties"]["integration_type"][
        "const"
    ] == "source"
    assert "build_manifest_path" in schemas["AgentOnboardingRequest"]["required"]
    assert "source_snapshot_sha256" in schemas["AuditRun"]["required"]
    assert "dashboard_path" in schemas["ReportArtifacts"]["properties"]
    assert "audit_refs" in schemas["ReportArtifacts"]["properties"]
    assert "trust_level" in schemas["ProfileEvidenceItem"]["required"]
    assert schemas["ProfileEvidenceItem"]["properties"]["trust_level"]["enum"] == [
        "static",
        "attested",
        "observed",
    ]
