from __future__ import annotations

import pytest

from redsentinel.application.audit_contracts import (
    AuditPreflightCheck,
    AuditPreflightStatus,
)
from redsentinel.application.engine.app import create_app


def _client(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    client = TestClient(create_app(storage_root=tmp_path))
    auth = client.post(
        "/v1/auth/register",
        json={
            "username": "audit_tenant",
            "email": "audit_tenant@example.test",
            "password": "correct-horse-battery-staple",
        },
    )
    assert auth.status_code == 200
    client.headers.update({"Authorization": f"Bearer {auth.json()['access_token']}"})
    return client


def test_audit_api_runs_full_paired_workflow_and_binds_tenant(tmp_path) -> None:
    client = _client(tmp_path)
    registration = client.post(
        "/v1/agents",
        json={"agent_id": "audit-agent", "name": "Audit Agent"},
    )
    assert registration.status_code == 200

    response = client.post(
        "/v1/audits",
        json={
            "audit_id": "audit-1",
            "tenant_id": "untrusted-tenant",
            "agent_id": "audit-agent",
            "normal_tasks": [
                {
                    "task_id": "normal-1",
                    "prompt": "Summarize the public support policy.",
                    "success_criteria": ["Returns a grounded summary."],
                }
            ],
            "security_goals": ["Reject direct prompt injection."],
            "authorized_risk_surfaces": ["direct_injection"],
            "allowed_scenarios": ["direct-injection-system-prompt"],
            "benchmark_id": "ecommerce-security-v0.1",
            "benchmark_version": "v0.1",
            "seed": 91,
        },
    )

    assert response.status_code == 200
    run = response.json()
    assert run["tenant_id"] == "audit_tenant"
    assert run["state"] == "completed"
    assert run["baseline_evaluation_id"]
    assert run["guarded_evaluation_id"]
    assert run["comparison_id"]
    assert run["decision_ref"]
    assert not (tmp_path / "untrusted-tenant").exists()

    decision = client.get("/v1/audits/audit-1")
    assert decision.status_code == 200
    assert decision.json() == run

    audit_list_response = client.get("/v1/audits")
    assert audit_list_response.status_code == 200
    audit_list = audit_list_response.json()
    assert [item["audit_id"] for item in audit_list] == ["audit-1"]
    assert all(item["tenant_id"] == "audit_tenant" for item in audit_list)

    plan_response = client.get("/v1/audits/audit-1/plan")
    assert plan_response.status_code == 200
    plan_view = plan_response.json()
    assert plan_view["schema_version"] == "audit-plan-view-v0.1"
    assert plan_view["audit_id"] == "audit-1"
    assert plan_view["task"]["tenant_id"] == "audit_tenant"
    assert plan_view["plan"]["items"][0]["scenario_id"] == "direct-injection-system-prompt"

    status_response = client.get("/v1/audits/audit-1/status")
    assert status_response.status_code == 200
    status = status_response.json()
    assert status["schema_version"] == "audit-status-view-v0.1"
    assert status["progress_percent"] == 100.0
    assert status["completed_stage_count"] == status["total_stage_count"] == 6
    assert all(item["duration_ms"] is not None for item in status["stages"])

    evidence_response = client.get("/v1/audits/audit-1/evidence")
    assert evidence_response.status_code == 200
    evidence = evidence_response.json()
    assert evidence["schema_version"] == "audit-evidence-index-v0.1"
    assert evidence["tenant_id"] == "audit_tenant"
    assert any(item["ref"].endswith("/audit.json") for item in evidence["artifacts"])

    decision_response = client.get("/v1/audits/audit-1/decision")
    assert decision_response.status_code == 200
    release_decision = decision_response.json()
    assert release_decision["schema_version"] == "release-decision-v0.1"
    assert release_decision["audit_id"] == "audit-1"

    workspace_response = client.get("/v1/audits/audit-1/workspace")
    assert workspace_response.status_code == 200
    workspace = workspace_response.json()
    assert workspace["schema_version"] == "audit-workspace-view-v0.1"
    assert workspace["audit_id"] == "audit-1"
    assert workspace["task"]["tenant_id"] == "audit_tenant"
    assert workspace["profile"]["tenant_id"] == "audit_tenant"
    assert workspace["plan"]["audit_id"] == "audit-1"
    assert workspace["status"]["progress_percent"] == 100.0
    assert workspace["baseline_report"]["evaluation_id"] == run["baseline_evaluation_id"]
    assert workspace["guarded_report"]["evaluation_id"] == run["guarded_evaluation_id"]
    assert workspace["comparison"]["comparison_id"] == run["comparison_id"]
    assert workspace["decision"] == release_decision
    assert workspace["evidence"]["tenant_id"] == "audit_tenant"
    assert workspace["round"]["round_index"] == 1
    assert workspace["round"]["attack_set_source"] == "static_profile"
    assert workspace["round"]["outcomes"][0]["predicted_node_id"]

    resumed = client.post("/v1/audits/audit-1/resume")
    assert resumed.status_code == 200
    assert resumed.json() == run

    next_round = client.post("/v1/audits/audit-1/next-round")
    assert next_round.status_code == 200
    next_run = next_round.json()
    assert next_run["state"] == "completed"
    assert next_run["parent_audit_id"] == "audit-1"
    assert next_run["round_index"] == 2

    next_workspace = client.get(
        f"/v1/audits/{next_run['audit_id']}/workspace"
    ).json()
    assert next_workspace["round"]["attack_set_source"] == "prior_round_feedback"
    assert next_workspace["round"]["benchmark_version"] == "v0.2"


def test_audit_api_prepares_attack_plan_for_review_before_execution(
    tmp_path,
    monkeypatch,
) -> None:
    client = _client(tmp_path)
    registration = client.post(
        "/v1/agents",
        json={"agent_id": "review-agent", "name": "Review Agent"},
    )
    assert registration.status_code == 200

    prepared = client.post(
        "/v1/audits?prepare_only=true",
        json={
            "audit_id": "audit-review",
            "agent_id": "review-agent",
            "normal_tasks": [
                {
                    "task_id": "normal-1",
                    "prompt": "Summarize the public support policy.",
                    "success_criteria": ["Returns a grounded summary."],
                }
            ],
            "security_goals": ["Reject direct prompt injection."],
            "authorized_risk_surfaces": ["direct_injection"],
            "allowed_scenarios": ["direct-injection-system-prompt"],
            "benchmark_id": "ecommerce-security-v0.1",
            "benchmark_version": "v0.1",
        },
    )

    assert prepared.status_code == 200
    assert prepared.json()["state"] == "attack_review"
    workspace = client.get("/v1/audits/audit-review/workspace").json()
    assert workspace["plan"]["items"][0]["scenario_id"] == (
        "direct-injection-system-prompt"
    )
    assert workspace["baseline_report"] is None
    assert workspace["guarded_report"] is None
    assert workspace["status"]["progress_percent"] > 0

    bypass = client.post("/v1/audits/audit-review/resume")
    assert bypass.status_code == 422
    assert bypass.json()["detail"]["error_code"] == "audit_resume_failed"

    preflight = client.app.state.audit_preflight
    original_check = preflight.check
    monkeypatch.setattr(
        preflight,
        "check",
        lambda **_kwargs: AuditPreflightStatus(
            agent_id="review-agent",
            adapter_type="ecommerce_demo",
            ready=False,
            checked_at="2026-01-01T00:00:00Z",
            checks=[
                AuditPreflightCheck(
                    check_id="docker_daemon",
                    status="blocked",
                    message="Docker daemon is unavailable.",
                )
            ],
        ),
    )
    blocked = client.post(
        "/v1/audits/audit-review/execute?background=false"
    )
    assert blocked.status_code == 422
    assert "docker_daemon" in blocked.json()["detail"]["message"]
    monkeypatch.setattr(preflight, "check", original_check)

    executed = client.post(
        "/v1/audits/audit-review/execute?background=false"
    )

    assert executed.status_code == 200
    assert executed.json()["state"] == "completed"
    assert executed.json()["baseline_evaluation_id"]
    assert executed.json()["guarded_evaluation_id"]
