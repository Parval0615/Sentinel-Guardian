from pathlib import Path

import pytest
from pydantic import ValidationError

from redsentinel.application.contracts import (
    AgentOnboardingRequest,
    AgentProfile,
    AgentProfileNode,
    AgentRegistration,
    EvaluationRequest,
)
from redsentinel.application.engine.service import ProductEvaluationService


def _source_request(tmp_path: Path, agent_id: str = "source_agent") -> AgentOnboardingRequest:
    source_root = tmp_path / "source-inputs" / agent_id
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "agent.py").write_text("def run(task):\n    return task\n", encoding="utf-8")
    manifest = source_root / "sandbox-build.json"
    manifest.write_text(
        '{"schema_version":"agent-sandbox-build-v0.1","adapter_type":"external_sdk"}',
        encoding="utf-8",
    )
    return AgentOnboardingRequest(
        agent_id=agent_id,
        name="Source Agent",
        integration_type="source",
        source_path=str(source_root),
        build_manifest_path=str(manifest),
    )


def _source_request(tmp_path: Path, agent_id: str = "source_agent") -> AgentOnboardingRequest:
    source_root = tmp_path / "source-inputs" / agent_id
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "agent.py").write_text("def run(task):\n    return task\n", encoding="utf-8")
    manifest = source_root / "sandbox-build.json"
    manifest.write_text(
        '{"schema_version":"agent-sandbox-build-v0.1","adapter_type":"external_sdk"}',
        encoding="utf-8",
    )
    return AgentOnboardingRequest(
        agent_id=agent_id,
        name="Source Agent",
        integration_type="source",
        source_path=str(source_root),
        build_manifest_path=str(manifest),
    )


def _source_request(tmp_path: Path, agent_id: str = "source_agent") -> AgentOnboardingRequest:
    source_root = tmp_path / "source-inputs" / agent_id
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "agent.py").write_text("def run(task):\n    return task\n", encoding="utf-8")
    manifest = source_root / "sandbox-build.json"
    manifest.write_text(
        '{"schema_version":"agent-sandbox-build-v0.1","adapter_type":"external_sdk"}',
        encoding="utf-8",
    )
    return AgentOnboardingRequest(
        agent_id=agent_id,
        name="Source Agent",
        integration_type="source",
        source_path=str(source_root),
        build_manifest_path=str(manifest),
    )


def _source_request(tmp_path: Path, agent_id: str = "source_agent") -> AgentOnboardingRequest:
    source_root = tmp_path / "source-inputs" / agent_id
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "agent.py").write_text("def run(task):\n    return task\n", encoding="utf-8")
    manifest = source_root / "sandbox-build.json"
    manifest.write_text(
        '{"schema_version":"agent-sandbox-build-v0.1","adapter_type":"external_sdk"}',
        encoding="utf-8",
    )
    return AgentOnboardingRequest(
        agent_id=agent_id,
        name="Source Agent",
        integration_type="source",
        source_path=str(source_root),
        build_manifest_path=str(manifest),
    )


def test_product_service_registers_runs_and_reports(tmp_path: Path) -> None:
    service = ProductEvaluationService(storage_root=tmp_path)
    registration = service.register_agent(
        AgentRegistration(agent_id="ecommerce_customer_guide", name="E-commerce Guide")
    )
    session = service.create_session(registration.tenant_id, registration.agent_id)
    status = service.run_evaluation(
        EvaluationRequest(tenant_id=registration.tenant_id, agent_id=registration.agent_id)
    )
    loaded_status = service.get_evaluation(status.evaluation_id)
    report = service.get_report(status.report_id or status.evaluation_id)

    assert session["agent_id"] == registration.agent_id
    assert loaded_status.status == "completed"
    assert status.report_path
    assert report.schema_version == "agent-security-report-v0.1"
    assert report.scenario_results
    assert Path(report.artifacts.report_path).exists()
    assert Path(report.artifacts.markdown_path or "").exists()
    assert report.artifacts.audit_refs
    assert Path(report.artifacts.audit_refs[0]).exists()
    assert service.storage.metric_snapshot_path(
        registration.tenant_id,
        f"snapshot-{status.evaluation_id}",
    ).exists()


def test_product_service_uploads_offline_trace(tmp_path: Path) -> None:
    service = ProductEvaluationService(storage_root=tmp_path)
    registration = service.register_agent(AgentRegistration(agent_id="agent_trace", name="Trace Agent"))
    uploaded = service.upload_trajectory(
        registration.tenant_id,
        registration.agent_id,
        {"turns": [{"message": "hello"}]},
    )

    assert uploaded["trajectory_id"].startswith("trace_")
    assert Path(uploaded["path"]).exists()


def test_product_service_does_not_count_masked_support_input_as_pii_leak(tmp_path: Path) -> None:
    service = ProductEvaluationService(storage_root=tmp_path)
    registration = service.register_agent(
        AgentRegistration(agent_id="ecommerce_customer_guide", name="E-commerce Guide")
    )
    status = service.run_evaluation(
        EvaluationRequest(
            tenant_id=registration.tenant_id,
            agent_id=registration.agent_id,
            scenarios=["support-pii-masking"],
        )
    )
    report = service.get_report(status.report_id or status.evaluation_id)

    assert status.status == "completed"
    assert report.scenario_results[0].passed is True
    assert not report.findings


def test_onboarding_contract_rejects_hosted_api_material() -> None:
    with pytest.raises(ValidationError, match="source"):
        AgentOnboardingRequest(
            agent_id="hosted_agent",
            name="Hosted Agent",
            integration_type="api",
            endpoint_url="https://example.test/v1/chat/completions",
            api_key="sk-live-secret",
        )


def test_source_onboarding_records_verified_snapshot(tmp_path: Path) -> None:
    service = ProductEvaluationService(storage_root=tmp_path)
    response = service.onboard_agent(_source_request(tmp_path))

    assert response.ready is True
    assert response.material.source_snapshot_verified is True
    assert response.material.source_snapshot_sha256
    assert [stage.name for stage in response.stages] == [
        "agent_record",
        "source_snapshot",
        "profile_analysis",
        "sandbox_build_plan",
    ]


def test_source_onboarding_rejects_manifest_outside_source(tmp_path: Path) -> None:
    service = ProductEvaluationService(storage_root=tmp_path)
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "agent.py").write_text("pass\n", encoding="utf-8")
    manifest = tmp_path / "sandbox-build.json"
    manifest.write_text(
        '{"schema_version":"agent-sandbox-build-v0.1","adapter_type":"external_sdk"}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="inside source_path"):
        service.onboard_agent(
        AgentOnboardingRequest(
            agent_id="source_agent",
            name="Source Agent",
            integration_type="source",
                source_path=str(source_root),
                build_manifest_path=str(manifest),
            )
        )


def test_dashboard_summary_can_use_metric_snapshot_without_report(tmp_path: Path) -> None:
    service = ProductEvaluationService(storage_root=tmp_path)
    registration = service.register_agent(AgentRegistration(agent_id="snapshot_agent", name="Snapshot Agent"))
    service.storage.write_metric_snapshot(
        registration.tenant_id,
        registration.agent_id,
        "snap_001",
        {
            "snapshot_id": "snap_001",
            "agent_id": registration.agent_id,
            "score": 81,
            "risk_level": "medium",
            "asr": 0.25,
            "fpr": 0.1,
            "benchmark_id": "bench_001",
            "benchmark_version": "v1",
        },
    )

    summary = service.get_dashboard_summary(registration.agent_id)

    assert summary.has_data is True
    assert summary.latest_source == "metric_snapshot"
    assert summary.current_security_score == 81
    assert summary.current_risk_level == "medium"
    assert summary.recent_asr == 0.25
    assert summary.recent_fpr == 0.1
    assert summary.trend[0].snapshot_id == "snap_001"


def test_incomplete_report_does_not_refresh_dashboard_summary(tmp_path: Path) -> None:
    service = ProductEvaluationService(storage_root=tmp_path)
    registration = service.register_agent(AgentRegistration(agent_id="integrity_agent", name="Integrity Agent"))
    complete = service.run_evaluation(
        EvaluationRequest(agent_id=registration.agent_id, scenarios=["support-pii-masking"])
    )
    complete_report = service.get_report(complete.report_id or complete.evaluation_id)

    service.storage.write_profile(
        registration.tenant_id,
        registration.agent_id,
        f"profile-{registration.agent_id}",
        AgentProfile(
            profile_id=f"profile-{registration.agent_id}",
            tenant_id=registration.tenant_id,
            agent_id=registration.agent_id,
            nodes=[AgentProfileNode(node_id="uncovered_required_node", node_type="external_api", required=True)],
        ).model_dump(mode="json"),
    )
    incomplete = service.run_evaluation(
        EvaluationRequest(agent_id=registration.agent_id, scenarios=["support-pii-masking"])
    )
    incomplete_report = service.get_report(incomplete.report_id or incomplete.evaluation_id)

    summary = service.get_dashboard_summary(registration.agent_id)

    assert complete_report.status == "complete"
    assert incomplete_report.status == "incomplete"
    assert incomplete_report.summary["integrity_issues"]
    assert summary.latest_report_id == complete.report_id
    assert summary.current_security_score == complete_report.overall_score
    assert len(summary.trend) == 1
    assert not service.storage.metric_snapshot_path(
        registration.tenant_id,
        f"snapshot-{incomplete.evaluation_id}",
    ).exists()


def test_product_service_rejects_unsafe_artifact_ids(tmp_path: Path) -> None:
    service = ProductEvaluationService(storage_root=tmp_path)

    with pytest.raises(ValueError, match="Unsafe tenant_id"):
        service.register_agent(AgentRegistration(tenant_id="../tenant", agent_id="agent", name="Unsafe"))

    with pytest.raises(ValueError, match="Unsafe report_id"):
        service.get_report("../eval")
