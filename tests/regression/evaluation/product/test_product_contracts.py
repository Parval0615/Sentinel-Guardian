from redsentinel.application.contracts import (
    AgentMaterial,
    AgentOnboardingRequest,
    AgentProfile,
    AgentProfileNode,
    AgentRegistration,
    AgentSecurityReport,
    BenchmarkCase,
    BenchmarkSummary,
    BenchmarkVersion,
    BenchmarkVersionDetail,
    BenchmarkVersionSummary,
    DashboardSummary,
    DashboardTrendPoint,
    EvaluationProgress,
    EvaluationRequest,
    EvaluationStatus,
    LogDetail,
    LogSummary,
    MetricSnapshot,
    ReportArtifacts,
)


def test_product_contracts_import_and_validate() -> None:
    registration = AgentRegistration(agent_id="agent_001", name="Demo Agent")
    request = EvaluationRequest(agent_id=registration.agent_id)
    status = EvaluationStatus(
        evaluation_id="eval_001",
        tenant_id=request.tenant_id,
        agent_id=request.agent_id,
        status="queued",
    )
    report = AgentSecurityReport(
        tenant_id=request.tenant_id,
        agent_id=request.agent_id,
        benchmark=request.benchmark,
        overall_score=100,
        risk_level="low",
        artifacts=ReportArtifacts(report_path="runs/product/report.json"),
    )

    assert registration.schema_version == "agent-registration-v0.1"
    assert request.benchmark == "ecommerce-security-v0.1"
    assert request.pilot_preset is None
    assert request.model_dump(mode="json")["defense_enabled"] is True
    assert request.defense_enabled is True
    assert EvaluationRequest(agent_id=registration.agent_id, defense_enabled=False).defense_enabled is False
    assert status.status == "queued"
    assert report.schema_version == "agent-security-report-v0.1"


def test_product_agent_benchmark_log_and_metric_contracts_validate() -> None:
    onboarding = AgentOnboardingRequest(
        tenant_id="tenant_001",
        agent_id="agent_source",
        name="Source Agent",
        integration_type="source",
        source_path="/workspace/agent",
        build_manifest_path="/workspace/agent/sandbox-build.json",
    )
    material = AgentMaterial(
        material_id="mat_001",
        tenant_id=onboarding.tenant_id,
        agent_id=onboarding.agent_id,
        type="source",
        source_path=onboarding.source_path,
        build_manifest_path=onboarding.build_manifest_path,
        source_sha256="a" * 64,
        build_manifest_sha256="b" * 64,
        source_snapshot_sha256="c" * 64,
        source_file_count=3,
        source_snapshot_verified=True,
    )
    profile = AgentProfile(
        profile_id="profile_001",
        tenant_id=onboarding.tenant_id,
        agent_id=onboarding.agent_id,
        nodes=[AgentProfileNode(node_id="tool_node", node_type="tool", critical=True)],
        risk_surface=["tool_tampering"],
    )
    case = BenchmarkCase(
        case_id="case_001",
        benchmark_id="bench_001",
        version="v1",
        case_type="attack",
        prompt="Attempt unauthorized tool use.",
        target_node="tool_node",
        expected_decision="block",
        severity="critical",
    )
    version = BenchmarkVersion(
        benchmark_id=case.benchmark_id,
        version=case.version,
        case_count=1,
        node_coverage={"tool_node": 1},
        cases=[case],
    )
    benchmark_summary = BenchmarkSummary(
        benchmark_id=case.benchmark_id,
        name="Tool Benchmark",
        active_version=case.version,
        version_count=1,
        case_count=1,
        attack_case_count=1,
        clean_case_count=0,
    )
    version_summary = BenchmarkVersionSummary(
        benchmark_id=case.benchmark_id,
        version=case.version,
        case_count=1,
        attack_case_count=1,
        clean_case_count=0,
        node_count=1,
    )
    version_detail = BenchmarkVersionDetail(
        benchmark_id=case.benchmark_id,
        version=case.version,
        case_count=1,
        attack_case_count=1,
        clean_case_count=0,
        node_coverage={"tool_node": 1},
        cases=[case],
    )
    snapshot = MetricSnapshot(
        snapshot_id="snap_001",
        tenant_id=onboarding.tenant_id,
        agent_id=onboarding.agent_id,
        latest_report_id="eval_001",
        score=92,
        risk_level="low",
    )
    summary = LogSummary(
        evaluation_id="eval_001",
        tenant_id=onboarding.tenant_id,
        agent_id=onboarding.agent_id,
        score=92,
        risk_level="low",
        status="completed",
    )
    dashboard = DashboardSummary(
        tenant_id=onboarding.tenant_id,
        agent_id=onboarding.agent_id,
        has_data=True,
        current_security_score=92,
        current_risk_level="low",
        recent_asr=0.1,
        recent_fpr=0.0,
        latest_source="metric_snapshot",
        trend=[
            DashboardTrendPoint(
                label="Round 1",
                round=1,
                source="metric_snapshot",
                snapshot_id=snapshot.snapshot_id,
                score=92,
                risk_level="low",
                asr=0.1,
                fpr=0.0,
            )
        ],
    )
    detail = LogDetail(summary=summary, total_case_count=1, target_nodes=["tool_node"])

    assert "api_key" not in onboarding.model_dump(mode="json")
    assert material.source_snapshot_verified is True
    assert material.source_snapshot_sha256 == "c" * 64
    assert profile.nodes[0].critical is True
    assert version.cases[0].case_type == "attack"
    assert benchmark_summary.case_count == 1
    assert version_summary.node_count == 1
    assert version_detail.cases[0].prompt == "Attempt unauthorized tool use."
    assert snapshot.schema_version == "metric-snapshot-v0.1"
    assert dashboard.trend[0].source == "metric_snapshot"
    assert detail.summary.status == "completed"
    assert EvaluationProgress(total_cases=4, completed_cases=2, percent=50.0).percent == 50.0
