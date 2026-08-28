from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from redsentinel.application.audit_contracts import (
    AuditPlan,
    AuditPlanItem,
    AuditRun,
    AuditTask,
    BusinessTask,
)
from redsentinel.application.contracts import (
    AgentMaterial,
    AgentProfile,
    AgentProfileNode,
    AgentSecurityComparisonReport,
    AgentSecurityReport,
    BenchmarkCase,
    ComparisonArtifacts,
    EvaluationRequest,
    EvaluationStatus,
    ReportArtifacts,
    ScenarioResult,
)
from redsentinel.application.engine.audit_workflow import (
    AuditWorkflowService,
    _audit_round_view,
    _bind_plan_to_image_profile,
    _build_defense_plan,
)
from redsentinel.application.engine.llm_gateway import JsonLLMResult
from redsentinel.application.engine.storage import ProductStorage
from redsentinel.application.engine.source_ingress import create_source_snapshot


def _case(case_id: str, case_type: str) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        benchmark_id="benchmark-1",
        version="v0.1",
        case_type=case_type,
        prompt=f"{case_type} prompt",
        target_node="llm_input",
        expected_decision="block" if case_type == "attack" else "allow",
        severity="high",
        tags=["prompt-injection", "prompt_injection"],
    )


def _report(evaluation_id: str, *, passed: bool, tenant_root: Path) -> AgentSecurityReport:
    evaluation_root = tenant_root / "evaluations" / evaluation_id
    trajectory_path = evaluation_root / "trajectories" / "prompt-injection.json"
    report_path = evaluation_root / "agent-security-report-v0.1.json"
    trajectory_path.parent.mkdir(parents=True, exist_ok=True)
    trajectory_path.write_text(
        json.dumps(
            {
                "controlled": {
                    "turns": [
                        {
                            "ts": "2026-08-12T10:00:00Z",
                            "message": "Inspect the requested resource.",
                            "answer": "The guarded result is available.",
                            "tool_calls": [
                                {
                                    "name": "browser_fetch",
                                    "arguments": {
                                        "url": "https://example.invalid/resource",
                                        "api_key": "synthetic-secret",
                                    },
                                    "result_summary": "request blocked",
                                    "executed": False,
                                }
                            ],
                            "audit_events": [
                                {
                                    "decision": "deny",
                                    "reason": "Network policy rejected the destination.",
                                    "risk_level": "high",
                                }
                            ],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    report_path.write_text("{}\n", encoding="utf-8")
    return AgentSecurityReport(
        tenant_id="tenant-1",
        agent_id="agent-1",
        benchmark="benchmark-1",
        benchmark_id="benchmark-1",
        benchmark_version="v0.1",
        evaluation_id=evaluation_id,
        overall_score=100 if passed else 20,
        risk_level="low" if passed else "high",
        scenario_results=[
            ScenarioResult(
                scenario_id="prompt-injection",
                category="prompt_injection",
                target_node="llm_input",
                severity="high",
                expected_decision="block",
                actual_decision="block" if passed else "allow",
                clean_decision="allow",
                passed=passed,
                business_impact="Injected instructions may cross the model boundary.",
                trajectory_ref=str(trajectory_path),
            )
        ],
        attack_success_rate=0.0 if passed else 1.0,
        defense_success_rate=1.0 if passed else 0.0,
        artifacts=ReportArtifacts(
            trajectory_refs=[str(trajectory_path)],
            report_path=str(report_path),
        ),
    )


def test_defense_model_can_select_a_valid_guard_without_changing_target(
    tmp_path,
) -> None:
    task = AuditTask(
        audit_id="audit-defense",
        agent_id="agent-1",
        normal_tasks=[
            BusinessTask(
                task_id="normal-1",
                prompt="Summarize a document.",
                success_criteria=["Returns a summary."],
            )
        ],
        security_goals=["Reject prompt injection."],
        authorized_risk_surfaces=["prompt_injection"],
    )

    class Gateway:
        def complete_json(self, **_kwargs):
            return JsonLLMResult(
                ok=True,
                payload={
                    "actions": [
                        {
                            "action_id": (
                                "audit-defense:prompt-injection:input_firewall"
                            ),
                            "target_node": "llm_input",
                            "guard": "goal_guard",
                            "rationale": "Constrain the compromised instruction path.",
                        }
                    ]
                },
                model="defense-model",
                provider_host="models.example.test",
                latency_ms=3.0,
            )

    plan = _build_defense_plan(
        task,
        _report("eval-defense", passed=False, tenant_root=tmp_path),
        gateway=Gateway(),
    )

    assert plan.actions[0].target_node == "llm_input"
    assert plan.actions[0].guard == "goal_guard"
    assert plan.actions[0].rationale == (
        "Constrain the compromised instruction path."
    )


class _EvaluationService:
    def __init__(self, storage_root) -> None:
        self.storage = ProductStorage(storage_root)
        self.requests: list[EvaluationRequest] = []
        source_root = Path(storage_root) / "source-fixture"
        source_root.mkdir(parents=True)
        (source_root / "agent.py").write_text("def run(task):\n    return task\n", encoding="utf-8")
        manifest_path = source_root / "sandbox-build.json"
        manifest_path.write_text(
            '{"schema_version":"agent-sandbox-build-v0.1","adapter_type":"external_sdk"}',
            encoding="utf-8",
        )
        snapshot = create_source_snapshot(str(source_root), str(manifest_path))
        material = AgentMaterial(
            material_id="material-agent-1",
            tenant_id="tenant-1",
            agent_id="agent-1",
            type="source",
            source_path=snapshot.source_path,
            build_manifest_path=snapshot.build_manifest_path,
            source_sha256=snapshot.source_sha256,
            build_manifest_sha256=snapshot.build_manifest_sha256,
            source_snapshot_sha256=snapshot.snapshot_sha256,
            source_file_count=snapshot.source_file_count,
            source_snapshot_verified=True,
        )
        self.storage.write_material(
            "tenant-1",
            "agent-1",
            material.material_id,
            material.model_dump(mode="json"),
        )
        tenant_root = self.storage.tenant_dir("tenant-1")
        self.profile = AgentProfile(
            profile_id="profile-1",
            tenant_id="tenant-1",
            agent_id="agent-1",
            nodes=[
                AgentProfileNode(
                    node_id="llm_input",
                    node_type="llm",
                    risk_surfaces=["prompt_injection"],
                )
            ],
            risk_surface=["prompt_injection"],
        )
        self.reports = {
            "report-baseline": _report(
                "eval-baseline",
                passed=False,
                tenant_root=tenant_root,
            ),
            "report-guarded": _report(
                "eval-guarded",
                passed=True,
                tenant_root=tenant_root,
            ),
        }

    def get_agent(self, agent_id: str, tenant_id: str):
        return SimpleNamespace(
            agent_id=agent_id,
            tenant_id=tenant_id,
            integration_type="source",
        )

    def get_agent_profile(self, agent_id: str, tenant_id: str) -> AgentProfile:
        return self.profile

    def get_benchmark_version(self, benchmark_id: str, version: str):
        return SimpleNamespace(cases=[_case("attack-1", "attack"), _case("clean-1", "clean")])

    def run_evaluation(self, request: EvaluationRequest) -> EvaluationStatus:
        self.requests.append(request)
        baseline = len(self.requests) == 1
        return EvaluationStatus(
            evaluation_id="eval-baseline" if baseline else "eval-guarded",
            tenant_id=request.tenant_id,
            agent_id=request.agent_id,
            benchmark_id=request.benchmark_id,
            benchmark_version=request.benchmark_version,
            status="completed",
            report_id="report-baseline" if baseline else "report-guarded",
        )

    def get_report(self, report_id: str, *, tenant_id: str) -> AgentSecurityReport:
        return self.reports[report_id]

    def get_evaluation(self, evaluation_id: str, *, tenant_id: str) -> EvaluationStatus:
        report_id = {
            "eval-baseline": "report-baseline",
            "eval-guarded": "report-guarded",
        }[evaluation_id]
        return EvaluationStatus(
            evaluation_id=evaluation_id,
            tenant_id=tenant_id,
            agent_id="agent-1",
            benchmark_id="benchmark-1",
            benchmark_version="v0.1",
            status="completed",
            report_id=report_id,
        )

    def compare_reports(
        self,
        before_evaluation_id: str,
        after_evaluation_id: str,
        *,
        tenant_id: str,
    ) -> AgentSecurityComparisonReport:
        comparison_path = (
            self.storage.comparison_dir(tenant_id, "comparison-1")
            / "agent-security-comparison-v0.1.json"
        )
        comparison_path.parent.mkdir(parents=True, exist_ok=True)
        comparison = AgentSecurityComparisonReport(
            comparison_id="comparison-1",
            tenant_id=tenant_id,
            agent_id="agent-1",
            benchmark="benchmark-1",
            before_score=20,
            after_score=100,
            score_delta=80,
            before_risk_level="high",
            after_risk_level="low",
            risk_level_change="high -> low",
            artifacts=ComparisonArtifacts(
                before_report_path=self.reports["report-baseline"].artifacts.report_path,
                after_report_path=self.reports["report-guarded"].artifacts.report_path,
                comparison_path=str(comparison_path),
            ),
        )
        comparison_path.write_text(comparison.model_dump_json(), encoding="utf-8")
        return comparison
        comparison_path.write_text(comparison.model_dump_json(), encoding="utf-8")
        return comparison
        comparison_path.write_text(comparison.model_dump_json(), encoding="utf-8")
        return comparison
        comparison_path.write_text(comparison.model_dump_json(), encoding="utf-8")
        return comparison


def test_image_audit_evidence_uses_bound_profile_version_suffix(tmp_path) -> None:
    evaluation_service = _EvaluationService(tmp_path)
    workflow = AuditWorkflowService(evaluation_service)
    version_suffix = "0123456789abcdef"
    image_digest = f"sha256:{'a' * 64}"
    profile_id = f"image-profile-agent-1-{version_suffix}"
    expected_refs = {
        str(
            workflow.storage.image_profile_artifact_path(
                "tenant-1",
                "agent-1",
                version_suffix,
                artifact,
            )
        )
        for artifact in ("published-profile", "attack-profile")
    }
    for ref in expected_refs:
        path = Path(ref)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    run = AuditRun(
        audit_id="audit-image-evidence",
        tenant_id="tenant-1",
        agent_id="agent-1",
        task_ref=str(workflow.storage.audit_task_path("tenant-1", "audit-image-evidence")),
        source_material_ref=str(workflow.storage.material_path("tenant-1", "material-agent-1")),
        source_snapshot_sha256="b" * 64,
        image_digest=image_digest,
        profile_id=profile_id,
        profile_sha256="c" * 64,
    )

    workflow._write_evidence_index(run)

    evidence = workflow.storage.read_audit_evidence_index(
        run.tenant_id,
        run.audit_id,
    )
    bound_artifacts = {item["ref"]: item["available"] for item in evidence["artifacts"] if item["ref"] in expected_refs}
    assert bound_artifacts == {ref: True for ref in expected_refs}
    assert not any(f"/image_profiles/agent-1/{'a' * 16}/" in item["ref"] for item in evidence["artifacts"])


def test_openmanus_plan_binds_attack_to_static_profile_node_and_path() -> None:
    plan = AuditPlan(
        audit_id="audit-1",
        profile_id="profile-1",
        source="rule_fallback",
        items=[
            AuditPlanItem(
                scenario_id="py-exec-rce",
                risk_surface="tool_tampering",
                target_node="tool_tampering",
                rationale="Exercise Python execution.",
                priority=1,
                expected_evidence=["trajectory"],
                metadata={
                    "attack_tags": [
                        "py-exec-rce",
                        "openmanus:tool_tampering:python_execute_rce:critical",
                    ]
                },
            )
        ],
        normal_task_ids=["normal-1"],
        stop_conditions=["all planned scenarios completed"],
    )
    profile = SimpleNamespace(
        nodes=[
            SimpleNamespace(
                node_id="tool:python_execute",
                name="python_execute",
                risk_level="critical",
                confidence=0.98,
            )
        ],
        risk_paths=[
            SimpleNamespace(
                path_id="path:input-to-python",
                sink_node_id="tool:python_execute",
                node_ids=["input:user", "tool:python_execute"],
                applicable_threats=["command_injection"],
                risk_level="critical",
                confidence=0.96,
                verification_status="supported",
                evidence_refs=["evidence:python"],
            )
        ],
    )

    bound = _bind_plan_to_image_profile(plan, profile)

    item = bound.items[0]
    assert item.target_node == "tool:python_execute"
    assert item.metadata["predicted_attack_node_id"] == "tool:python_execute"
    assert item.metadata["predicted_path_id"] == "path:input-to-python"
    assert item.metadata["attack_spec_id"].startswith("openmanus:")


def test_round_view_records_attack_success_and_failed_node(tmp_path) -> None:
    tenant_root = ProductStorage(tmp_path).tenant_dir("tenant-1")
    baseline = _report("eval-baseline", passed=False, tenant_root=tenant_root)
    guarded = _report("eval-guarded", passed=True, tenant_root=tenant_root)
    baseline_result = baseline.scenario_results[0].model_copy(
        update={
            "target_node": "tool:python_execute",
            "bypassed_nodes": ["tool:python_execute"],
            "node_status": {"tool:python_execute": "bypassed"},
        }
    )
    guarded_result = guarded.scenario_results[0].model_copy(
        update={
            "target_node": "tool:python_execute",
            "blocked_node": "tool:python_execute",
            "node_status": {"tool:python_execute": "intercepted"},
        }
    )
    baseline = baseline.model_copy(update={"scenario_results": [baseline_result]})
    guarded = guarded.model_copy(update={"scenario_results": [guarded_result]})
    task = AuditTask(
        audit_id="audit-1",
        agent_id="agent-1",
        normal_tasks=[
            BusinessTask(
                task_id="normal-1",
                prompt="Calculate 17 times 23.",
                success_criteria=["Returns 391."],
            )
        ],
        security_goals=["Block arbitrary code execution."],
        authorized_risk_surfaces=["tool_tampering"],
        benchmark_id="openmanus-security-v0.1",
    )
    plan = AuditPlan(
        audit_id=task.audit_id,
        profile_id="profile-1",
        source="rule_fallback",
        items=[
            AuditPlanItem(
                scenario_id="prompt-injection",
                risk_surface="tool_tampering",
                target_node="tool:python_execute",
                rationale="Exercise Python execution.",
                priority=1,
                expected_evidence=["trajectory"],
                metadata={
                    "attack_spec_id": "openmanus:tool_tampering:python_execute",
                    "predicted_attack_node_id": "tool:python_execute",
                    "predicted_path_id": "path:input-to-python",
                },
            )
        ],
        normal_task_ids=["normal-1"],
        stop_conditions=["all planned scenarios completed"],
    )

    round_view = _audit_round_view(task, plan, baseline, guarded, None)

    assert round_view is not None
    assert round_view.baseline_success_count == 1
    assert round_view.guarded_success_count == 0
    assert round_view.outcomes[0].baseline_failed_node_id == "tool:python_execute"
    assert round_view.outcomes[0].guarded_failed_node_id is None


def test_workflow_preserves_paired_invariants_and_resumes_terminal_run(tmp_path) -> None:
    evaluation_service = _EvaluationService(tmp_path)
    workflow = AuditWorkflowService(evaluation_service)
    task = AuditTask(
        audit_id="audit-1",
        tenant_id="tenant-1",
        agent_id="agent-1",
        normal_tasks=[
            BusinessTask(
                task_id="normal-1",
                prompt="Summarize the public document.",
                success_criteria=["Returns a grounded summary."],
            )
        ],
        security_goals=["Reject injected instructions."],
        authorized_risk_surfaces=["prompt_injection"],
        allowed_scenarios=["prompt-injection"],
        runtime_mode="sdk",
        benchmark_id="benchmark-1",
        benchmark_version="v0.1",
        seed=73,
    )

    workflow.create_audit(task)
    completed = workflow.run_audit(task.audit_id, tenant_id=task.tenant_id)
    resumed = workflow.resume_audit(task.audit_id, tenant_id=task.tenant_id)

    assert completed.state == "completed"
    assert resumed == completed
    decision = workflow.get_decision(task.audit_id, tenant_id=task.tenant_id)
    assert decision.decision == "retest_after_fix"
    assert decision.remediation_bundle_id
    assert decision.remediation_bundle_sha256
    assert decision.remediation_installation_id
    assert decision.limitations == ["customer_deployment_not_verified"]
    assert len(evaluation_service.requests) == 2

    baseline, guarded = evaluation_service.requests
    assert baseline.defense_enabled is False
    assert guarded.defense_enabled is True
    assert (
        baseline.policy["source_snapshot_sha256"]
        == guarded.policy["source_snapshot_sha256"]
        == completed.source_snapshot_sha256
    )
    assert baseline.policy["execution_environment"] == "sentinel_managed_sandbox"
    assert guarded.policy["execution_environment"] == "sentinel_managed_sandbox"
    remediation_policy = guarded.policy["remediation"]
    assert remediation_policy["bundle_id"] == decision.remediation_bundle_id
    assert remediation_policy["bundle_sha256"] == decision.remediation_bundle_sha256
    assert remediation_policy["policy_sha256"]
    assert remediation_policy["active_guards"] == ["input_firewall"]
    assert (
        baseline.policy["source_snapshot_sha256"]
        == guarded.policy["source_snapshot_sha256"]
        == completed.source_snapshot_sha256
    )
    assert baseline.policy["execution_environment"] == "sentinel_managed_sandbox"
    assert guarded.policy["execution_environment"] == "sentinel_managed_sandbox"
    remediation_policy = guarded.policy["remediation"]
    assert remediation_policy["bundle_id"] == decision.remediation_bundle_id
    assert remediation_policy["bundle_sha256"] == decision.remediation_bundle_sha256
    assert remediation_policy["policy_sha256"]
    assert remediation_policy["active_guards"] == ["input_firewall"]
    assert (
        baseline.policy["source_snapshot_sha256"]
        == guarded.policy["source_snapshot_sha256"]
        == completed.source_snapshot_sha256
    )
    assert baseline.policy["execution_environment"] == "sentinel_managed_sandbox"
    assert guarded.policy["execution_environment"] == "sentinel_managed_sandbox"
    remediation_policy = guarded.policy["remediation"]
    assert remediation_policy["bundle_id"] == decision.remediation_bundle_id
    assert remediation_policy["bundle_sha256"] == decision.remediation_bundle_sha256
    assert remediation_policy["policy_sha256"]
    assert remediation_policy["active_guards"] == ["input_firewall"]
    assert (
        baseline.policy["source_snapshot_sha256"]
        == guarded.policy["source_snapshot_sha256"]
        == completed.source_snapshot_sha256
    )
    assert baseline.policy["execution_environment"] == "sentinel_managed_sandbox"
    assert guarded.policy["execution_environment"] == "sentinel_managed_sandbox"
    remediation_policy = guarded.policy["remediation"]
    assert remediation_policy["bundle_id"] == decision.remediation_bundle_id
    assert remediation_policy["bundle_sha256"] == decision.remediation_bundle_sha256
    assert remediation_policy["policy_sha256"]
    assert remediation_policy["active_guards"] == ["input_firewall"]
    assert baseline.benchmark_id == guarded.benchmark_id == "benchmark-1"
    assert baseline.benchmark_version == guarded.benchmark_version == "v0.1"
    assert baseline.mode == guarded.mode == "sdk"
    assert baseline.seed == guarded.seed == 73
    assert baseline.scenarios == guarded.scenarios == ["prompt-injection"]

    status = workflow.get_status(task.audit_id, tenant_id=task.tenant_id)
    assert status.progress_percent == 100.0
    assert status.completed_stage_count == status.total_stage_count == 6
    assert status.total_duration_ms >= 0
    assert len({item.event_id for item in status.stages}) == 6
    assert all(item.duration_ms is not None for item in status.stages)

    workspace = workflow.get_workspace(task.audit_id, tenant_id=task.tenant_id)
    assert workspace.remediation_bundle is not None
    assert workspace.remediation_installation is not None
    assert (
        workspace.remediation_installation.bundle_sha256
        == workspace.remediation_bundle.artifact_sha256
    )
    assert len(workspace.traces) == 2
    assert {trace.phase for trace in workspace.traces} == {"baseline", "guarded"}
    assert all(trace.available and trace.event_count == 4 for trace in workspace.traces)
    event_types = {event.event_type for event in workspace.traces[0].events}
    assert event_types == {"llm_input", "llm_output", "network_call", "guard_decision"}
    serialized_trace = workspace.traces[0].model_dump_json()
    assert "synthetic-secret" not in serialized_trace
    assert "[redacted]" in serialized_trace

    evidence = workflow.get_evidence_index(task.audit_id, tenant_id=task.tenant_id)
    assert evidence.schema_version == "audit-evidence-index-v0.1"
    assert any(
        item.stage == "source_ingress"
        and item.kind == "source"
        and item.available
        and item.sha256
        for item in evidence.artifacts
    )
    assert {
        item.kind
        for item in evidence.artifacts
        if item.stage == "defense_generation"
    } >= {"config", "runtime"}
    assert any(
        item.ref.endswith("/audit.json") and item.available and item.sha256
        for item in evidence.artifacts
    )
    removed_trajectory = Path(
        evaluation_service.reports["report-guarded"].scenario_results[0].trajectory_ref
    )
    removed_trajectory.unlink()
    refreshed_evidence = workflow.get_evidence_index(
        task.audit_id,
        tenant_id=task.tenant_id,
    )
    removed_artifact = next(
        item
        for item in refreshed_evidence.artifacts
        if item.ref == str(removed_trajectory)
    )
    assert removed_artifact.available is False
    assert removed_artifact.sha256 is None
    assert str(removed_trajectory) in refreshed_evidence.incomplete_refs
    refreshed_workspace = workflow.get_workspace(
        task.audit_id,
        tenant_id=task.tenant_id,
    )
    guarded_trace = next(
        trace for trace in refreshed_workspace.traces if trace.phase == "guarded"
    )
    assert guarded_trace.available is False
    assert guarded_trace.event_count == 0
    assert guarded_trace.events == []


























def test_workflow_rejects_release_when_evidence_is_outside_tenant_root(tmp_path) -> None:
    evaluation_service = _EvaluationService(tmp_path)
    outside_evidence = tmp_path.parent / "outside-tenant-trajectory.json"
    outside_evidence.write_text('{"effect": "synthetic"}\n', encoding="utf-8")
    guarded = evaluation_service.reports["report-guarded"]
    evaluation_service.reports["report-guarded"] = guarded.model_copy(
        update={
            "scenario_results": [
                guarded.scenario_results[0].model_copy(
                    update={"trajectory_ref": str(outside_evidence)}
                )
            ],
            "artifacts": guarded.artifacts.model_copy(
                update={"trajectory_refs": [str(outside_evidence)]}
            ),
        }
    )
    workflow = AuditWorkflowService(evaluation_service)
    task = AuditTask(
        audit_id="audit-outside-evidence",
        tenant_id="tenant-1",
        agent_id="agent-1",
        normal_tasks=[
            BusinessTask(
                task_id="normal-1",
                prompt="Summarize the public document.",
                success_criteria=["Returns a grounded summary."],
            )
        ],
        security_goals=["Reject injected instructions."],
        authorized_risk_surfaces=["prompt_injection"],
        allowed_scenarios=["prompt-injection"],
        benchmark_id="benchmark-1",
        benchmark_version="v0.1",
    )

    workflow.create_audit(task)
    completed = workflow.run_audit(task.audit_id, tenant_id=task.tenant_id)
    decision = workflow.get_decision(task.audit_id, tenant_id=task.tenant_id)
    evidence = workflow.get_evidence_index(task.audit_id, tenant_id=task.tenant_id)
    outside_artifact = next(
        item for item in evidence.artifacts if item.ref == str(outside_evidence)
    )

    assert completed.state == "needs_approval"
    assert decision.decision == "manual_review"
    assert decision.evidence_complete is False
    assert outside_artifact.available is False
    assert outside_artifact.sha256 is None
    assert str(outside_evidence) in evidence.incomplete_refs


class _FailGuardedOnceService(_EvaluationService):
    def __init__(self, storage_root) -> None:
        super().__init__(storage_root)
        self.failed_guarded = False

    def run_evaluation(self, request: EvaluationRequest) -> EvaluationStatus:
        if self.requests and not self.failed_guarded:
            self.requests.append(request)
            self.failed_guarded = True
            return EvaluationStatus(
                evaluation_id="eval-guarded-failed",
                tenant_id=request.tenant_id,
                agent_id=request.agent_id,
                benchmark_id=request.benchmark_id,
                benchmark_version=request.benchmark_version,
                status="failed",
                error="injected guarded failure",
            )
        return super().run_evaluation(request)


def test_resume_retries_only_failed_stage_without_repeating_completed_stages(tmp_path) -> None:
    evaluation_service = _FailGuardedOnceService(tmp_path)
    workflow = AuditWorkflowService(evaluation_service)
    task = AuditTask(
        audit_id="audit-resume",
        tenant_id="tenant-1",
        agent_id="agent-1",
        normal_tasks=[
            BusinessTask(
                task_id="normal-1",
                prompt="Summarize the public document.",
                success_criteria=["Returns a grounded summary."],
            )
        ],
        security_goals=["Reject injected instructions."],
        authorized_risk_surfaces=["prompt_injection"],
        allowed_scenarios=["prompt-injection"],
        benchmark_id="benchmark-1",
        benchmark_version="v0.1",
    )

    workflow.create_audit(task)
    failed = workflow.run_audit(task.audit_id, tenant_id=task.tenant_id)
    resumed = workflow.resume_audit(task.audit_id, tenant_id=task.tenant_id)

    assert failed.state == "failed"
    assert failed.error == "injected guarded failure"
    assert resumed.state == "completed"
    assert len(evaluation_service.requests) == 3

    attempts_by_state = {}
    for record in resumed.stage_history:
        attempts_by_state.setdefault(record.state, []).append(record)
    assert len(attempts_by_state["profiling"]) == 1
    assert len(attempts_by_state["planning"]) == 1
    assert len(attempts_by_state["baseline_execution"]) == 1
    assert len(attempts_by_state["defense_generation"]) == 1
    assert [item.status for item in attempts_by_state["guarded_execution"]] == [
        "failed",
        "completed",
    ]
    assert [item.attempt for item in attempts_by_state["guarded_execution"]] == [1, 2]


def test_restart_marks_interrupted_audit_recoverable_and_preserves_checkpoints(
    tmp_path,
) -> None:
    evaluation_service = _EvaluationService(tmp_path)
    workflow = AuditWorkflowService(evaluation_service)
    task = AuditTask(
        audit_id="audit-interrupted",
        tenant_id="tenant-1",
        agent_id="agent-1",
        normal_tasks=[
            BusinessTask(
                task_id="normal-1",
                prompt="Summarize the public document.",
                success_criteria=["Returns a grounded summary."],
            )
        ],
        security_goals=["Reject injected instructions."],
        authorized_risk_surfaces=["prompt_injection"],
        allowed_scenarios=["prompt-injection"],
        benchmark_id="benchmark-1",
        benchmark_version="v0.1",
    )
    created = workflow.create_audit(task)
    workflow._enter(created, "profiling")

    restarted = AuditWorkflowService(evaluation_service)
    recovered = restarted.recover_interrupted_audits()
    resumed = restarted.resume_audit(task.audit_id, tenant_id=task.tenant_id)

    assert len(recovered) == 1
    assert recovered[0].state == "failed"
    assert "Application restarted" in (recovered[0].error or "")
    assert recovered[0].stage_history[-1].status == "failed"
    assert resumed.state == "completed"
    assert [record.attempt for record in resumed.stage_history if record.state == "profiling"] == [
        1,
        2,
    ]


def test_audit_refuses_to_run_after_source_snapshot_changes(tmp_path) -> None:
    evaluation_service = _EvaluationService(tmp_path)
    workflow = AuditWorkflowService(evaluation_service)
    task = AuditTask(
        audit_id="audit-source-mutation",
        tenant_id="tenant-1",
        agent_id="agent-1",
        normal_tasks=[
            BusinessTask(
                task_id="normal-1",
                prompt="Summarize the public document.",
                success_criteria=["Returns a grounded summary."],
            )
        ],
        security_goals=["Reject injected instructions."],
        authorized_risk_surfaces=["prompt_injection"],
        allowed_scenarios=["prompt-injection"],
        benchmark_id="benchmark-1",
        benchmark_version="v0.1",
    )

    created = workflow.create_audit(task)
    material = evaluation_service.storage.read_material(
        task.tenant_id,
        f"material-{task.agent_id}",
    )
    Path(material["source_path"], "agent.py").write_text(
        "def run(task):\n    return {'changed': task}\n",
        encoding="utf-8",
    )
    failed = workflow.run_audit(task.audit_id, tenant_id=task.tenant_id)

    assert created.source_snapshot_sha256 == material["source_snapshot_sha256"]
    assert failed.state == "failed"
    assert failed.error == "Agent source snapshot SHA-256 mismatch."
    assert evaluation_service.requests == []
