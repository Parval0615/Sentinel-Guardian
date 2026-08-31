from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from redsentinel.adapters.engine.adapter import AgentAdapter
from redsentinel.application.contracts import (
    AgentOnboardingRequest,
    AgentRegistration,
    EvaluationRequest,
)
from redsentinel.application.audit_contracts import AuditPlannerCallEvidence, AuditTask
from redsentinel.application.engine.audit_planner import AuditPlanner
from redsentinel.application.engine.audit_workflow import AuditWorkflowService
from redsentinel.application.engine.dynamic_profile_probe import DynamicProfileProbe
from redsentinel.application.engine.local_image_ref import (
    LocalDockerImageRefResolver,
)
from redsentinel.application.engine.llm_gateway import (
    JsonLLMGateway,
    OpenAIJsonGateway,
)
from redsentinel.application.engine.image_profile_workflow import ImageProfileWorkflowService
from redsentinel.application.engine.service import ProductEvaluationService
from redsentinel.application.engine.supervision import SupervisionEventStore
from redsentinel.core.docker_runtime import resolve_docker_binary
from redsentinel.core.models import EvidenceRef
from redsentinel.profiling.semantic import SemanticEnricher, semantic_gateway_from_environment


class AgentManagementService:
    """Application boundary for Agent registration, onboarding, and profiles."""

    def __init__(self, service: ProductEvaluationService) -> None:
        self._service = service

    def register_agent(self, registration: AgentRegistration, adapter: AgentAdapter | None = None):
        return self._service.register_agent(registration, adapter)

    def onboard_agent(self, request: AgentOnboardingRequest):
        return self._service.onboard_agent(request)

    def get_agent(self, agent_id: str, tenant_id: str = "private_tenant"):
        return self._service.get_agent(agent_id, tenant_id)

    def list_agents(self, tenant_id: str = "private_tenant"):
        agent_root = self._service.storage.tenant_dir(tenant_id) / "agents"
        agents = []
        for path in sorted(agent_root.glob("*.json")):
            payload = self._service.storage.read_json(path)
            if payload.get("status") == "ready" or (
                payload.get("data_boundary", {}).get("image_digest")
                and payload.get("status") in {"profiling", "failed"}
            ):
                agents.append(AgentRegistration.model_validate(payload))
        return agents

    def unregister_agent(self, agent_id: str, tenant_id: str = "private_tenant"):
        return self._service.unregister_agent(agent_id, tenant_id)

    def get_agent_profile(self, agent_id: str, tenant_id: str = "private_tenant"):
        return self._service.get_agent_profile(agent_id, tenant_id)

    def create_session(self, tenant_id: str, agent_id: str):
        return self._service.create_session(tenant_id, agent_id)


class EvaluationApplicationService:
    """Application boundary for benchmark execution and experiment progression."""

    def __init__(self, service: ProductEvaluationService) -> None:
        self._service = service

    def run_evaluation(self, request: EvaluationRequest):
        return self._service.run_evaluation(request)

    def get_evaluation(self, evaluation_id: str, *, tenant_id: str | None = None):
        return self._service.get_evaluation(evaluation_id, tenant_id=tenant_id)

    def list_benchmarks(self):
        return self._service.list_benchmarks()

    def list_benchmark_versions(self, benchmark_id: str):
        return self._service.list_benchmark_versions(benchmark_id)

    def get_benchmark_version(self, benchmark_id: str, version: str):
        return self._service.get_benchmark_version(benchmark_id, version)

    def create_next_round(self, evaluation_id: str, *, tenant_id: str | None = None):
        return self._service.create_next_round(evaluation_id, tenant_id=tenant_id)

    def upload_trajectory(self, tenant_id: str, agent_id: str, trajectory: dict[str, Any]):
        return self._service.upload_trajectory(tenant_id, agent_id, trajectory)


class ReportingApplicationService:
    """Application boundary for reports, logs, comparisons, and dashboard data."""

    def __init__(self, service: ProductEvaluationService) -> None:
        self._service = service

    def get_report(self, report_id: str, *, tenant_id: str | None = None):
        return self._service.get_report(report_id, tenant_id=tenant_id)

    def list_logs(self, agent_id: str, tenant_id: str = "private_tenant"):
        return self._service.list_logs(agent_id, tenant_id)

    def get_log_detail(self, evaluation_id: str, tenant_id: str | None = None):
        return self._service.get_log_detail(evaluation_id, tenant_id)

    def get_dashboard_summary(self, agent_id: str, tenant_id: str = "private_tenant"):
        return self._service.get_dashboard_summary(agent_id, tenant_id)

    def compare_reports(
        self,
        before_report_id: str,
        after_report_id: str,
        *,
        tenant_id: str | None = None,
    ):
        return self._service.compare_reports(
            before_report_id,
            after_report_id,
            tenant_id=tenant_id,
        )


class AuditApplicationService:
    """Application boundary for autonomous security audit workflows."""

    def __init__(self, workflow: AuditWorkflowService) -> None:
        self._workflow = workflow

    def create_audit(self, task: AuditTask):
        return self._workflow.create_audit(task)

    def run_audit(self, audit_id: str, *, tenant_id: str):
        return self._workflow.run_audit(audit_id, tenant_id=tenant_id)

    def prepare_audit(self, audit_id: str, *, tenant_id: str):
        return self._workflow.prepare_audit(audit_id, tenant_id=tenant_id)

    def resume_audit(self, audit_id: str, *, tenant_id: str):
        return self._workflow.resume_audit(audit_id, tenant_id=tenant_id)

    def create_next_audit_round(
        self,
        audit_id: str,
        *,
        tenant_id: str,
        run_immediately: bool = True,
    ):
        return self._workflow.create_next_round(
            audit_id,
            tenant_id=tenant_id,
            run_immediately=run_immediately,
        )

    def get_audit(self, audit_id: str, *, tenant_id: str):
        return self._workflow.get_audit(audit_id, tenant_id=tenant_id)

    def list_audits(self, *, tenant_id: str):
        return self._workflow.list_audits(tenant_id=tenant_id)

    def recover_interrupted_audits(self):
        return self._workflow.recover_interrupted_audits()

    def get_decision(self, audit_id: str, *, tenant_id: str):
        return self._workflow.get_decision(audit_id, tenant_id=tenant_id)













    def get_plan_view(self, audit_id: str, *, tenant_id: str):
        return self._workflow.get_plan_view(audit_id, tenant_id=tenant_id)

    def get_status(self, audit_id: str, *, tenant_id: str):
        return self._workflow.get_status(audit_id, tenant_id=tenant_id)

    def get_evidence_index(self, audit_id: str, *, tenant_id: str):
        return self._workflow.get_evidence_index(audit_id, tenant_id=tenant_id)

    def get_workspace(self, audit_id: str, *, tenant_id: str):
        return self._workflow.get_workspace(audit_id, tenant_id=tenant_id)


class ProductApplicationService:
    """Public Product API facade composed from narrow application services.

    The legacy evaluation service remains the compatibility implementation
    during migration. HTTP routes depend on this facade so research and domain
    implementations can move without changing the public API contract.
    """

    def __init__(
        self,
        storage_root: str | Path = "runs/product",
        *,
        planner_gateway: JsonLLMGateway | None = None,
        defense_gateway: JsonLLMGateway | None = None,
    ) -> None:
        legacy = ProductEvaluationService(storage_root=storage_root)
        self._legacy = legacy
        self.storage = legacy.storage
        self.agents = AgentManagementService(legacy)
        self.evaluations = EvaluationApplicationService(legacy)
        self.reporting = ReportingApplicationService(legacy)
        docker_binary = resolve_docker_binary()
        self.image_profiles = ImageProfileWorkflowService(
            self.storage,
            semantic_enricher=SemanticEnricher(semantic_gateway_from_environment()),
            dynamic_probe_factory=lambda artifact_root: DynamicProfileProbe(
                artifact_root,
                docker_binary=docker_binary,
            ),
            image_ref_resolver=LocalDockerImageRefResolver(docker_binary),
            agent_writer=legacy.register_agent,
        )
        gateway = (
            planner_gateway
            if planner_gateway is not None
            else _planner_gateway_from_environment()
        )
        planner = AuditPlanner(
            gateway=gateway,
            evidence_writer=(
                lambda evidence: _write_planner_call_evidence(self.storage, evidence)
            )
            if gateway is not None
            else None,
        )
        self.audits = AuditApplicationService(
            AuditWorkflowService(
                legacy,
                planner=planner,
                defense_gateway=defense_gateway,
                image_profiles=self.image_profiles,
            )
        )
        self.supervision = SupervisionEventStore(storage=self.storage)

    register_agent = property(lambda self: self.agents.register_agent)
    onboard_agent = property(lambda self: self.agents.onboard_agent)
    list_agents = property(lambda self: self.agents.list_agents)
    unregister_agent = property(lambda self: self.agents.unregister_agent)
    get_agent = property(lambda self: self.agents.get_agent)
    get_agent_profile = property(lambda self: self.agents.get_agent_profile)
    create_session = property(lambda self: self.agents.create_session)
    run_evaluation = property(lambda self: self.evaluations.run_evaluation)
    get_evaluation = property(lambda self: self.evaluations.get_evaluation)
    list_benchmarks = property(lambda self: self.evaluations.list_benchmarks)
    list_benchmark_versions = property(lambda self: self.evaluations.list_benchmark_versions)
    get_benchmark_version = property(lambda self: self.evaluations.get_benchmark_version)
    create_next_round = property(lambda self: self.evaluations.create_next_round)
    upload_trajectory = property(lambda self: self.evaluations.upload_trajectory)
    get_report = property(lambda self: self.reporting.get_report)
    list_logs = property(lambda self: self.reporting.list_logs)
    get_log_detail = property(lambda self: self.reporting.get_log_detail)
    get_dashboard_summary = property(lambda self: self.reporting.get_dashboard_summary)
    compare_reports = property(lambda self: self.reporting.compare_reports)
    create_audit = property(lambda self: self.audits.create_audit)
    run_audit = property(lambda self: self.audits.run_audit)
    prepare_audit = property(lambda self: self.audits.prepare_audit)
    resume_audit = property(lambda self: self.audits.resume_audit)
    create_next_audit_round = property(
        lambda self: self.audits.create_next_audit_round
    )
    get_audit = property(lambda self: self.audits.get_audit)
    list_audits = property(lambda self: self.audits.list_audits)
    recover_interrupted_audits = property(
        lambda self: self.audits.recover_interrupted_audits
    )
    get_audit_decision = property(lambda self: self.audits.get_decision)
    get_audit_plan_view = property(lambda self: self.audits.get_plan_view)
    get_audit_status = property(lambda self: self.audits.get_status)
    get_audit_evidence_index = property(lambda self: self.audits.get_evidence_index)
    get_audit_workspace = property(lambda self: self.audits.get_workspace)


def _planner_gateway_from_environment() -> JsonLLMGateway | None:
    api_key = os.environ.get("RED_SENTINEL_PLANNER_API_KEY", "").strip()
    base_url = os.environ.get("RED_SENTINEL_PLANNER_BASE_URL", "").strip()
    model = os.environ.get("RED_SENTINEL_PLANNER_MODEL", "").strip()
    if not any((api_key, base_url, model)):
        return None
    missing = [
        name
        for name, value in (
            ("RED_SENTINEL_PLANNER_API_KEY", api_key),
            ("RED_SENTINEL_PLANNER_BASE_URL", base_url),
            ("RED_SENTINEL_PLANNER_MODEL", model),
        )
        if not value
    ]
    if missing:
        raise ValueError(f"Incomplete LLM planner configuration: {', '.join(missing)}")
    timeout = float(os.environ.get("RED_SENTINEL_PLANNER_TIMEOUT_SECONDS", "30"))
    return OpenAIJsonGateway(
        api_key=api_key,
        base_url=base_url,
        model=model,
        timeout_seconds=timeout,
    )


def _write_planner_call_evidence(storage, evidence: AuditPlannerCallEvidence) -> EvidenceRef:
    path = storage.audit_planner_call_path(evidence.tenant_id, evidence.audit_id)
    storage.write_audit_planner_call(
        evidence.tenant_id,
        evidence.audit_id,
        evidence.model_dump(mode="json"),
    )
    return EvidenceRef(
        ref=str(path),
        kind="runtime",
        description="Sanitized LLM planner call metadata and prompt hashes.",
    )


__all__ = [
    "AgentManagementService",
    "AuditApplicationService",
    "EvaluationApplicationService",
    "ProductApplicationService",
    "ReportingApplicationService",
]
