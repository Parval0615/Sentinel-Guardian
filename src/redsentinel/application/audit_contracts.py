from __future__ import annotations

from typing import Any, Literal
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from redsentinel.application.contracts import (
    AgentProfile,
    AgentSecurityComparisonReport,
    AgentSecurityReport,
    EvaluationMode,
    utc_now_iso,
)
from redsentinel.core.models import EvidenceRef


AuditState = Literal[
    "created",
    "profiling",
    "planning",
    "attack_review",
    "baseline_execution",
    "defense_generation",
    "guarded_execution",
    "decision",
    "needs_approval",
    "completed",
    "failed",
]
PlanSource = Literal["llm", "rule_fallback"]
PlannerCallOutcome = Literal["accepted", "rejected", "failed"]
ReleaseDecisionType = Literal[
    "allow_release",
    "retest_after_fix",
    "block_release",
    "manual_review",
]
StageStatus = Literal["running", "completed", "failed", "skipped"]
AuditTracePhase = Literal["baseline", "guarded"]
AuditTraceStream = Literal["baseline", "clean", "controlled", "runtime"]
ModelRuntimeRole = Literal["target", "attack", "defense"]


def _audit_id() -> str:
    return f"audit_{uuid4().hex[:12]}"


def _plan_id() -> str:
    return f"plan_{uuid4().hex[:12]}"


def _defense_plan_id() -> str:
    return f"defense_{uuid4().hex[:12]}"


def _remediation_bundle_id() -> str:
    return f"remediation_{uuid4().hex[:12]}"


def _installation_id() -> str:
    return f"installation_{uuid4().hex[:12]}"


def _decision_id() -> str:
    return f"decision_{uuid4().hex[:12]}"


def _stage_event_id() -> str:
    return f"stage_{uuid4().hex[:12]}"


def _planner_call_id() -> str:
    return f"planner_call_{uuid4().hex[:12]}"


class AuditBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_scenarios: int = Field(default=8, ge=1, le=50)
    max_runtime_seconds: int = Field(default=900, ge=1)
    max_model_calls: int = Field(default=20, ge=0)
    max_cost_usd: float = Field(default=5.0, ge=0.0)


class OpenManusRuntimeConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_key: SecretStr = Field(min_length=1)
    base_url: str = Field(min_length=1)
    model: str = Field(min_length=1)

    @field_validator("base_url")
    @classmethod
    def require_http_endpoint(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("base_url must use http or https")
        return normalized

    @field_validator("model")
    @classmethod
    def require_model_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("model must not be blank")
        return normalized


class OpenManusRuntimeStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    configured: bool
    base_url: str | None = None
    model: str | None = None


class ModelRuntimeConfiguration(OpenManusRuntimeConfiguration):
    model_config = ConfigDict(extra="forbid")


class ModelRuntimeStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: ModelRuntimeRole
    configured: bool
    tested: bool
    base_url: str | None = None
    model: str | None = None
    tested_at: str | None = None
    error: str | None = None


class AuditPreflightCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_id: str = Field(min_length=1)
    status: Literal["ready", "blocked", "not_required"]
    message: str = Field(min_length=1)
    detail: str | None = None


class AuditPreflightStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1)
    adapter_type: str = Field(min_length=1)
    ready: bool
    checked_at: str = Field(min_length=1)
    checks: list[AuditPreflightCheck] = Field(default_factory=list)


class BusinessTaskOracle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required_answer_substrings: list[str] = Field(default_factory=list)
    required_business_events: list[str] = Field(default_factory=list)
    must_not_be_blocked: bool = True


class BusinessTask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    success_criteria: list[str] = Field(min_length=1)
    oracle: BusinessTaskOracle | None = None

    @field_validator("task_id", "prompt")
    @classmethod
    def require_non_blank_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("value must not be blank")
        return stripped

    @field_validator("success_criteria")
    @classmethod
    def require_valid_success_criteria(cls, value: list[str]) -> list[str]:
        return _non_blank_unique(value, "success criteria")


class AuditTask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["audit-task-v0.1"] = "audit-task-v0.1"
    audit_id: str = Field(default_factory=_audit_id, min_length=1)
    parent_audit_id: str | None = Field(default=None, min_length=1)
    round_index: int = Field(default=1, ge=1)
    tenant_id: str = Field(default="private_tenant", min_length=1)
    agent_id: str = Field(min_length=1)
    image_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    profile_id: str | None = Field(default=None, min_length=1)
    profile_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    normal_tasks: list[BusinessTask] = Field(min_length=1)
    security_goals: list[str] = Field(min_length=1)
    authorized_risk_surfaces: list[str] = Field(min_length=1)
    allowed_scenarios: list[str] = Field(default_factory=list)
    runtime_mode: EvaluationMode = "sdk"
    benchmark_id: str = Field(default="ecommerce-security-v0.1", min_length=1)
    benchmark_version: str | None = None
    seed: int = 42
    budget: AuditBudget = Field(default_factory=AuditBudget)
    auto_harden: bool = True
    approval_required_actions: list[str] = Field(default_factory=list)
    minimum_clean_utility: float = Field(default=0.95, ge=0.0, le=1.0)
    created_at: str = Field(default_factory=utc_now_iso)

    @field_validator(
        "security_goals",
        "authorized_risk_surfaces",
        "allowed_scenarios",
        "approval_required_actions",
    )
    @classmethod
    def require_valid_list_items(cls, value: list[str], info) -> list[str]:
        return _non_blank_unique(value, info.field_name.replace("_", " "))

    @model_validator(mode="after")
    def require_unique_normal_task_ids(self) -> AuditTask:
        task_ids = [item.task_id for item in self.normal_tasks]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("normal task ids must be unique")
        bindings = (self.image_digest, self.profile_id, self.profile_sha256)
        if any(bindings) and not all(bindings):
            raise ValueError(
                "image_digest, profile_id, and profile_sha256 must be provided together"
            )
        if self.runtime_mode not in {"sdk", "openmanus_real"}:
            raise ValueError(
                "Source audits require a Sentinel-managed sdk or openmanus_real sandbox."
            )
        return self


class AuditPlanItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)
    risk_surface: str = Field(min_length=1)
    target_node: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    priority: int = Field(ge=1)
    expected_evidence: list[str] = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["audit-plan-v0.1"] = "audit-plan-v0.1"
    plan_id: str = Field(default_factory=_plan_id, min_length=1)
    audit_id: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    source: PlanSource
    planner_model: str | None = None
    items: list[AuditPlanItem] = Field(min_length=1)
    normal_task_ids: list[str] = Field(min_length=1)
    stop_conditions: list[str] = Field(min_length=1)
    warnings: list[str] = Field(default_factory=list)
    call_evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    generated_at: str = Field(default_factory=utc_now_iso)

    @model_validator(mode="after")
    def require_unique_scenarios(self) -> AuditPlan:
        scenario_ids = [item.scenario_id for item in self.items]
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ValueError("audit plan scenario ids must be unique")
        priorities = [item.priority for item in self.items]
        if len(priorities) != len(set(priorities)):
            raise ValueError("audit plan priorities must be unique")
        if len(self.normal_task_ids) != len(set(self.normal_task_ids)):
            raise ValueError("audit plan normal task ids must be unique")
        return self


class AuditPlannerCallEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["audit-planner-call-evidence-v0.1"] = (
        "audit-planner-call-evidence-v0.1"
    )
    call_id: str = Field(default_factory=_planner_call_id, min_length=1)
    audit_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    purpose: Literal["audit_planning"] = "audit_planning"
    outcome: PlannerCallOutcome
    model: str = Field(min_length=1)
    provider_host: str = Field(min_length=1)
    latency_ms: float = Field(ge=0.0)
    max_tokens: int = Field(ge=1)
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    system_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    user_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    provider_request_id: str | None = None
    error: str | None = None
    created_at: str = Field(default_factory=utc_now_iso)


class DefenseAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=1)
    target_node: str = Field(min_length=1)
    guard: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class DefensePlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["defense-plan-v0.1"] = "defense-plan-v0.1"
    defense_plan_id: str = Field(default_factory=_defense_plan_id, min_length=1)
    audit_id: str = Field(min_length=1)
    source_evaluation_id: str = Field(min_length=1)
    actions: list[DefenseAction] = Field(default_factory=list)
    utility_constraints: dict[str, float] = Field(default_factory=dict)
    generated_at: str = Field(default_factory=utc_now_iso)


class RemediationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=1)
    target_node: str = Field(min_length=1)
    guard: str = Field(min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)


class RemediationBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["remediation-bundle-v0.1"] = "remediation-bundle-v0.1"
    bundle_id: str = Field(default_factory=_remediation_bundle_id, min_length=1)
    audit_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    source_defense_plan_id: str = Field(min_length=1)
    source_evaluation_id: str = Field(min_length=1)
    deployment_type: Literal["sandbox_policy"] = "sandbox_policy"
    policies: list[RemediationPolicy] = Field(default_factory=list)
    utility_constraints: dict[str, float] = Field(default_factory=dict)
    prerequisites: list[str] = Field(default_factory=list)
    baseline_evidence: list[EvidenceRef] = Field(default_factory=list)
    rollback_plan: list[str] = Field(min_length=1)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generated_at: str = Field(default_factory=utc_now_iso)


class RemediationInstallation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["remediation-installation-v0.1"] = (
        "remediation-installation-v0.1"
    )
    installation_id: str = Field(default_factory=_installation_id, min_length=1)
    audit_id: str = Field(min_length=1)
    bundle_id: str = Field(min_length=1)
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_environment: Literal["audit_sandbox"] = "audit_sandbox"
    status: Literal["installed"] = "installed"
    policy_ref: str = Field(min_length=1)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    active_guards: list[str] = Field(default_factory=list)
    installed_action_ids: list[str] = Field(default_factory=list)
    installed_at: str = Field(default_factory=utc_now_iso)


class AuditStageRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=_stage_event_id, min_length=1)
    state: AuditState
    status: StageStatus
    attempt: int = Field(default=1, ge=1)
    started_at: str = Field(default_factory=utc_now_iso)
    completed_at: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    message: str | None = None
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class ReleaseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["release-decision-v0.1"] = "release-decision-v0.1"
    decision_id: str = Field(default_factory=_decision_id, min_length=1)
    audit_id: str = Field(min_length=1)
    decision: ReleaseDecisionType
    reasons: list[str] = Field(min_length=1)
    baseline_evaluation_id: str | None = None
    guarded_evaluation_id: str | None = None
    comparison_id: str | None = None
    remediation_bundle_id: str | None = None
    remediation_bundle_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    remediation_installation_id: str | None = None
    clean_utility_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    metrics: dict[str, float] = Field(default_factory=dict)
    unresolved_risks: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    evidence_complete: bool = False
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now_iso)

    @model_validator(mode="after")
    def enforce_release_evidence_gate(self) -> ReleaseDecision:
        if self.decision != "allow_release":
            return self
        if not self.evidence_complete:
            raise ValueError("allow_release requires complete evidence")
        if not all(
            (
                self.baseline_evaluation_id,
                self.guarded_evaluation_id,
                self.comparison_id,
            )
        ):
            raise ValueError("allow_release requires baseline, guarded, and comparison ids")
        if self.clean_utility_rate is None:
            raise ValueError("allow_release requires measured clean utility")
        required_kinds = {"report", "trajectory"}
        if not required_kinds.issubset({item.kind for item in self.evidence_refs}):
            raise ValueError("allow_release requires report and trajectory evidence")
        return self


class AuditRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["audit-run-v0.1"] = "audit-run-v0.1"
    audit_id: str = Field(min_length=1)
    parent_audit_id: str | None = Field(default=None, min_length=1)
    round_index: int = Field(default=1, ge=1)
    tenant_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    state: AuditState = "created"
    task_ref: str = Field(min_length=1)
    source_material_ref: str = Field(min_length=1)
    source_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    image_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    profile_id: str | None = Field(default=None, min_length=1)
    profile_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    plan_ref: str | None = None
    defense_plan_ref: str | None = None
    remediation_bundle_ref: str | None = None
    remediation_installation_ref: str | None = None
    baseline_evaluation_id: str | None = None
    guarded_evaluation_id: str | None = None
    comparison_id: str | None = None
    comparison_ref: str | None = None
    decision_ref: str | None = None
    evidence_index_ref: str | None = None
    stage_history: list[AuditStageRecord] = Field(default_factory=list)
    error: str | None = None
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)

    @model_validator(mode="after")
    def require_complete_image_profile_binding(self) -> AuditRun:
        bindings = (self.image_digest, self.profile_id, self.profile_sha256)
        if any(bindings) and not all(bindings):
            raise ValueError(
                "image_digest, profile_id, and profile_sha256 must be provided together"
            )
        return self

    def with_update(self, **updates: Any) -> AuditRun:
        return self.model_copy(update={**updates, "updated_at": utc_now_iso()})


class AuditPlanView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["audit-plan-view-v0.1"] = "audit-plan-view-v0.1"
    audit_id: str = Field(min_length=1)
    state: AuditState
    task: AuditTask
    plan: AuditPlan


class AuditEvidenceArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(min_length=1)
    stage: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    ref: str = Field(min_length=1)
    available: bool
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class AuditEvidenceIndex(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["audit-evidence-index-v0.1"] = "audit-evidence-index-v0.1"
    audit_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    generated_at: str = Field(default_factory=utc_now_iso)
    artifacts: list[AuditEvidenceArtifact] = Field(default_factory=list)
    incomplete_refs: list[str] = Field(default_factory=list)


class AuditStatusView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["audit-status-view-v0.1"] = "audit-status-view-v0.1"
    audit_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    state: AuditState
    progress_percent: float = Field(ge=0.0, le=100.0)
    completed_stage_count: int = Field(ge=0)
    total_stage_count: int = Field(ge=1)
    total_duration_ms: int = Field(ge=0)
    error: str | None = None
    evidence_index_ref: str | None = None
    stages: list[AuditStageRecord] = Field(default_factory=list)


class AuditTraceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    phase: AuditTracePhase
    scenario_id: str = Field(min_length=1)
    stream: AuditTraceStream
    sequence: int = Field(ge=0)
    event_type: str = Field(min_length=1)
    timestamp: str | None = None
    title: str = Field(min_length=1)
    summary: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class AuditScenarioTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["audit-scenario-trace-v0.1"] = "audit-scenario-trace-v0.1"
    trace_id: str = Field(min_length=1)
    phase: AuditTracePhase
    scenario_id: str = Field(min_length=1)
    trajectory_ref: str = Field(min_length=1)
    available: bool
    event_count: int = Field(ge=0)
    truncated: bool = False
    events: list[AuditTraceEvent] = Field(default_factory=list)


class AuditAttackOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)
    attack_spec_id: str = Field(min_length=1)
    risk_surface: str = Field(min_length=1)
    predicted_node_id: str = Field(min_length=1)
    predicted_path_id: str | None = None
    baseline_attack_succeeded: bool | None = None
    baseline_failed_node_id: str | None = None
    guarded_attack_succeeded: bool | None = None
    guarded_failed_node_id: str | None = None
    defense_guards: list[str] = Field(default_factory=list)
    baseline_trajectory_ref: str | None = None
    guarded_trajectory_ref: str | None = None


class AuditRoundView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["audit-round-view-v0.1"] = "audit-round-view-v0.1"
    round_index: int = Field(ge=1)
    parent_audit_id: str | None = None
    attack_set_source: Literal["static_profile", "prior_round_feedback"]
    benchmark_id: str = Field(min_length=1)
    benchmark_version: str = Field(min_length=1)
    attack_count: int = Field(ge=0)
    baseline_success_count: int = Field(ge=0)
    guarded_success_count: int = Field(ge=0)
    outcomes: list[AuditAttackOutcome] = Field(default_factory=list)


class AuditWorkspaceView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["audit-workspace-view-v0.1"] = "audit-workspace-view-v0.1"
    audit_id: str = Field(min_length=1)
    state: AuditState
    run: AuditRun
    task: AuditTask
    profile: AgentProfile
    plan: AuditPlan | None = None
    status: AuditStatusView
    baseline_report: AgentSecurityReport | None = None
    guarded_report: AgentSecurityReport | None = None
    comparison: AgentSecurityComparisonReport | None = None
    decision: ReleaseDecision | None = None
    remediation_bundle: RemediationBundle | None = None
    remediation_installation: RemediationInstallation | None = None
    evidence: AuditEvidenceIndex
    traces: list[AuditScenarioTrace] = Field(default_factory=list)
    round: AuditRoundView | None = None


def _non_blank_unique(values: list[str], label: str) -> list[str]:
    stripped = [value.strip() for value in values]
    if any(not value for value in stripped):
        raise ValueError(f"{label} must not contain blank values")
    if len(stripped) != len(set(stripped)):
        raise ValueError(f"{label} must be unique")
    return stripped


__all__ = [
    "AuditBudget",
    "AuditEvidenceArtifact",
    "AuditEvidenceIndex",
    "AuditPlan",
    "AuditPlanItem",
    "AuditPlannerCallEvidence",
    "AuditPlanView",
    "AuditAttackOutcome",
    "AuditRoundView",
    "AuditRun",
    "AuditStageRecord",
    "AuditState",
    "AuditStatusView",
    "AuditTask",
    "AuditWorkspaceView",
    "BusinessTask",
    "DefenseAction",
    "DefensePlan",
    "OpenManusRuntimeConfiguration",
    "OpenManusRuntimeStatus",
    "PlanSource",
    "RemediationBundle",
    "RemediationInstallation",
    "RemediationPolicy",
    "ReleaseDecision",
    "ReleaseDecisionType",
]
