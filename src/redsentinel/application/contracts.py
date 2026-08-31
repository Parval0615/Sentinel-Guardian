from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr


RiskLevel = Literal["low", "medium", "high", "critical"]
EvaluationMode = Literal["sdk", "hosted_api", "offline_trace", "openmanus_real"]
EvaluationState = Literal["queued", "running", "completed", "failed"]
FindingComparisonStatus = Literal["resolved", "new", "persisted"]
ScenarioComparisonStatus = Literal["improved", "regressed", "unchanged_pass", "unchanged_fail"]
IntegrationType = Literal["source", "docker", "api"]
AgentStatus = Literal["created", "profiling", "benchmarking", "ready", "failed"]
AgentType = Literal["ecommerce_rag", "generic_executor"]
BenchmarkCaseType = Literal["attack", "clean"]
Decision = Literal["allow", "block"]
SupervisionDecision = Literal["allow", "deny", "ask"]
SupervisionStatus = Literal["observed", "blocked", "pending", "approved", "rejected", "expired"]
SupervisionCallType = Literal["llm_input", "llm_output", "tool_call", "tool_result", "code_execution", "file_access"]
SupervisionDefaultAction = Literal["allow", "deny"]
SupervisionResponseAction = Literal["approve", "reject"]
SupervisionResponseStatus = Literal["approved", "rejected", "expired"]
ReportStatus = Literal["complete", "incomplete"]
OnboardingStageName = Literal[
    "agent_record",
    "source_snapshot",
    "profile_analysis",
    "sandbox_build_plan",
    "initial_benchmark",
    "default_defense_mount",
]
OnboardingStageStatus = Literal["completed", "failed", "skipped"]
AuthUserStatus = Literal["active", "disabled"]
AuthUserRole = Literal["user", "admin"]
AuthErrorCode = Literal[
    "invalid_auth_request",
    "invalid_credentials",
    "auth_required",
    "token_invalid",
    "token_expired",
    "user_conflict",
    "user_disabled",
    "auth_service_error",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _supervision_event_id() -> str:
    return f"evt_{uuid4().hex[:12]}"


class SupervisionEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=_supervision_event_id, min_length=1)
    schema_version: Literal["supervision-event-v0.1"] = "supervision-event-v0.1"
    timestamp: str = Field(default_factory=utc_now_iso, min_length=1)
    tenant_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    call_type: SupervisionCallType
    decision: SupervisionDecision
    reason: str = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)
    payload_summary: dict[str, Any] = Field(default_factory=dict)
    source: str = Field(min_length=1)
    status: SupervisionStatus


class PendingDecisionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    tenant_id: str | None = Field(default=None, min_length=1)
    requested_at: str = Field(min_length=1)
    expires_at: str = Field(min_length=1)
    default_action: SupervisionDefaultAction
    supervisor_action: str | None = None
    resolved_at: str | None = None


class SupervisionResponseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["supervision-response-request-v0.1"] = "supervision-response-request-v0.1"
    action: SupervisionResponseAction
    operator: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class SupervisionResponseRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["supervision-response-v0.1"] = "supervision-response-v0.1"
    event_id: str = Field(min_length=1)
    action: SupervisionResponseAction
    operator: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    resolved_at: str = Field(default_factory=utc_now_iso, min_length=1)
    status: SupervisionResponseStatus


class AuthRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["auth-register-request-v0.1"] = "auth-register-request-v0.1"
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: SecretStr = Field(min_length=8, max_length=256, exclude=True)


class AuthLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["auth-login-request-v0.1"] = "auth-login-request-v0.1"
    account: str = Field(min_length=1, max_length=254)
    password: SecretStr = Field(min_length=1, max_length=256, exclude=True)
    remember_me: bool = False


class AuthUserSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["auth-user-summary-v0.1"] = "auth-user-summary-v0.1"
    user_id: str = Field(min_length=1)
    username: str = Field(min_length=1)
    email: str = Field(min_length=3)
    status: AuthUserStatus = "active"
    role: AuthUserRole = "user"


class AuthUserRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["auth-user-record-v0.1"] = "auth-user-record-v0.1"
    user_id: str = Field(min_length=1)
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password_hash: str = Field(min_length=1)
    password_salt: str = Field(min_length=1)
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    last_login_at: str | None = None
    status: AuthUserStatus = "active"
    role: AuthUserRole = "user"
    token_version: int = Field(default=0, ge=0)


class AgentLibraryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-library-entry-v0.1"] = "agent-library-entry-v0.1"
    agent_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1)
    framework: str = Field(min_length=1)
    description: str = Field(default="", min_length=0)
    default_benchmark_id: str = Field(default="ecommerce-security-v0.1", min_length=1)
    tags: list[str] = Field(default_factory=list)
    source: Literal["official", "custom"] = "custom"
    created_by: str | None = None
    created_at: str = Field(default_factory=utc_now_iso)


class AuthTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["auth-token-response-v0.1"] = "auth-token-response-v0.1"
    access_token: str = Field(min_length=1)
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(gt=0)
    user: AuthUserSummary


class AuthRegisterResponse(AuthTokenResponse):
    schema_version: Literal["auth-register-response-v0.1"] = "auth-register-response-v0.1"


class AuthLoginResponse(AuthTokenResponse):
    schema_version: Literal["auth-login-response-v0.1"] = "auth-login-response-v0.1"


class AuthCurrentUserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["auth-current-user-response-v0.1"] = "auth-current-user-response-v0.1"
    user: AuthUserSummary


class AuthLogoutResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["auth-logout-response-v0.1"] = "auth-logout-response-v0.1"
    success: bool = True
    message: str = Field(default="Logged out.", min_length=1)


class AuthFieldError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(min_length=1)
    message: str = Field(min_length=1)
    error_code: str | None = Field(default=None, min_length=1)


class AuthErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["auth-error-response-v0.1"] = "auth-error-response-v0.1"
    error_code: AuthErrorCode
    message: str = Field(min_length=1)
    field_errors: list[AuthFieldError] = Field(default_factory=list)


class ToolSpecModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    risk_level: str = Field(min_length=1)
    description: str = Field(min_length=1)


class AgentRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-registration-v0.1"] = "agent-registration-v0.1"
    tenant_id: str = Field(default="private_tenant", min_length=1)
    username: str | None = None
    agent_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    domain: str = Field(default="general", min_length=1)
    integration_type: IntegrationType = "source"
    framework: str = Field(default="sdk", min_length=1)
    adapter_type: Literal["ecommerce_demo", "external_sdk", "http_endpoint", "openmanus"] = "ecommerce_demo"
    endpoint_url: str | None = None
    secret_ref: str | None = None
    has_api_key: bool = False
    masked_api_key: str | None = None
    status: AgentStatus = "created"
    remarks: str | None = None
    created_at: str = Field(default_factory=utc_now_iso)
    tool_specs: list[ToolSpecModel] = Field(default_factory=list)
    data_boundary: dict[str, Any] = Field(default_factory=dict)


class AgentOnboardingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-onboarding-request-v0.1"] = "agent-onboarding-request-v0.1"
    tenant_id: str = Field(default="private_tenant", min_length=1)
    username: str | None = None
    agent_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    domain: str = Field(default="general", min_length=1)
    integration_type: Literal["source"] = "source"
    framework: str = Field(default="sdk", min_length=1)
    remarks: str | None = None
    source_path: str = Field(min_length=1)
    build_manifest_path: str = Field(min_length=1)


class AgentMaterial(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-material-v0.1"] = "agent-material-v0.1"
    material_id: str = Field(min_length=1)
    tenant_id: str = Field(default="private_tenant", min_length=1)
    agent_id: str = Field(min_length=1)
    type: IntegrationType
    source_path: str | None = None
    build_manifest_path: str | None = None
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    build_manifest_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    source_snapshot_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    source_file_count: int = Field(default=0, ge=0)
    source_snapshot_verified: bool = False
    openapi_path: str | None = None
    docker_image: str | None = None
    endpoint_url: str | None = None
    secret_ref: str | None = None
    has_api_key: bool = False
    masked_api_key: str | None = None
    uploaded_files: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now_iso)


class AgentProfileNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(min_length=1)
    node_type: str = Field(min_length=1)
    required: bool = True
    critical: bool = False
    risk_surfaces: list[str] = Field(default_factory=list)
    defenses: list[str] = Field(default_factory=list)


class AgentProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-profile-v0.1"] = "agent-profile-v0.1"
    profile_id: str = Field(min_length=1)
    tenant_id: str = Field(default="private_tenant", min_length=1)
    agent_id: str = Field(min_length=1)
    agent_type: AgentType = "ecommerce_rag"
    created_at: str = Field(default_factory=utc_now_iso)
    nodes: list[AgentProfileNode] = Field(default_factory=list)
    tools: list[ToolSpecModel] = Field(default_factory=list)
    rag: dict[str, Any] = Field(default_factory=dict)
    memory: dict[str, Any] = Field(default_factory=dict)
    data_boundary: dict[str, Any] = Field(default_factory=dict)
    risk_surface: list[str] = Field(default_factory=list)
    generated_at: str = Field(default_factory=utc_now_iso)


class AgentOnboardingStage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: OnboardingStageName
    status: OnboardingStageStatus
    mode: str | None = None
    evaluation_id: str | None = None
    message: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class AgentOnboardingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-onboarding-response-v0.1"] = "agent-onboarding-response-v0.1"
    tenant_id: str = Field(default="private_tenant", min_length=1)
    agent_id: str = Field(min_length=1)
    status: AgentStatus
    ready: bool = False
    agent: AgentRegistration
    material: AgentMaterial
    profile: AgentProfile
    stages: list[AgentOnboardingStage] = Field(default_factory=list)


class BenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["benchmark-case-v0.1"] = "benchmark-case-v0.1"
    case_id: str = Field(min_length=1)
    benchmark_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    case_type: BenchmarkCaseType
    prompt: str = Field(min_length=1)
    rag_documents: list[str] = Field(default_factory=list)
    rag_document_summary: str | None = None
    target_node: str = Field(min_length=1)
    expected_decision: Decision
    severity: RiskLevel = "medium"
    tags: list[str] = Field(default_factory=list)


class BenchmarkVersion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["benchmark-version-v0.1"] = "benchmark-version-v0.1"
    benchmark_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    source_report_id: str | None = None
    generation_record: dict[str, Any] = Field(default_factory=dict)
    case_count: int = Field(default=0, ge=0)
    node_coverage: dict[str, int] = Field(default_factory=dict)
    cases: list[BenchmarkCase] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now_iso)


class Benchmark(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["benchmark-v0.1"] = "benchmark-v0.1"
    benchmark_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(default="", min_length=0)
    domain: str = Field(default="general", min_length=1)
    active_version: str = Field(min_length=1)
    created_at: str = Field(default_factory=utc_now_iso)


class BenchmarkSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["benchmark-summary-v0.1"] = "benchmark-summary-v0.1"
    benchmark_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(default="", min_length=0)
    domain: str = Field(default="general", min_length=1)
    active_version: str = Field(min_length=1)
    version_count: int = Field(default=0, ge=0)
    case_count: int = Field(default=0, ge=0)
    attack_case_count: int = Field(default=0, ge=0)
    clean_case_count: int = Field(default=0, ge=0)
    created_at: str | None = None


class BenchmarkVersionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["benchmark-version-summary-v0.1"] = "benchmark-version-summary-v0.1"
    benchmark_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    source_report_id: str | None = None
    case_count: int = Field(default=0, ge=0)
    attack_case_count: int = Field(default=0, ge=0)
    clean_case_count: int = Field(default=0, ge=0)
    node_count: int = Field(default=0, ge=0)
    created_at: str | None = None


class BenchmarkVersionDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["benchmark-version-detail-v0.1"] = "benchmark-version-detail-v0.1"
    benchmark_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    source_report_id: str | None = None
    generation_record: dict[str, Any] = Field(default_factory=dict)
    case_count: int = Field(default=0, ge=0)
    attack_case_count: int = Field(default=0, ge=0)
    clean_case_count: int = Field(default=0, ge=0)
    node_coverage: dict[str, int] = Field(default_factory=dict)
    cases: list[BenchmarkCase] = Field(default_factory=list)
    created_at: str | None = None


class NextRoundResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["next-round-response-v0.1"] = "next-round-response-v0.1"
    source_evaluation_id: str = Field(min_length=1)
    source_report_id: str = Field(min_length=1)
    benchmark_id: str = Field(min_length=1)
    benchmark_version: str = Field(min_length=1)
    version: BenchmarkVersionDetail
    attack_generation: dict[str, Any] = Field(default_factory=dict)
    defense_suggestions: list[str] = Field(default_factory=list)


class EvaluationProgress(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_cases: int = Field(default=0, ge=0)
    completed_cases: int = Field(default=0, ge=0)
    percent: float = Field(default=0.0, ge=0.0, le=100.0)
    current_case: str | None = None
    current_node: str | None = None


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(default="private_tenant", min_length=1)
    agent_id: str = Field(min_length=1)
    benchmark: str = Field(default="ecommerce-security-v0.1", min_length=1)
    benchmark_id: str | None = None
    benchmark_version: str | None = None
    mode: EvaluationMode = "sdk"
    pilot_preset: str | None = None
    attack_intensity: Literal["light", "medium", "heavy"] = "medium"
    defense_enabled: bool = True
    seed: int = 42
    scenarios: list[str] = Field(default_factory=list)
    policy: dict[str, Any] = Field(default_factory=lambda: {
        "no_real_payment": True,
        "no_external_attack": True,
        "single_tenant": True,
    })


class EvaluationStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evaluation_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    benchmark_id: str | None = None
    benchmark_version: str | None = None
    status: EvaluationState
    progress: EvaluationProgress | None = None
    current_case: str | None = None
    current_node: str | None = None
    report_id: str | None = None
    report_path: str | None = None
    error: str | None = None


class EvaluationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["evaluation-v0.1"] = "evaluation-v0.1"
    evaluation_id: str = Field(min_length=1)
    tenant_id: str = Field(default="private_tenant", min_length=1)
    agent_id: str = Field(min_length=1)
    benchmark_id: str = Field(min_length=1)
    benchmark_version: str = Field(min_length=1)
    status: EvaluationState
    progress: EvaluationProgress = Field(default_factory=EvaluationProgress)
    started_at: str = Field(default_factory=utc_now_iso)
    completed_at: str | None = None


class EvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["evaluation-result-v0.1"] = "evaluation-result-v0.1"
    result_id: str = Field(min_length=1)
    evaluation_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    case_type: BenchmarkCaseType
    target_node: str = Field(min_length=1)
    expected_decision: Decision
    actual_decision: Decision
    blocked_node: str | None = None
    bypassed_nodes: list[str] = Field(default_factory=list)
    trajectory_ref: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    severity: RiskLevel
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    business_impact: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)


class ScenarioResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    target_node: str | None = None
    severity: RiskLevel
    expected_decision: Literal["allow", "block"]
    actual_decision: Literal["allow", "block"]
    clean_decision: Literal["allow", "block"]
    passed: bool
    business_impact: str = Field(min_length=1)
    trajectory_ref: str = Field(min_length=1)
    blocked_node: str | None = None
    bypassed_nodes: list[str] = Field(default_factory=list)
    node_status: dict[str, Any] = Field(default_factory=dict)


class ReportArtifacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trajectory_refs: list[str] = Field(default_factory=list)
    audit_refs: list[str] = Field(default_factory=list)
    report_path: str = Field(min_length=1)
    markdown_path: str | None = None
    dashboard_path: str | None = None


class MetricInputs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_case_count: int = Field(default=0, ge=0)
    clean_case_count: int = Field(default=0, ge=0)
    attack_success_count: int = Field(default=0, ge=0)
    attack_blocked_count: int = Field(default=0, ge=0)
    clean_blocked_count: int = Field(default=0, ge=0)
    bypassed_critical_node_count: int = Field(default=0, ge=0)
    critical_node_test_count: int = Field(default=0, ge=0)
    critical_attack_bypass_count: int = Field(default=0, ge=0)
    tested_node_count: int = Field(default=0, ge=0)
    total_required_node_count: int = Field(default=0, ge=0)
    failed_attack_severity_weights: list[int] = Field(default_factory=list)


class DeterministicMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_case_count: int = Field(default=0, ge=0)
    clean_case_count: int = Field(default=0, ge=0)
    attack_success_count: int = Field(default=0, ge=0)
    attack_blocked_count: int = Field(default=0, ge=0)
    clean_blocked_count: int = Field(default=0, ge=0)
    bypassed_critical_node_count: int = Field(default=0, ge=0)
    critical_node_test_count: int = Field(default=0, ge=0)
    critical_attack_bypass_count: int = Field(default=0, ge=0)
    tested_node_count: int = Field(default=0, ge=0)
    total_required_node_count: int = Field(default=0, ge=0)
    asr: float = Field(default=0.0, ge=0.0, le=1.0)
    dsr: float = Field(default=0.0, ge=0.0, le=1.0)
    fpr: float = Field(default=0.0, ge=0.0, le=1.0)
    coverage_gap: float = Field(default=0.0, ge=0.0, le=1.0)
    critical_node_bypass_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    severity_penalty: float = Field(default=0.0, ge=0.0, le=10.0)


class ScoreBreakdown(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    raw_score: float
    penalties: dict[str, float] = Field(default_factory=dict)


class MetricSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["metric-snapshot-v0.1"] = "metric-snapshot-v0.1"
    snapshot_id: str = Field(min_length=1)
    tenant_id: str = Field(default="private_tenant", min_length=1)
    agent_id: str = Field(min_length=1)
    latest_report_id: str | None = None
    evaluation_id: str | None = None
    benchmark_id: str | None = None
    benchmark_version: str | None = None
    score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    asr: float = Field(default=0.0, ge=0.0, le=1.0)
    dsr: float = Field(default=0.0, ge=0.0, le=1.0)
    fpr: float = Field(default=0.0, ge=0.0, le=1.0)
    coverage_gap: float = Field(default=0.0, ge=0.0, le=1.0)
    critical_node_bypass_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    created_at: str = Field(default_factory=utc_now_iso)


class DashboardTrendPoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1)
    round: int = Field(ge=1)
    source: Literal["report", "metric_snapshot"]
    evaluation_id: str | None = None
    report_id: str | None = None
    snapshot_id: str | None = None
    benchmark_id: str | None = None
    benchmark_version: str | None = None
    score: int | None = Field(default=None, ge=0, le=100)
    risk_level: RiskLevel | None = None
    asr: float | None = Field(default=None, ge=0.0, le=1.0)
    fpr: float | None = Field(default=None, ge=0.0, le=1.0)
    created_at: str | None = None


class DashboardSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["dashboard-summary-v0.1"] = "dashboard-summary-v0.1"
    tenant_id: str = Field(default="private_tenant", min_length=1)
    agent_id: str = Field(min_length=1)
    has_data: bool
    empty_reason: str | None = None
    current_security_score: int | None = Field(default=None, ge=0, le=100)
    current_risk_level: RiskLevel | None = None
    recent_asr: float | None = Field(default=None, ge=0.0, le=1.0)
    recent_fpr: float | None = Field(default=None, ge=0.0, le=1.0)
    latest_source: Literal["report", "metric_snapshot"] | None = None
    latest_evaluation_id: str | None = None
    latest_report_id: str | None = None
    latest_snapshot_id: str | None = None
    benchmark_id: str | None = None
    benchmark_version: str | None = None
    updated_at: str | None = None
    trend: list[DashboardTrendPoint] = Field(default_factory=list)


class AgentSecurityReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-security-report-v0.1"] = "agent-security-report-v0.1"
    tenant_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    benchmark: str = Field(min_length=1)
    benchmark_id: str | None = None
    benchmark_version: str | None = None
    evaluation_id: str | None = None
    status: ReportStatus = "complete"
    overall_score: int = Field(ge=0, le=100)
    risk_level: Literal["low", "medium", "high", "critical"]
    summary: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    scenario_results: list[ScenarioResult] = Field(default_factory=list)
    guard_effectiveness: dict[str, Any] = Field(default_factory=dict)
    false_positive_rate: float = Field(default=0.0, ge=0)
    attack_success_rate: float = Field(default=0.0, ge=0)
    defense_success_rate: float = Field(default=0.0, ge=0)
    deterministic_metrics: DeterministicMetrics | None = None
    score_breakdown: ScoreBreakdown | None = None
    business_impact: dict[str, Any] = Field(default_factory=dict)
    artifacts: ReportArtifacts


class LogSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["log-summary-v0.1"] = "log-summary-v0.1"
    evaluation_id: str = Field(min_length=1)
    tenant_id: str = Field(default="private_tenant", min_length=1)
    agent_id: str = Field(min_length=1)
    benchmark_version: str | None = None
    score: int | None = Field(default=None, ge=0, le=100)
    risk_level: RiskLevel | None = None
    asr: float | None = Field(default=None, ge=0.0, le=1.0)
    fpr: float | None = Field(default=None, ge=0.0, le=1.0)
    weakest_link: str | None = None
    evaluated_at: str | None = None
    status: EvaluationState


class LogDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["log-detail-v0.1"] = "log-detail-v0.1"
    summary: LogSummary
    metrics: DeterministicMetrics | None = None
    total_case_count: int = Field(default=0, ge=0)
    prompts: list[str] = Field(default_factory=list)
    rag_documents: list[str] = Field(default_factory=list)
    target_nodes: list[str] = Field(default_factory=list)
    bypassed_nodes: list[str] = Field(default_factory=list)
    critical_node_blocked: dict[str, bool] = Field(default_factory=dict)
    trajectory_refs: list[str] = Field(default_factory=list)


class ComparisonFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    severity: RiskLevel
    title: str = Field(min_length=1)
    status: FindingComparisonStatus
    recommendation: str = Field(min_length=1)


class ComparisonScenarioDelta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)
    before_passed: bool | None = None
    after_passed: bool | None = None
    before_decision: str | None = None
    after_decision: str | None = None
    status: ScenarioComparisonStatus


class ComparisonArtifacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    before_report_path: str = Field(min_length=1)
    after_report_path: str = Field(min_length=1)
    comparison_path: str = Field(min_length=1)
    markdown_path: str | None = None


class AgentSecurityComparisonReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-security-comparison-v0.1"] = "agent-security-comparison-v0.1"
    comparison_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    benchmark: str = Field(min_length=1)
    before_score: int = Field(ge=0, le=100)
    after_score: int = Field(ge=0, le=100)
    score_delta: int
    before_risk_level: RiskLevel
    after_risk_level: RiskLevel
    risk_level_change: str = Field(min_length=1)
    resolved_findings: list[ComparisonFinding] = Field(default_factory=list)
    new_findings: list[ComparisonFinding] = Field(default_factory=list)
    persisted_findings: list[ComparisonFinding] = Field(default_factory=list)
    scenario_deltas: list[ComparisonScenarioDelta] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    artifacts: ComparisonArtifacts
