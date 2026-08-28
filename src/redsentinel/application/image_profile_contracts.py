from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from redsentinel.core.profile_evidence import EvidenceLocator, ProfileEvidence  # noqa: F401 - compatibility re-export
from redsentinel.core.image_profile_graph import (
    AnalysisLimitation,
    EvidenceClaim,
    FrameworkDetection,
    ProfileCapability,
    ProfileEdge,
    ProfileNode,
    ProfilePermission,
    ProfileRiskPath,
    SecurityControl,
)
from redsentinel.core.image_profile_graph import (
    ControlType,  # noqa: F401 - compatibility re-export
    PermissionType,  # noqa: F401 - compatibility re-export
    ProfileEdgeType,  # noqa: F401 - compatibility re-export
    ProfileNodeType,  # noqa: F401 - compatibility re-export
    ProfileRiskLevel,  # noqa: F401 - compatibility re-export
    VerificationStatus,  # noqa: F401 - compatibility re-export
)


ImageType = Literal["docker_archive", "oci_layout"]
AnalysisStageName = Literal[
    "inventory",
    "unpack",
    "static_extract",
    "framework_detect",
    "graph_reconstruct",
    "semantic_enrich",
    "dynamic_verify",
    "finalize",
]
AnalysisStageStatus = Literal["pending", "running", "completed", "failed", "skipped"]
AnalysisOverallStatus = Literal["queued", "running", "completed", "partial", "failed"]
ProfileCompletenessConclusion = Literal["complete", "partial"]
StaticSourceRecovery = Literal["complete", "partial", "metadata_only", "bytecode_only", "none"]
ANALYSIS_STAGE_ORDER: tuple[AnalysisStageName, ...] = (
    "inventory",
    "unpack",
    "static_extract",
    "framework_detect",
    "graph_reconstruct",
    "semantic_enrich",
    "dynamic_verify",
    "finalize",
)
_DIRECT_EVIDENCE_METHODS = {"image_config", "package_metadata", "static", "framework"}
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"
_DEFAULT_PROFILE_CONFIGURATION_DIGEST = "sha256:ebe69d0544ff05e2508f3018392eda081bda6c7bf4277186aa90a4e60eb869a3"


class ImageProfileContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _require_unique(values: list[str], label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return values


def _validate_relative_artifact_path(value: str) -> str:
    if "\\" in value:
        raise ValueError("image path must use POSIX separators")
    path = PurePosixPath(value)
    if path.is_absolute() or value in {"", "."} or ".." in path.parts:
        raise ValueError("image path must be a non-empty relative path without traversal")
    if str(path) != value:
        raise ValueError("image path must be normalized")
    return value


class ImageReference(ImageProfileContract):
    type: ImageType
    path: str = Field(min_length=1)
    digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _validate_relative_artifact_path(value)


class DynamicRuntimeRequirements(ImageProfileContract):
    requires_privileged: bool = False
    required_host_mounts: list[str] = Field(default_factory=list)
    probe_module: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$",
    )

    @field_validator("required_host_mounts")
    @classmethod
    def host_mounts_must_be_unique_absolute_paths(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("required host mounts must be unique")
        if any(not value.startswith("/") or "\x00" in value for value in values):
            raise ValueError("required host mounts must be absolute paths")
        return values


DYNAMIC_PROBE_PROTOCOL_VERSION = "behavior-v0.1"


class AgentDirectoryDescriptor(ImageProfileContract):
    schema_version: Literal["agent-directory-v0.1"] = "agent-directory-v0.1"
    agent_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    name: str = Field(min_length=1)
    image: ImageReference
    platform: str | None = Field(default=None, min_length=1)
    runtime: DynamicRuntimeRequirements = Field(default_factory=DynamicRuntimeRequirements)
    expected_frameworks: list[str] = Field(default_factory=list)
    notes: str | None = Field(default=None, min_length=1)

    @field_validator("expected_frameworks")
    @classmethod
    def framework_names_must_be_unique(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("expected framework names must not be blank")
        return _require_unique(values, "expected framework names")


def profile_configuration_digest(descriptor: AgentDirectoryDescriptor) -> str:
    payload = {
        "expected_frameworks": sorted(descriptor.expected_frameworks),
        "dynamic_probe_protocol": DYNAMIC_PROBE_PROTOCOL_VERSION,
        "platform": descriptor.platform,
        "probe_module": descriptor.runtime.probe_module,
        "required_host_mounts": sorted(descriptor.runtime.required_host_mounts),
        "requires_privileged": descriptor.runtime.requires_privileged,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def profile_version_digest(image_digest: str, configuration_digest: str) -> str:
    canonical = json.dumps(
        {
            "configuration_digest": configuration_digest,
            "image_digest": image_digest,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


class AnalysisError(ImageProfileContract):
    error_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    stage: AnalysisStageName
    code: str = Field(min_length=1, pattern=_ID_PATTERN)
    message: str = Field(min_length=1)
    retryable: bool = False
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class AnalysisStageState(ImageProfileContract):
    stage: AnalysisStageName
    status: AnalysisStageStatus = "pending"
    started_at: str | None = Field(default=None, min_length=1)
    completed_at: str | None = Field(default=None, min_length=1)
    checkpoint_ref: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def timestamps_match_status(self) -> AnalysisStageState:
        if self.status == "pending" and (self.started_at or self.completed_at):
            raise ValueError("pending stage cannot have timestamps")
        if self.status == "running" and not self.started_at:
            raise ValueError("running stage requires started_at")
        if self.status in {"completed", "failed", "skipped"} and not self.completed_at:
            raise ValueError(f"{self.status} stage requires completed_at")
        return self


def _default_analysis_stages() -> list[AnalysisStageState]:
    return [AnalysisStageState(stage=stage) for stage in ANALYSIS_STAGE_ORDER]


class ImageAnalysisStatus(ImageProfileContract):
    schema_version: Literal["image-analysis-status-v0.1"] = "image-analysis-status-v0.1"
    analysis_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    agent_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    image_digest: str = Field(pattern=_DIGEST_PATTERN)
    configuration_digest: str = Field(
        default=_DEFAULT_PROFILE_CONFIGURATION_DIGEST,
        pattern=_DIGEST_PATTERN,
    )
    status: AnalysisOverallStatus = "queued"
    stages: list[AnalysisStageState] = Field(default_factory=_default_analysis_stages)
    errors: list[AnalysisError] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_stage_machine(self) -> ImageAnalysisStatus:
        if tuple(stage.stage for stage in self.stages) != ANALYSIS_STAGE_ORDER:
            raise ValueError("analysis stages must contain the canonical eight stages in order")
        _require_unique([error.error_id for error in self.errors], "analysis error ids")
        if sum(stage.status == "running" for stage in self.stages) > 1:
            raise ValueError("only one analysis stage may be running")

        failed_stages = {stage.stage for stage in self.stages if stage.status == "failed"}
        error_stages = {error.stage for error in self.errors}
        if failed_stages != error_stages:
            raise ValueError("failed stages and analysis errors must match")
        if self.status == "queued" and any(stage.status != "pending" for stage in self.stages):
            raise ValueError("queued analysis requires all stages to be pending")
        if self.status == "running" and not any(stage.status == "running" for stage in self.stages):
            raise ValueError("running analysis requires one running stage")
        if self.status == "completed" and any(stage.status not in {"completed", "skipped"} for stage in self.stages):
            raise ValueError("completed analysis cannot contain pending, running, or failed stages")
        if self.status == "partial":
            if self.stages[-1].status != "completed":
                raise ValueError("partial analysis requires a completed finalize stage")
        if self.status == "failed" and not failed_stages:
            raise ValueError("failed analysis requires a failed stage")
        return self


class CoverageStatistic(ImageProfileContract):
    covered: int = Field(ge=0)
    total: int = Field(ge=0)
    ratio: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_counts(self) -> CoverageStatistic:
        if self.covered > self.total:
            raise ValueError("coverage cannot exceed total")
        expected = self.covered / self.total if self.total else 0.0
        if abs(self.ratio - expected) > 1e-9:
            raise ValueError("coverage ratio must match covered and total")
        return self


class ProfileCompleteness(ImageProfileContract):
    static_source_recovery: StaticSourceRecovery
    framework_coverage: CoverageStatistic
    graph_evidence_coverage: CoverageStatistic
    dynamic_corroboration_coverage: CoverageStatistic
    dynamic_behavior_coverage: CoverageStatistic
    unresolved_limitations: int = Field(ge=0)
    blocking_limitations: list[str] = Field(default_factory=list)
    conclusion: ProfileCompletenessConclusion

    @field_validator("blocking_limitations")
    @classmethod
    def blocking_limitation_codes_must_be_unique(cls, values: list[str]) -> list[str]:
        return _require_unique(values, "blocking limitation codes")

    @model_validator(mode="after")
    def complete_requires_all_gates(self) -> ProfileCompleteness:
        if self.conclusion == "complete":
            if self.static_source_recovery != "complete":
                raise ValueError("complete profile requires complete static source recovery")
            if self.framework_coverage.covered < self.framework_coverage.total:
                raise ValueError("complete profile requires full framework coverage")
            if self.graph_evidence_coverage.covered < self.graph_evidence_coverage.total:
                raise ValueError("complete profile requires full graph evidence coverage")
            if self.dynamic_corroboration_coverage.covered < 1:
                raise ValueError("complete profile requires dynamic corroboration")
            if (
                self.dynamic_behavior_coverage.total < 1
                or self.dynamic_behavior_coverage.covered < self.dynamic_behavior_coverage.total
            ):
                raise ValueError("complete profile requires full dynamic behavior coverage")
            if self.blocking_limitations:
                raise ValueError("complete profile cannot have blocking limitations")
        return self


class ImageIdentity(EvidenceClaim):
    digest: str = Field(pattern=_DIGEST_PATTERN)
    os: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    variant: str | None = Field(default=None, min_length=1)
    created_at: str | None = Field(default=None, min_length=1)
    entrypoint: list[str] = Field(default_factory=list)
    command: list[str] = Field(default_factory=list)
    working_directory: str = Field(default="/", min_length=1)
    environment_variables: list[str] = Field(default_factory=list)
    layer_digests: list[str] = Field(default_factory=list)

    @field_validator("environment_variables")
    @classmethod
    def environment_variable_names_must_be_unique(cls, values: list[str]) -> list[str]:
        if any(not value or "=" in value for value in values):
            raise ValueError("environment_variables may contain names only")
        return _require_unique(values, "environment variable names")

    @field_validator("layer_digests")
    @classmethod
    def layer_digests_must_be_valid_and_unique(cls, values: list[str]) -> list[str]:
        for value in values:
            if len(value) != 71 or not value.startswith("sha256:"):
                raise ValueError("layer digest must be a sha256 digest")
            try:
                int(value[7:], 16)
            except ValueError as exc:
                raise ValueError("layer digest must be a sha256 digest") from exc
        return _require_unique(values, "layer digests")


def _index_unique(items: list[object], attribute: str, label: str) -> dict[str, object]:
    values = [getattr(item, attribute) for item in items]
    _require_unique(values, label)
    return dict(zip(values, items, strict=True))


def _validate_claim_evidence(claim: EvidenceClaim, evidence: dict[str, ProfileEvidence], label: str) -> None:
    missing = set(claim.evidence_refs) - evidence.keys()
    if missing:
        raise ValueError(f"{label} references unknown evidence: {sorted(missing)}")
    referenced = [evidence[ref] for ref in claim.evidence_refs]
    methods = {item.method for item in referenced}
    static_extractors = {item.extractor for item in referenced if item.method in _DIRECT_EVIDENCE_METHODS}
    if claim.verification_status == "verified":
        corroborated = "dynamic" in methods and bool(methods & _DIRECT_EVIDENCE_METHODS)
        if not corroborated and len(static_extractors) < 2:
            raise ValueError(f"{label} verified status requires dynamic corroboration or two static extractors")
    if claim.verification_status == "supported" and not methods.intersection(_DIRECT_EVIDENCE_METHODS | {"dynamic"}):
        raise ValueError(f"{label} supported status requires direct static, framework, or dynamic evidence")


def _validate_graph(
    *,
    image: ImageIdentity,
    frameworks: list[FrameworkDetection],
    nodes: list[ProfileNode],
    edges: list[ProfileEdge],
    capabilities: list[ProfileCapability],
    permissions: list[ProfilePermission],
    controls: list[SecurityControl],
    risk_paths: list[ProfileRiskPath],
    evidence_items: list[ProfileEvidence],
    limitations: list[AnalysisLimitation],
) -> None:
    evidence = _index_unique(evidence_items, "evidence_id", "evidence ids")
    framework_index = _index_unique(frameworks, "framework_id", "framework ids")
    node_index = _index_unique(nodes, "node_id", "node ids")
    edge_index = _index_unique(edges, "edge_id", "edge ids")
    capability_index = _index_unique(capabilities, "capability_id", "capability ids")
    permission_index = _index_unique(permissions, "permission_id", "permission ids")
    control_index = _index_unique(controls, "control_id", "control ids")
    _index_unique(risk_paths, "path_id", "risk path ids")

    claims: list[tuple[str, EvidenceClaim]] = [("image identity", image)]
    claims.extend((f"framework {item.framework_id}", item) for item in frameworks)
    claims.extend((f"node {item.node_id}", item) for item in nodes)
    claims.extend((f"edge {item.edge_id}", item) for item in edges)
    claims.extend((f"capability {item.capability_id}", item) for item in capabilities)
    claims.extend((f"permission {item.permission_id}", item) for item in permissions)
    claims.extend((f"control {item.control_id}", item) for item in controls)
    claims.extend((f"risk path {item.path_id}", item) for item in risk_paths)
    for label, claim in claims:
        _validate_claim_evidence(claim, evidence, label)

    for limitation in limitations:
        missing = set(limitation.evidence_refs) - evidence.keys()
        if missing:
            raise ValueError(f"limitation {limitation.code} references unknown evidence: {sorted(missing)}")
    for edge in edges:
        if edge.source_node_id not in node_index or edge.target_node_id not in node_index:
            raise ValueError(f"edge {edge.edge_id} references unknown nodes")
    for capability in capabilities:
        if set(capability.node_ids) - node_index.keys():
            raise ValueError(f"capability {capability.capability_id} references unknown nodes")
    for permission in permissions:
        if set(permission.node_ids) - node_index.keys():
            raise ValueError(f"permission {permission.permission_id} references unknown nodes")
        if set(permission.capability_ids) - capability_index.keys():
            raise ValueError(f"permission {permission.permission_id} references unknown capabilities")
    for control in controls:
        if set(control.node_ids) - node_index.keys():
            raise ValueError(f"control {control.control_id} references unknown nodes")
    for node in nodes:
        if set(node.framework_ids) - framework_index.keys():
            raise ValueError(f"node {node.node_id} references unknown frameworks")
        if set(node.capability_ids) - capability_index.keys():
            raise ValueError(f"node {node.node_id} references unknown capabilities")
        if set(node.permission_ids) - permission_index.keys():
            raise ValueError(f"node {node.node_id} references unknown permissions")
        if set(node.control_ids) - control_index.keys():
            raise ValueError(f"node {node.node_id} references unknown controls")
    for path in risk_paths:
        if set(path.node_ids) - node_index.keys():
            raise ValueError(f"risk path {path.path_id} references unknown nodes")
        if set(path.edge_ids) - edge_index.keys():
            raise ValueError(f"risk path {path.path_id} references unknown edges")
        if set(path.capability_ids) - capability_index.keys():
            raise ValueError(f"risk path {path.path_id} references unknown capabilities")
        if set(path.permission_ids) - permission_index.keys():
            raise ValueError(f"risk path {path.path_id} references unknown permissions")
        if set(path.control_ids) - control_index.keys():
            raise ValueError(f"risk path {path.path_id} references unknown controls")
        for index, edge_id in enumerate(path.edge_ids):
            edge = edge_index[edge_id]
            if edge.source_node_id != path.node_ids[index] or edge.target_node_id != path.node_ids[index + 1]:
                raise ValueError(f"risk path {path.path_id} edge order does not match node order")


class ImageAgentProfile(ImageProfileContract):
    schema_version: Literal["agent-profile-v0.2"] = "agent-profile-v0.2"
    profile_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    tenant_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    generated_at: str = Field(min_length=1)
    image: ImageIdentity
    analysis: ImageAnalysisStatus
    frameworks: list[FrameworkDetection] = Field(default_factory=list)
    nodes: list[ProfileNode] = Field(default_factory=list)
    edges: list[ProfileEdge] = Field(default_factory=list)
    capabilities: list[ProfileCapability] = Field(default_factory=list)
    permissions: list[ProfilePermission] = Field(default_factory=list)
    controls: list[SecurityControl] = Field(default_factory=list)
    evidence: list[ProfileEvidence] = Field(min_length=1)
    risk_paths: list[ProfileRiskPath] = Field(default_factory=list)
    limitations: list[AnalysisLimitation] = Field(default_factory=list)
    completeness: ProfileCompleteness | None = None

    @model_validator(mode="after")
    def validate_profile_consistency(self) -> ImageAgentProfile:
        if self.agent_id != self.analysis.agent_id or self.image.digest != self.analysis.image_digest:
            raise ValueError("profile identity must match analysis identity")
        if self.completeness is not None:
            expected_status = "completed" if self.completeness.conclusion == "complete" else "partial"
            if self.analysis.status != expected_status:
                raise ValueError("analysis status must match completeness conclusion")
            dynamic_stage = next(item for item in self.analysis.stages if item.stage == "dynamic_verify")
            if self.completeness.conclusion == "complete" and dynamic_stage.status != "completed":
                raise ValueError("complete profile requires successful dynamic verification")
            if self.completeness.unresolved_limitations != len(self.limitations):
                raise ValueError("unresolved limitation count must match profile limitations")
        if any(item.artifact_digest != self.image.digest for item in self.evidence):
            raise ValueError("all profile evidence must bind to the profile image digest")
        _validate_graph(
            image=self.image,
            frameworks=self.frameworks,
            nodes=self.nodes,
            edges=self.edges,
            capabilities=self.capabilities,
            permissions=self.permissions,
            controls=self.controls,
            risk_paths=self.risk_paths,
            evidence_items=self.evidence,
            limitations=self.limitations,
        )
        if self.completeness is not None:
            evidence_index = {item.evidence_id: item for item in self.evidence}
            structural_claims = [*self.nodes, *self.edges, *self.controls]
            static_claims = [
                claim
                for claim in structural_claims
                if {evidence_index[ref].method for ref in claim.evidence_refs} & _DIRECT_EVIDENCE_METHODS
            ]
            required_claim_ids = dynamic_required_claim_ids(self)
            required_claims = [claim for claim in static_claims if _claim_id(claim) in required_claim_ids]
            corroborated = sum(_has_observed_dynamic_behavior(claim, evidence_index) for claim in required_claims)
            if self.completeness.graph_evidence_coverage.covered != len(static_claims):
                raise ValueError("graph evidence coverage must match profile evidence")
            if (
                self.completeness.dynamic_corroboration_coverage.covered != corroborated
                or self.completeness.dynamic_corroboration_coverage.total != len(required_claims)
            ):
                raise ValueError("dynamic corroboration coverage must match profile evidence")
            if self.completeness.conclusion == "complete":
                dynamic_event_types = {
                    (item.summary or "").partition(":")[0] for item in self.evidence if item.method == "dynamic"
                }
                required_behavior_events = {
                    "invocation_started",
                    "agent_invoked",
                    "output_observed",
                    "invocation_completed",
                }
                if not required_behavior_events <= dynamic_event_types:
                    raise ValueError("complete profile requires the dynamic behavior protocol")
                coverage_targets = {
                    (item.summary or "").partition(":")[2].strip().casefold()
                    for item in self.evidence
                    if item.method == "dynamic" and (item.summary or "").startswith("coverage_target:")
                }
                observed_targets = {
                    (item.summary or "").partition(":")[2].strip().casefold()
                    for item in self.evidence
                    if item.method == "dynamic"
                    and item.trust_level == "observed"
                    and (item.summary or "").partition(":")[0] in {"agent_invoked", "tool_called", "guard_decision"}
                }
                if self.completeness.dynamic_behavior_coverage.covered != len(
                    coverage_targets & observed_targets
                ) or self.completeness.dynamic_behavior_coverage.total != len(coverage_targets):
                    raise ValueError("dynamic behavior coverage must match profile evidence")
                if not coverage_targets or not coverage_targets <= observed_targets:
                    raise ValueError("complete profile requires observed dynamic coverage targets")
                if not required_claims or corroborated != len(required_claims):
                    raise ValueError(
                        "complete profile requires observed dynamic corroboration for every critical claim"
                    )
        return self


def dynamic_required_claim_ids(profile: ImageAgentProfile) -> set[str]:
    required = {
        node.node_id
        for node in profile.nodes
        if node.node_type in {"agent", "tool", "mcp", "guard"}
    }
    required.update(control.control_id for control in profile.controls)
    return required


def _claim_id(claim: EvidenceClaim) -> str:
    for attribute in ("node_id", "edge_id", "control_id"):
        value = getattr(claim, attribute, None)
        if value is not None:
            return str(value)
    raise TypeError("unsupported dynamic claim type")


def _has_observed_dynamic_behavior(
    claim: EvidenceClaim,
    evidence_index: dict[str, ProfileEvidence],
) -> bool:
    return any(
        evidence_index[ref].method == "dynamic"
        and evidence_index[ref].trust_level == "observed"
        and (evidence_index[ref].summary or "").partition(":")[0] in {"agent_invoked", "tool_called", "guard_decision"}
        for ref in claim.evidence_refs
    )


class AttackProfile(ImageProfileContract):
    schema_version: Literal["attack-profile-v0.1"] = "attack-profile-v0.1"
    attack_profile_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    source_profile_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    source_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    tenant_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    image: ImageIdentity
    generated_at: str = Field(min_length=1)
    include_inferred: bool = False
    frameworks: list[FrameworkDetection] = Field(default_factory=list)
    nodes: list[ProfileNode] = Field(min_length=1)
    edges: list[ProfileEdge] = Field(default_factory=list)
    capabilities: list[ProfileCapability] = Field(default_factory=list)
    permissions: list[ProfilePermission] = Field(default_factory=list)
    controls: list[SecurityControl] = Field(default_factory=list)
    evidence: list[ProfileEvidence] = Field(min_length=1)
    risk_paths: list[ProfileRiskPath] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_attack_handoff(self) -> AttackProfile:
        _validate_graph(
            image=self.image,
            frameworks=self.frameworks,
            nodes=self.nodes,
            edges=self.edges,
            capabilities=self.capabilities,
            permissions=self.permissions,
            controls=self.controls,
            risk_paths=self.risk_paths,
            evidence_items=self.evidence,
            limitations=[],
        )
        claims: list[EvidenceClaim] = [
            self.image,
            *self.frameworks,
            *self.nodes,
            *self.edges,
            *self.capabilities,
            *self.permissions,
            *self.controls,
            *self.risk_paths,
        ]
        if not self.include_inferred and any(claim.verification_status == "inferred" for claim in claims):
            raise ValueError("attack profile requires include_inferred=true for inferred claims")
        if any(
            path.verification_status == "inferred" and path.risk_level in {"high", "critical"}
            for path in self.risk_paths
        ):
            raise ValueError("inferred risk paths cannot trigger high-impact attacks")
        if any(item.artifact_digest != self.image.digest for item in self.evidence):
            raise ValueError("all attack evidence must bind to the attack image digest")
        return self


class AttackProfileNotApplicable(ImageProfileContract):
    schema_version: Literal["attack-profile-build-v0.1"] = "attack-profile-build-v0.1"
    status: Literal["not_applicable"] = "not_applicable"
    source_profile_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    reason: str = Field(min_length=1)
