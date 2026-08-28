from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


VerificationStatus = Literal["verified", "supported", "inferred", "rejected"]
ProfileNodeType = Literal[
    "external_input",
    "entrypoint",
    "agent",
    "sub_agent",
    "llm",
    "prompt",
    "router",
    "tool",
    "rag",
    "knowledge_base",
    "memory",
    "mcp",
    "external_api",
    "shell",
    "file",
    "browser",
    "database",
    "approval",
    "guard",
]
ProfileEdgeType = Literal["calls", "routes_to", "reads", "writes", "retrieves", "invokes", "controls", "sends_to"]
ProfileRiskLevel = Literal["low", "medium", "high", "critical"]
PermissionType = Literal["network", "file", "database", "shell", "browser", "external_api", "credential"]
ControlType = Literal[
    "parameter_validation",
    "allowlist",
    "authorization",
    "human_approval",
    "input_guard",
    "output_guard",
]
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"


class GraphContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceClaim(GraphContract):
    evidence_refs: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    verification_status: VerificationStatus

    @model_validator(mode="after")
    def evidence_refs_must_be_unique(self) -> EvidenceClaim:
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("evidence refs must be unique")
        return self


class FrameworkDetection(EvidenceClaim):
    framework_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    name: str = Field(min_length=1)
    version: str | None = Field(default=None, min_length=1)


class ProfileNode(EvidenceClaim):
    node_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    node_type: ProfileNodeType
    name: str = Field(min_length=1)
    framework_ids: list[str] = Field(default_factory=list)
    capability_ids: list[str] = Field(default_factory=list)
    permission_ids: list[str] = Field(default_factory=list)
    control_ids: list[str] = Field(default_factory=list)
    risk_level: ProfileRiskLevel = "low"


class ProfileEdge(EvidenceClaim):
    edge_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    edge_type: ProfileEdgeType
    source_node_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    target_node_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    condition: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def reject_self_edges(self) -> ProfileEdge:
        if self.source_node_id == self.target_node_id:
            raise ValueError("profile edge cannot connect a node to itself")
        return self


class ProfileCapability(EvidenceClaim):
    capability_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    name: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    node_ids: list[str] = Field(min_length=1)
    risk_level: ProfileRiskLevel = "low"


class ProfilePermission(EvidenceClaim):
    permission_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    permission_type: PermissionType
    operations: list[str] = Field(min_length=1)
    scope: str = Field(min_length=1)
    node_ids: list[str] = Field(min_length=1)
    capability_ids: list[str] = Field(default_factory=list)
    risk_level: ProfileRiskLevel = "low"


class SecurityControl(EvidenceClaim):
    control_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    control_type: ControlType
    name: str = Field(min_length=1)
    node_ids: list[str] = Field(min_length=1)
    description: str = Field(min_length=1)


class ProfileRiskPath(EvidenceClaim):
    path_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    source_node_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    sink_node_id: str = Field(min_length=1, pattern=_ID_PATTERN)
    node_ids: list[str] = Field(min_length=2)
    edge_ids: list[str] = Field(min_length=1)
    capability_ids: list[str] = Field(default_factory=list)
    permission_ids: list[str] = Field(default_factory=list)
    control_ids: list[str] = Field(default_factory=list)
    applicable_threats: list[str] = Field(min_length=1)
    control_gaps: list[str] = Field(default_factory=list)
    risk_level: ProfileRiskLevel

    @model_validator(mode="after")
    def validate_path_shape(self) -> ProfileRiskPath:
        if self.source_node_id != self.node_ids[0] or self.sink_node_id != self.node_ids[-1]:
            raise ValueError("risk path source and sink must match the ordered node path")
        if len(self.edge_ids) != len(self.node_ids) - 1:
            raise ValueError("risk path must contain one edge for each adjacent node pair")
        return self


class AnalysisLimitation(GraphContract):
    code: str = Field(min_length=1, pattern=_ID_PATTERN)
    message: str = Field(min_length=1)
    evidence_refs: list[str] = Field(default_factory=list)


__all__ = [
    "AnalysisLimitation",
    "ControlType",
    "EvidenceClaim",
    "FrameworkDetection",
    "PermissionType",
    "ProfileCapability",
    "ProfileEdge",
    "ProfileEdgeType",
    "ProfileNode",
    "ProfileNodeType",
    "ProfilePermission",
    "ProfileRiskPath",
    "ProfileRiskLevel",
    "SecurityControl",
    "VerificationStatus",
]
