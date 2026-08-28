from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from redsentinel.core.image_profile_graph import (
    AnalysisLimitation,
    ProfileCapability,
    ProfileEdge,
    ProfileNode,
    ProfilePermission,
    ProfileRiskPath,
    SecurityControl,
    VerificationStatus,
)
from redsentinel.core.profile_evidence import ProfileEvidence
from redsentinel.profiling.static_facts import SourceRecovery


SourceType = Literal[
    "user",
    "http",
    "cli",
    "message",
    "retrieval",
    "tool_result",
    "memory",
    "network",
]
SinkType = Literal[
    "llm_prompt",
    "shell",
    "file",
    "browser",
    "api",
    "database",
    "memory",
    "credential",
    "tool",
]


class DataflowModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DataflowSource(DataflowModel):
    source_id: str = Field(min_length=1)
    source_type: SourceType
    node_id: str = Field(min_length=1)
    module: str = Field(min_length=1)
    symbol: str = Field(min_length=1)
    expression: str = Field(min_length=1)
    evidence_refs: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    verification_status: VerificationStatus


class DataflowSink(DataflowModel):
    sink_id: str = Field(min_length=1)
    sink_type: SinkType
    node_id: str = Field(min_length=1)
    module: str = Field(min_length=1)
    symbol: str = Field(min_length=1)
    expression: str = Field(min_length=1)
    capability_id: str = Field(min_length=1)
    permission_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    verification_status: VerificationStatus


class WeakControlFact(DataflowModel):
    weak_control_id: str = Field(min_length=1)
    kind: Literal["normalization_only"] = "normalization_only"
    name: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    evidence_refs: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    verification_status: VerificationStatus


class UnresolvedFlow(DataflowModel):
    unresolved_id: str = Field(min_length=1)
    reason: Literal[
        "source_unavailable",
        "parse_error",
        "source_changed",
        "call_depth_exceeded",
        "ambiguous_project_call",
    ]
    module: str | None = Field(default=None, min_length=1)
    symbol: str | None = Field(default=None, min_length=1)
    source_type: SourceType | None = None
    sink_type: SinkType | None = None
    evidence_refs: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    verification_status: Literal["inferred"] = "inferred"


class DataflowAnalysisResult(DataflowModel):
    schema_version: Literal["dataflow-analysis-v0.1"] = "dataflow-analysis-v0.1"
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_recovery: SourceRecovery
    max_call_depth: int = Field(ge=1, le=3)
    sources: list[DataflowSource] = Field(default_factory=list)
    sinks: list[DataflowSink] = Field(default_factory=list)
    nodes: list[ProfileNode] = Field(default_factory=list)
    edges: list[ProfileEdge] = Field(default_factory=list)
    capabilities: list[ProfileCapability] = Field(default_factory=list)
    permissions: list[ProfilePermission] = Field(default_factory=list)
    controls: list[SecurityControl] = Field(default_factory=list)
    weak_controls: list[WeakControlFact] = Field(default_factory=list)
    risk_paths: list[ProfileRiskPath] = Field(default_factory=list)
    unresolved_flows: list[UnresolvedFlow] = Field(default_factory=list)
    evidence: list[ProfileEvidence] = Field(default_factory=list)
    limitations: list[AnalysisLimitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def references_must_resolve(self) -> DataflowAnalysisResult:
        evidence_ids = {item.evidence_id for item in self.evidence}
        node_ids = {item.node_id for item in self.nodes}
        edge_ids = {item.edge_id for item in self.edges}
        capability_ids = {item.capability_id for item in self.capabilities}
        permission_ids = {item.permission_id for item in self.permissions}
        control_ids = {item.control_id for item in self.controls}

        claims = [
            *self.sources,
            *self.sinks,
            *self.nodes,
            *self.edges,
            *self.capabilities,
            *self.permissions,
            *self.controls,
            *self.weak_controls,
            *self.risk_paths,
            *self.unresolved_flows,
        ]
        if any(set(item.evidence_refs) - evidence_ids for item in claims):
            raise ValueError("all dataflow claims must reference emitted evidence")
        if any(item.node_id not in node_ids for item in [*self.sources, *self.sinks, *self.weak_controls]):
            raise ValueError("source, sink, and weak-control nodes must exist")
        if any(item.capability_id not in capability_ids for item in self.sinks):
            raise ValueError("sink capabilities must exist")
        if any(set(item.permission_ids) - permission_ids for item in self.sinks):
            raise ValueError("sink permissions must exist")
        for path in self.risk_paths:
            if set(path.node_ids) - node_ids or set(path.edge_ids) - edge_ids:
                raise ValueError("risk path graph references must resolve")
            if set(path.capability_ids) - capability_ids:
                raise ValueError("risk path capabilities must resolve")
            if set(path.permission_ids) - permission_ids:
                raise ValueError("risk path permissions must resolve")
            if set(path.control_ids) - control_ids:
                raise ValueError("risk path controls must resolve")
        if any(item.verification_status == "verified" for item in claims):
            raise ValueError("static dataflow analysis cannot emit verified claims")
        return self


__all__ = [
    "DataflowAnalysisResult",
    "DataflowSink",
    "DataflowSource",
    "SinkType",
    "SourceType",
    "UnresolvedFlow",
    "WeakControlFact",
]
