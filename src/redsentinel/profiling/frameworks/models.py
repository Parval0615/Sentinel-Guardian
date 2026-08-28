from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from redsentinel.core.image_profile_graph import (
    AnalysisLimitation,
    FrameworkDetection,
    ProfileEdge,
    ProfileNode,
)
from redsentinel.core.profile_evidence import ProfileEvidence


class FrameworkModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FrameworkCandidate(FrameworkModel):
    framework_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str | None = Field(default=None, min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    signals: tuple[str, ...] = Field(min_length=1)
    selected: bool


class GraphFragment(FrameworkModel):
    framework: FrameworkDetection
    nodes: tuple[ProfileNode, ...] = ()
    edges: tuple[ProfileEdge, ...] = ()
    evidence: tuple[ProfileEvidence, ...] = Field(min_length=1)
    limitations: tuple[AnalysisLimitation, ...] = ()

    @model_validator(mode="after")
    def validate_evidence_and_graph(self) -> GraphFragment:
        evidence_ids = {item.evidence_id for item in self.evidence}
        claims = (self.framework, *self.nodes, *self.edges)
        if any(set(claim.evidence_refs) - evidence_ids for claim in claims):
            raise ValueError("framework fragment claims must reference fragment evidence")
        if any(set(item.evidence_refs) - evidence_ids for item in self.limitations):
            raise ValueError("framework fragment limitations must reference fragment evidence")
        node_ids = {node.node_id for node in self.nodes}
        if any(edge.source_node_id not in node_ids or edge.target_node_id not in node_ids for edge in self.edges):
            raise ValueError("framework fragment edges must reference fragment nodes")
        artifact_digests = {item.artifact_digest for item in self.evidence}
        if len(artifact_digests) != 1:
            raise ValueError("framework fragment evidence must bind to one artifact")
        return self


class MergedGraph(FrameworkModel):
    frameworks: tuple[FrameworkDetection, ...]
    nodes: tuple[ProfileNode, ...]
    edges: tuple[ProfileEdge, ...]
    evidence: tuple[ProfileEvidence, ...]
    limitations: tuple[AnalysisLimitation, ...]


class FrameworkAnalysis(FrameworkModel):
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    candidates: tuple[FrameworkCandidate, ...]
    frameworks: tuple[FrameworkDetection, ...]
    nodes: tuple[ProfileNode, ...]
    edges: tuple[ProfileEdge, ...]
    evidence: tuple[ProfileEvidence, ...]
    limitations: tuple[AnalysisLimitation, ...]

    @model_validator(mode="after")
    def validate_artifact_binding(self) -> FrameworkAnalysis:
        if any(item.artifact_digest != self.artifact_digest for item in self.evidence):
            raise ValueError("framework analysis evidence must bind to the static fact artifact")
        evidence_ids = {item.evidence_id for item in self.evidence}
        claims = (*self.frameworks, *self.nodes, *self.edges)
        if any(set(claim.evidence_refs) - evidence_ids for claim in claims):
            raise ValueError("framework analysis claims must reference analysis evidence")
        if any(set(candidate.evidence_refs) - evidence_ids for candidate in self.candidates):
            raise ValueError("framework candidates must reference analysis evidence")
        if any(set(item.evidence_refs) - evidence_ids for item in self.limitations):
            raise ValueError("framework analysis limitations must reference analysis evidence")
        return self


__all__ = ["FrameworkAnalysis", "FrameworkCandidate", "FrameworkModel", "GraphFragment", "MergedGraph"]
