from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

class SemanticModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


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
ProfileEdgeType = Literal[
    "calls",
    "routes_to",
    "reads",
    "writes",
    "retrieves",
    "invokes",
    "controls",
    "sends_to",
]


class GraphNode(SemanticModel):
    node_id: str = Field(min_length=1)
    node_type: ProfileNodeType
    name: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    labels: tuple[str, ...] = ()
    purpose: str | None = Field(default=None, min_length=1, max_length=500)

    @field_validator("evidence_refs", "labels")
    @classmethod
    def values_must_be_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("values must be unique")
        return values


class GraphRelation(SemanticModel):
    relation_id: str = Field(min_length=1)
    relation_type: ProfileEdgeType
    source_node_id: str = Field(min_length=1)
    target_node_id: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    verification_status: Literal["verified", "supported", "inferred", "rejected"]
    candidate: bool = False

    @model_validator(mode="after")
    def reject_self_relation(self) -> GraphRelation:
        if self.source_node_id == self.target_node_id:
            raise ValueError("graph relation cannot connect a node to itself")
        return self


class GraphFragment(SemanticModel):
    schema_version: Literal["graph-fragment-v0.1"] = "graph-fragment-v0.1"
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    nodes: tuple[GraphNode, ...] = ()
    relations: tuple[GraphRelation, ...] = ()
    evidence_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_references(self) -> GraphFragment:
        node_ids = [node.node_id for node in self.nodes]
        relation_ids = [relation.relation_id for relation in self.relations]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("graph node ids must be unique")
        if len(relation_ids) != len(set(relation_ids)):
            raise ValueError("graph relation ids must be unique")
        known_nodes = set(node_ids)
        known_evidence = set(self.evidence_ids)
        for node in self.nodes:
            if known_evidence and set(node.evidence_refs) - known_evidence:
                raise ValueError(f"node {node.node_id} references unknown graph evidence")
        for relation in self.relations:
            if {relation.source_node_id, relation.target_node_id} - known_nodes:
                raise ValueError(f"relation {relation.relation_id} references unknown nodes")
            if known_evidence and set(relation.evidence_refs) - known_evidence:
                raise ValueError(f"relation {relation.relation_id} references unknown graph evidence")
        return self


class NodeSemanticProposal(SemanticModel):
    node_id: str = Field(min_length=1)
    labels: tuple[str, ...] = Field(default=(), max_length=8)
    purpose: str | None = Field(default=None, min_length=1, max_length=500)
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @field_validator("labels")
    @classmethod
    def labels_must_be_non_blank_and_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() or len(value) > 80 for value in values):
            raise ValueError("labels must be non-blank and at most 80 characters")
        if len(values) != len(set(values)):
            raise ValueError("labels must be unique")
        return values

    @model_validator(mode="after")
    def require_semantic_change(self) -> NodeSemanticProposal:
        if not self.labels and self.purpose is None:
            raise ValueError("node semantic proposal must include labels or purpose")
        return self


class CandidateRelationProposal(SemanticModel):
    source_node_id: str = Field(min_length=1)
    target_node_id: str = Field(min_length=1)
    relation_type: ProfileEdgeType
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def reject_self_relation(self) -> CandidateRelationProposal:
        if self.source_node_id == self.target_node_id:
            raise ValueError("candidate relation cannot connect a node to itself")
        return self


class SemanticProposal(SemanticModel):
    schema_version: Literal["semantic-proposal-v0.1"] = "semantic-proposal-v0.1"
    node_updates: tuple[NodeSemanticProposal, ...] = ()
    candidate_relations: tuple[CandidateRelationProposal, ...] = ()

    @model_validator(mode="after")
    def proposals_must_be_unique(self) -> SemanticProposal:
        node_ids = [item.node_id for item in self.node_updates]
        relation_keys = [
            (item.source_node_id, item.target_node_id, item.relation_type)
            for item in self.candidate_relations
        ]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("node updates must be unique")
        if len(relation_keys) != len(set(relation_keys)):
            raise ValueError("candidate relations must be unique")
        return self


SemanticOutcome = Literal["accepted", "rejected", "skipped", "fallback"]


class SemanticCallEvidence(SemanticModel):
    schema_version: Literal["semantic-call-evidence-v0.1"] = "semantic-call-evidence-v0.1"
    provider_host: str = Field(min_length=1)
    model: str = Field(min_length=1)
    latency_ms: float = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    outcome: SemanticOutcome
    error: str | None = Field(default=None, max_length=500)


class SemanticEnrichmentResult(SemanticModel):
    outcome: SemanticOutcome
    graph: GraphFragment
    proposal: SemanticProposal | None = None
    call_evidence: SemanticCallEvidence | None = None
    error: str | None = Field(default=None, max_length=500)


__all__ = [
    "CandidateRelationProposal",
    "GraphFragment",
    "GraphNode",
    "GraphRelation",
    "NodeSemanticProposal",
    "SemanticCallEvidence",
    "SemanticEnrichmentResult",
    "SemanticOutcome",
    "SemanticProposal",
]
