from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from redsentinel.core.llm_gateway import JsonLLMGateway, JsonLLMResult, OpenAIJsonGateway
from redsentinel.profiling.semantic.models import (
    GraphFragment,
    GraphRelation,
    SemanticCallEvidence,
    SemanticEnrichmentResult,
    SemanticProposal,
)
from redsentinel.profiling.static_facts import StaticFactIndex


_MAX_TOKENS = 1600
_DEFAULT_CONTEXT_CHARS = 24_000
_SENSITIVE_KEY_RE = re.compile(
    r"(?:api[_-]?key|token|secret|password|passwd|pwd|credential|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIAL_RE = re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@")
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|credential)\b(\s*[:=]\s*)([^\s,;]+)"
)
_SYSTEM_PROMPT = (
    "Return one JSON object matching semantic-proposal-v0.1. You may only add labels or purpose "
    "to listed node_ids and propose candidate relations between listed nodes. Every item requires "
    "one or more listed evidence_refs. Do not create nodes, facts, permissions, controls, risks, "
    "or verified claims. No additional fields are allowed."
)


class SemanticConfigurationError(ValueError):
    pass


def semantic_gateway_from_environment(
    environment: Mapping[str, str] | None = None,
) -> JsonLLMGateway | None:
    env = os.environ if environment is None else environment
    names = (
        "RED_SENTINEL_SEMANTIC_API_KEY",
        "RED_SENTINEL_SEMANTIC_BASE_URL",
        "RED_SENTINEL_SEMANTIC_MODEL",
    )
    values = {name: str(env.get(name, "")).strip() for name in names}
    if not any(values.values()):
        return None
    missing = [name for name in names if not values[name]]
    if missing:
        raise SemanticConfigurationError(
            f"Incomplete semantic model configuration: {', '.join(missing)}"
        )
    raw_timeout = str(env.get("RED_SENTINEL_SEMANTIC_TIMEOUT_SECONDS", "30")).strip()
    try:
        timeout = float(raw_timeout)
    except ValueError as exc:
        raise SemanticConfigurationError(
            "RED_SENTINEL_SEMANTIC_TIMEOUT_SECONDS must be a number"
        ) from exc
    try:
        return OpenAIJsonGateway(
            api_key=values[names[0]],
            base_url=values[names[1]],
            model=values[names[2]],
            timeout_seconds=timeout,
        )
    except ValueError as exc:
        raise SemanticConfigurationError(str(exc)) from exc


def build_semantic_context(
    facts: StaticFactIndex,
    graph: GraphFragment,
    *,
    max_chars: int = _DEFAULT_CONTEXT_CHARS,
) -> str:
    if max_chars < 512:
        raise ValueError("max_chars must be at least 512")
    if facts.artifact_digest != graph.artifact_digest:
        raise ValueError("static facts and graph must bind to the same artifact")

    payload: dict[str, Any] = {
        "schema_version": "semantic-context-v0.1",
        "artifact_digest": facts.artifact_digest,
        "source_recovery": facts.source_recovery,
        "nodes": [
            {
                "node_id": _redact(node.node_id),
                "node_type": node.node_type,
                "name": _redact(node.name),
                "evidence_refs": list(node.evidence_refs),
            }
            for node in sorted(graph.nodes, key=lambda item: item.node_id)
        ],
        "relations": [
            {
                "relation_type": relation.relation_type,
                "source_node_id": relation.source_node_id,
                "target_node_id": relation.target_node_id,
                "evidence_refs": list(relation.evidence_refs),
            }
            for relation in sorted(graph.relations, key=lambda item: item.relation_id)
        ],
        "facts": [],
        "truncated": False,
    }
    fact_records = _minimal_fact_records(facts)
    for record in fact_records:
        payload["facts"].append(record)
        serialized = _compact_json(payload)
        if len(serialized) > max_chars:
            payload["facts"].pop()
            payload["truncated"] = True
            break
    serialized = _compact_json(payload)
    if len(serialized) > max_chars:
        payload["relations"] = []
        payload["truncated"] = True
        serialized = _compact_json(payload)
    if len(serialized) > max_chars:
        payload["nodes"] = []
        serialized = _compact_json(payload)
    if len(serialized) > max_chars:
        raise ValueError("max_chars is too small for semantic context metadata")
    return serialized


class SemanticEnricher:
    def __init__(
        self,
        gateway: JsonLLMGateway | None,
        *,
        max_context_chars: int = _DEFAULT_CONTEXT_CHARS,
    ) -> None:
        if max_context_chars < 512:
            raise ValueError("max_context_chars must be at least 512")
        self.gateway = gateway
        self.max_context_chars = max_context_chars

    def enrich(
        self,
        facts: StaticFactIndex,
        graph: GraphFragment,
    ) -> SemanticEnrichmentResult:
        if self.gateway is None:
            return SemanticEnrichmentResult(
                outcome="skipped",
                graph=graph,
                error="semantic model configuration is absent",
            )
        context = build_semantic_context(
            facts,
            graph,
            max_chars=self.max_context_chars,
        )
        prompt_hash = _sha256_text(f"{_SYSTEM_PROMPT}\n{context}")
        try:
            result = self.gateway.complete_json(
                system_prompt=_SYSTEM_PROMPT,
                user_prompt=context,
                max_tokens=_MAX_TOKENS,
            )
        except Exception as exc:
            error = _safe_error(exc)
            return SemanticEnrichmentResult(
                outcome="fallback",
                graph=graph,
                error=error,
            )

        if not result.ok or result.payload is None:
            error = _redact(result.error or "semantic model returned no JSON object")[:500]
            return SemanticEnrichmentResult(
                outcome="fallback",
                graph=graph,
                call_evidence=_call_evidence(result, prompt_hash, "fallback", error),
                error=error,
            )
        try:
            proposal = SemanticProposal.model_validate(result.payload)
            _validate_proposal(proposal, facts, graph)
            enriched = _merge_proposal(graph, proposal)
        except (ValidationError, ValueError) as exc:
            error = _safe_error(exc)
            return SemanticEnrichmentResult(
                outcome="rejected",
                graph=graph,
                call_evidence=_call_evidence(result, prompt_hash, "rejected", error),
                error=error,
            )
        return SemanticEnrichmentResult(
            outcome="accepted",
            graph=enriched,
            proposal=proposal,
            call_evidence=_call_evidence(result, prompt_hash, "accepted", None),
        )


def _minimal_fact_records(facts: StaticFactIndex) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    excluded = {"evidence", "fact_id", "is_sensitive", "command"}
    collections = (
        facts.modules,
        facts.symbols,
        facts.imports,
        facts.calls,
        facts.decorators,
        facts.class_bases,
        facts.dependencies,
        facts.entrypoints,
        facts.configuration,
        facts.capabilities,
        facts.limitations,
    )
    for collection in collections:
        for fact in collection:
            details = {
                key: _redact(value)
                for key, value in fact.model_dump(mode="json").items()
                if key not in excluded and value not in (None, "", [], {})
            }
            records.append(
                {
                    "fact_id": fact.fact_id,
                    "evidence_id": fact.evidence.evidence_id,
                    "kind": type(fact).__name__,
                    "details": details,
                }
            )
    return sorted(records, key=lambda item: (item["kind"], item["fact_id"]))


def _validate_proposal(
    proposal: SemanticProposal,
    facts: StaticFactIndex,
    graph: GraphFragment,
) -> None:
    known_nodes = {node.node_id for node in graph.nodes}
    known_evidence = {
        evidence.evidence_id
        for evidence in facts.all_evidence()
    } | set(graph.evidence_ids)
    graph_refs = {
        evidence_id
        for node in graph.nodes
        for evidence_id in node.evidence_refs
    } | {
        evidence_id
        for relation in graph.relations
        for evidence_id in relation.evidence_refs
    }
    unknown_graph_evidence = graph_refs - known_evidence
    if unknown_graph_evidence:
        raise ValueError(
            f"graph references unknown evidence ids: {sorted(unknown_graph_evidence)}"
        )
    for update in proposal.node_updates:
        if update.node_id not in known_nodes:
            raise ValueError(f"node update references unknown node: {update.node_id}")
        missing = set(update.evidence_refs) - known_evidence
        if missing:
            raise ValueError(f"node update references unknown evidence: {sorted(missing)}")
    for relation in proposal.candidate_relations:
        missing_nodes = {
            relation.source_node_id,
            relation.target_node_id,
        } - known_nodes
        if missing_nodes:
            raise ValueError(
                f"candidate relation references unknown nodes: {sorted(missing_nodes)}"
            )
        missing_evidence = set(relation.evidence_refs) - known_evidence
        if missing_evidence:
            raise ValueError(
                f"candidate relation references unknown evidence: {sorted(missing_evidence)}"
            )


def _merge_proposal(
    graph: GraphFragment,
    proposal: SemanticProposal,
) -> GraphFragment:
    updates = {item.node_id: item for item in proposal.node_updates}
    nodes = []
    for node in graph.nodes:
        update = updates.get(node.node_id)
        if update is None:
            nodes.append(node)
            continue
        labels = tuple(dict.fromkeys((*node.labels, *update.labels)))
        nodes.append(
            node.model_copy(
                update={
                    "labels": labels,
                    "purpose": update.purpose or node.purpose,
                }
            )
        )
    relations = list(graph.relations)
    existing = {
        (item.source_node_id, item.target_node_id, item.relation_type)
        for item in relations
    }
    for proposal_relation in proposal.candidate_relations:
        key = (
            proposal_relation.source_node_id,
            proposal_relation.target_node_id,
            proposal_relation.relation_type,
        )
        if key in existing:
            continue
        relation_id = "semantic:" + hashlib.sha256(
            "\x1f".join(key).encode("utf-8")
        ).hexdigest()[:20]
        relations.append(
            GraphRelation(
                relation_id=relation_id,
                relation_type=proposal_relation.relation_type,
                source_node_id=proposal_relation.source_node_id,
                target_node_id=proposal_relation.target_node_id,
                evidence_refs=proposal_relation.evidence_refs,
                verification_status="inferred",
                candidate=True,
            )
        )
        existing.add(key)
    return graph.model_copy(update={"nodes": tuple(nodes), "relations": tuple(relations)})


def _call_evidence(
    result: JsonLLMResult,
    prompt_hash: str,
    outcome: str,
    error: str | None,
) -> SemanticCallEvidence:
    response_hash = result.response_sha256
    if response_hash is None and result.payload is not None:
        response_hash = hashlib.sha256(
            _compact_json(result.payload).encode("utf-8")
        ).hexdigest()
    return SemanticCallEvidence(
        provider_host=result.provider_host,
        model=result.model,
        latency_ms=result.latency_ms,
        input_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        total_tokens=result.total_tokens,
        prompt_sha256=prompt_hash,
        response_sha256=response_hash,
        outcome=outcome,
        error=error,
    )


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        redacted = _BEARER_RE.sub("Bearer [REDACTED]", value)
        redacted = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", redacted)
        redacted = _ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", redacted)
        if _SENSITIVE_KEY_RE.fullmatch(redacted):
            return "[REDACTED]"
        return redacted
    if isinstance(value, list | tuple):
        return [_redact(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEY_RE.search(str(key)) else _redact(item)
            for key, item in value.items()
        }
    return value


def _safe_error(exc: Exception) -> str:
    return _redact(f"{type(exc).__name__}: {exc}")[:500]


def _compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = [
    "SemanticConfigurationError",
    "SemanticEnricher",
    "build_semantic_context",
    "semantic_gateway_from_environment",
]
