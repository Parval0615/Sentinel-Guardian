from __future__ import annotations

import json

import pytest

from redsentinel.application.engine.llm_gateway import JsonLLMResult
from redsentinel.core.profile_evidence import EvidenceLocator, ProfileEvidence
from redsentinel.profiling.semantic import (
    GraphFragment,
    GraphNode,
    SemanticConfigurationError,
    SemanticEnricher,
    build_semantic_context,
    semantic_gateway_from_environment,
)
from redsentinel.profiling.static_facts import StaticFactIndex, SymbolFact


IMAGE_DIGEST = f"sha256:{'a' * 64}"
CONTENT_SHA256 = "b" * 64


def _evidence(evidence_id: str, *, summary: str = "Agent entrypoint") -> ProfileEvidence:
    return ProfileEvidence(
        evidence_id=evidence_id,
        artifact_digest=IMAGE_DIGEST,
        locator=EvidenceLocator(
            image_path="/app/agent.py",
            python_module="agent",
            symbol="Agent.run",
            line_start=1,
            line_end=8,
        ),
        extractor="python_ast",
        method="static",
        content_sha256=CONTENT_SHA256,
        summary=summary,
    )


def _facts() -> StaticFactIndex:
    evidence = _evidence(
        "evidence:agent",
        summary="password=source-secret Bearer private-token",
    )
    return StaticFactIndex(
        artifact_digest=IMAGE_DIGEST,
        source_recovery="complete",
        symbols=[
            SymbolFact(
                fact_id="symbol:agent",
                evidence=evidence,
                module="agent",
                qualified_name="Agent.run",
                symbol_kind="function",
                line_start=1,
                line_end=8,
            )
        ],
    )


def _graph() -> GraphFragment:
    return GraphFragment(
        artifact_digest=IMAGE_DIGEST,
        evidence_ids=("evidence:agent",),
        nodes=(
            GraphNode(
                node_id="node:agent",
                node_type="agent",
                name="Agent Bearer private-token",
                evidence_refs=("evidence:agent",),
            ),
            GraphNode(
                node_id="node:tool",
                node_type="tool",
                name="Search",
                evidence_refs=("evidence:agent",),
            ),
        ),
    )


class _Gateway:
    def __init__(
        self,
        payload: dict[str, object] | None,
        *,
        ok: bool = True,
        error: str | None = None,
    ) -> None:
        self.payload = payload
        self.ok = ok
        self.error = error
        self.system_prompt = ""
        self.user_prompt = ""

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
    ) -> JsonLLMResult:
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        return JsonLLMResult(
            ok=self.ok,
            payload=self.payload,
            model="semantic-test",
            provider_host="model.example.test",
            latency_ms=12.5,
            response_sha256="c" * 64,
            provider_request_id="must-not-be-saved",
            prompt_tokens=30,
            completion_tokens=12,
            total_tokens=42,
            error=self.error,
        )


class _TimeoutGateway:
    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
    ) -> JsonLLMResult:
        raise TimeoutError("provider timed out with password=transport-secret")


def test_accepts_evidence_anchored_semantics_and_candidate_relation() -> None:
    gateway = _Gateway(
        {
            "schema_version": "semantic-proposal-v0.1",
            "node_updates": [
                {
                    "node_id": "node:agent",
                    "labels": ["orchestrator"],
                    "purpose": "Coordinates tool selection.",
                    "evidence_refs": ["evidence:agent"],
                }
            ],
            "candidate_relations": [
                {
                    "source_node_id": "node:agent",
                    "target_node_id": "node:tool",
                    "relation_type": "calls",
                    "evidence_refs": ["evidence:agent"],
                }
            ],
        }
    )

    result = SemanticEnricher(gateway).enrich(_facts(), _graph())

    assert result.outcome == "accepted"
    assert result.graph.nodes[0].labels == ("orchestrator",)
    assert result.graph.nodes[0].purpose == "Coordinates tool selection."
    assert len(result.graph.nodes) == 2
    assert len(result.graph.relations) == 1
    assert result.graph.relations[0].candidate is True
    assert result.graph.relations[0].verification_status == "inferred"
    assert result.call_evidence is not None
    assert result.call_evidence.total_tokens == 42
    evidence_payload = result.call_evidence.model_dump_json()
    assert "must-not-be-saved" not in evidence_payload
    assert "Coordinates tool selection" not in evidence_payload
    assert "user_prompt" not in evidence_payload


@pytest.mark.parametrize(
    "payload",
    [
        {
            "node_updates": [
                {
                    "node_id": "node:invented",
                    "labels": ["invented"],
                    "evidence_refs": ["evidence:agent"],
                }
            ]
        },
        {
            "candidate_relations": [
                {
                    "source_node_id": "node:agent",
                    "target_node_id": "node:tool",
                    "relation_type": "calls",
                    "evidence_refs": ["evidence:invented"],
                }
            ]
        },
        {
            "candidate_relations": [
                {
                    "source_node_id": "node:agent",
                    "target_node_id": "node:invented",
                    "relation_type": "calls",
                    "evidence_refs": ["evidence:agent"],
                }
            ]
        },
    ],
)
def test_rejects_nodes_or_relations_without_known_evidence(
    payload: dict[str, object],
) -> None:
    graph = _graph()

    result = SemanticEnricher(_Gateway(payload)).enrich(_facts(), graph)

    assert result.outcome == "rejected"
    assert result.graph == graph
    assert result.proposal is None
    assert result.call_evidence is not None
    assert result.call_evidence.outcome == "rejected"


def test_rejects_illegal_schema_and_preserves_graph() -> None:
    graph = _graph()
    gateway = _Gateway(
        {
            "node_updates": [
                {
                    "node_id": "node:agent",
                    "labels": ["agent"],
                    "evidence_refs": ["evidence:agent"],
                    "risk_level": "critical",
                }
            ],
            "new_nodes": [{"node_id": "node:invented"}],
        }
    )

    result = SemanticEnricher(gateway).enrich(_facts(), graph)

    assert result.outcome == "rejected"
    assert result.graph == graph
    assert "extra_forbidden" in (result.error or "")


def test_context_is_minimal_bounded_and_redacted() -> None:
    context = build_semantic_context(_facts(), _graph(), max_chars=1024)
    payload = json.loads(context)

    assert len(context) <= 1024
    assert "private-token" not in context
    assert "source-secret" not in context
    assert "Agent entrypoint" not in context
    assert "content_sha256" not in context
    assert "[REDACTED]" in context
    assert payload["nodes"][0]["node_id"] == "node:agent"
    assert payload["facts"][0]["evidence_id"] == "evidence:agent"


def test_timeout_returns_deterministic_fallback_without_mutating_graph() -> None:
    graph = _graph()

    result = SemanticEnricher(_TimeoutGateway()).enrich(_facts(), graph)

    assert result.outcome == "fallback"
    assert result.graph == graph
    assert result.call_evidence is None
    assert "transport-secret" not in (result.error or "")
    assert "[REDACTED]" in (result.error or "")


def test_failed_gateway_keeps_only_sanitized_call_metadata() -> None:
    graph = _graph()
    gateway = _Gateway(
        None,
        ok=False,
        error="HTTP timeout password=provider-secret",
    )

    result = SemanticEnricher(gateway).enrich(_facts(), graph)

    assert result.outcome == "fallback"
    assert result.graph == graph
    assert result.call_evidence is not None
    serialized = result.call_evidence.model_dump_json()
    assert "provider-secret" not in serialized
    assert "private-token" not in serialized
    assert "prompt" not in serialized.replace("prompt_sha256", "")


def test_missing_configuration_skips_without_calling_model() -> None:
    graph = _graph()

    gateway = semantic_gateway_from_environment({})
    result = SemanticEnricher(gateway).enrich(_facts(), graph)

    assert gateway is None
    assert result.outcome == "skipped"
    assert result.graph == graph
    assert result.call_evidence is None


@pytest.mark.parametrize(
    "environment",
    [
        {"RED_SENTINEL_SEMANTIC_API_KEY": "key"},
        {
            "RED_SENTINEL_SEMANTIC_API_KEY": "key",
            "RED_SENTINEL_SEMANTIC_BASE_URL": "https://model.example.test/v1",
        },
        {"RED_SENTINEL_SEMANTIC_MODEL": "model"},
    ],
)
def test_partial_configuration_is_rejected(environment: dict[str, str]) -> None:
    with pytest.raises(SemanticConfigurationError, match="Incomplete"):
        semantic_gateway_from_environment(environment)
