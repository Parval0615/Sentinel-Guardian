from __future__ import annotations

import shutil
from pathlib import Path

from redsentinel.application.image_profile_contracts import FrameworkDetection, ProfileEdge, ProfileNode
from redsentinel.core.profile_evidence import EvidenceLocator, ProfileEvidence
from redsentinel.profiling.frameworks import GraphFragment, analyze_frameworks, merge_graph_fragments
from redsentinel.profiling.static_facts import extract_static_facts


FIXTURES = Path(__file__).parents[2] / "fixtures" / "profiling" / "frameworks"


def _index_from_fixture(tmp_path: Path, *names: str):
    root = tmp_path / "rootfs"
    root.mkdir()
    for name in names:
        shutil.copyfile(FIXTURES / name, root / name)
    return extract_static_facts(root)


def test_detects_mixed_langgraph_and_langchain_and_reconstructs_graph(tmp_path: Path) -> None:
    index = _index_from_fixture(tmp_path, "mixed_langgraph_langchain.py")

    first = analyze_frameworks(index)
    second = analyze_frameworks(index)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert {framework.framework_id for framework in first.frameworks} == {"langchain", "langgraph"}
    assert all(framework.verification_status == "supported" for framework in first.frameworks)
    node_by_name = {node.name: node for node in first.nodes}
    assert node_by_name["search"].node_type == "tool"
    assert node_by_name["model"].node_type == "llm"
    assert {"prompt", "memory", "rag"} <= {node.node_type for node in first.nodes}
    assert {"prompt", "memory", "rag"} <= {node.node_type for node in first.nodes}
    assert {"prompt", "memory", "rag"} <= {node.node_type for node in first.nodes}
    assert {"prompt", "memory", "rag"} <= {node.node_type for node in first.nodes}
    assert any(
        edge.edge_type == "routes_to"
        and edge.condition == "route"
        and first.nodes
        for edge in first.edges
    )
    assert any(edge.condition == "done" for edge in first.edges)
    assert any(edge.condition == "retry" for edge in first.edges)
    assert any(edge.edge_type == "invokes" and edge.target_node_id == node_by_name["search"].node_id for edge in first.edges)
    evidence_ids = {item.evidence_id for item in first.evidence}
    assert all(set(claim.evidence_refs) <= evidence_ids for claim in (*first.frameworks, *first.nodes, *first.edges))
    assert all(item.artifact_digest == index.artifact_digest for item in first.evidence)
    assert all(item.method == "framework" for item in first.evidence)


def test_openmanus_reconstructs_agents_tools_mcp_planning_approval_and_llm(tmp_path: Path) -> None:
    index = _index_from_fixture(tmp_path, "openmanus.py")

    result = analyze_frameworks(index)

    assert {framework.framework_id for framework in result.frameworks} == {"openmanus"}
    node_types = {node.node_type for node in result.nodes}
    assert {"agent", "tool", "mcp", "router", "approval", "llm"} <= node_types
    assert any(node.name == "SearchTool" and node.risk_level == "high" for node in result.nodes)
    assert any(node.node_type == "mcp" and node.risk_level == "high" for node in result.nodes)
    assert any(edge.edge_type == "controls" for edge in result.edges)
    assert any(edge.edge_type == "routes_to" for edge in result.edges)


def test_basic_framework_candidates_preserve_dependency_versions(tmp_path: Path) -> None:
    index = _index_from_fixture(tmp_path, "requirements.txt")

    result = analyze_frameworks(index)

    frameworks = {item.framework_id: item for item in result.frameworks}
    assert frameworks["crewai"].version == "==0.102.0"
    assert frameworks["autogen"].version == "==0.4.7"
    assert frameworks["mcp"].version == "==1.2.0"
    assert {item.code for item in result.limitations} == {"framework_adapter_shallow"}


def test_custom_fallback_uses_only_static_index_and_reports_limitation(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "agent.py").write_text("class LocalAgent:\\n    pass\\n", encoding="utf-8")
    index = extract_static_facts(root)

    result = analyze_frameworks(index)

    assert [item.framework_id for item in result.frameworks] == ["custom"]
    assert result.frameworks[0].confidence == 0.5
    assert any(item.code == "unsupported_framework" for item in result.limitations)
    assert all(item.artifact_digest == index.artifact_digest for item in result.evidence)


def _evidence(evidence_id: str) -> ProfileEvidence:
    return ProfileEvidence(
        evidence_id=evidence_id,
        artifact_digest=f"sha256:{'a' * 64}",
        locator=EvidenceLocator(image_path=f"/{evidence_id}.py", line_start=1, line_end=1),
        extractor=evidence_id,
        method="framework",
        content_sha256="b" * 64,
        summary=evidence_id,
    )


def _fragment(
    framework_id: str,
    evidence_id: str,
    node_type: str,
    risk_level: str,
    edge_id: str,
) -> GraphFragment:
    framework = FrameworkDetection(
        framework_id=framework_id,
        name=framework_id,
        evidence_refs=[evidence_id],
        confidence=0.8,
        verification_status="supported",
    )
    nodes = (
        ProfileNode(
            node_id="node:shared",
            node_type=node_type,
            name="Shared",
            framework_ids=[framework_id],
            risk_level=risk_level,
            evidence_refs=[evidence_id],
            confidence=0.8,
            verification_status="supported",
        ),
        ProfileNode(
            node_id="node:target",
            node_type="tool",
            name="Target",
            framework_ids=[framework_id],
            risk_level="medium",
            evidence_refs=[evidence_id],
            confidence=0.8,
            verification_status="supported",
        ),
    )
    edge = ProfileEdge(
        edge_id=edge_id,
        edge_type="invokes",
        source_node_id="node:shared",
        target_node_id="node:target",
        condition="approved",
        evidence_refs=[evidence_id],
        confidence=0.8,
        verification_status="supported",
    )
    return GraphFragment(framework=framework, nodes=nodes, edges=(edge,), evidence=(_evidence(evidence_id),))


def test_merger_is_order_independent_preserves_conflicts_and_deduplicates_edges() -> None:
    first = _fragment("alpha", "evidence:alpha", "agent", "low", "edge:alpha")
    second = _fragment("beta", "evidence:beta", "router", "critical", "edge:beta")

    forward = merge_graph_fragments((first, second))
    reverse = merge_graph_fragments((second, first))

    assert forward.model_dump(mode="json") == reverse.model_dump(mode="json")
    shared = next(node for node in forward.nodes if node.node_id == "node:shared")
    assert shared.node_type == "agent"
    assert shared.risk_level == "critical"
    assert shared.framework_ids == ["alpha", "beta"]
    assert shared.evidence_refs == ["evidence:alpha", "evidence:beta"]
    assert len(forward.edges) == 1
    assert forward.edges[0].evidence_refs == ["evidence:alpha", "evidence:beta"]
    conflict = next(item for item in forward.limitations if item.code == "framework_node_type_conflict")
    assert conflict.evidence_refs == ["evidence:alpha", "evidence:beta"]
