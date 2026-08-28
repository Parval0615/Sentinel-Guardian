from __future__ import annotations

from collections.abc import Iterable

from redsentinel.core.image_profile_graph import (
    AnalysisLimitation,
    FrameworkDetection,
    ProfileEdge,
    ProfileNode,
)
from redsentinel.profiling.frameworks.base import RISK_ORDER, STATUS_ORDER, stable_id
from redsentinel.profiling.frameworks.models import GraphFragment, MergedGraph


def _claim_choice(left, right):
    return min(
        (left, right),
        key=lambda item: (
            -item.confidence,
            -STATUS_ORDER[item.verification_status],
            getattr(item, "node_type", ""),
            getattr(item, "name", ""),
        ),
    )


def _merge_framework(left: FrameworkDetection, right: FrameworkDetection) -> FrameworkDetection:
    chosen = _claim_choice(left, right)
    versions = sorted(version for version in (left.version, right.version) if version)
    return chosen.model_copy(
        update={
            "version": versions[0] if versions else None,
            "evidence_refs": sorted(set(left.evidence_refs) | set(right.evidence_refs)),
            "confidence": max(left.confidence, right.confidence),
            "verification_status": max(
                (left.verification_status, right.verification_status),
                key=STATUS_ORDER.__getitem__,
            ),
        }
    )


def _merge_node(left: ProfileNode, right: ProfileNode) -> tuple[ProfileNode, AnalysisLimitation | None]:
    chosen = _claim_choice(left, right)
    refs = sorted(set(left.evidence_refs) | set(right.evidence_refs))
    merged = chosen.model_copy(
        update={
            "framework_ids": sorted(set(left.framework_ids) | set(right.framework_ids)),
            "capability_ids": sorted(set(left.capability_ids) | set(right.capability_ids)),
            "permission_ids": sorted(set(left.permission_ids) | set(right.permission_ids)),
            "control_ids": sorted(set(left.control_ids) | set(right.control_ids)),
            "risk_level": max((left.risk_level, right.risk_level), key=RISK_ORDER.__getitem__),
            "evidence_refs": refs,
            "confidence": max(left.confidence, right.confidence),
            "verification_status": max(
                (left.verification_status, right.verification_status),
                key=STATUS_ORDER.__getitem__,
            ),
        }
    )
    if left.node_type == right.node_type:
        return merged, None
    types = sorted((left.node_type, right.node_type))
    return merged, AnalysisLimitation(
        code="framework_node_type_conflict",
        message=(
            f"Adapters classified node {left.node_id} as {types[0]} and {types[1]}; "
            f"selected {merged.node_type} deterministically"
        ),
        evidence_refs=refs,
    )


def _merge_edge(left: ProfileEdge, right: ProfileEdge) -> ProfileEdge:
    chosen = _claim_choice(left, right)
    key = (left.source_node_id, left.target_node_id, left.edge_type, left.condition)
    return chosen.model_copy(
        update={
            "edge_id": stable_id("edge", *key),
            "evidence_refs": sorted(set(left.evidence_refs) | set(right.evidence_refs)),
            "confidence": max(left.confidence, right.confidence),
            "verification_status": max(
                (left.verification_status, right.verification_status),
                key=STATUS_ORDER.__getitem__,
            ),
        }
    )


def _merge_limitations(limitations: Iterable[AnalysisLimitation]) -> tuple[AnalysisLimitation, ...]:
    merged: dict[tuple[str, str], AnalysisLimitation] = {}
    for limitation in limitations:
        key = (limitation.code, limitation.message)
        current = merged.get(key)
        if current is None:
            merged[key] = limitation
        else:
            merged[key] = current.model_copy(
                update={
                    "evidence_refs": sorted(set(current.evidence_refs) | set(limitation.evidence_refs)),
                }
            )
    return tuple(merged[key] for key in sorted(merged))


def merge_graph_fragments(fragments: Iterable[GraphFragment]) -> MergedGraph:
    ordered = sorted(fragments, key=lambda item: item.framework.framework_id)
    frameworks: dict[str, FrameworkDetection] = {}
    nodes: dict[str, ProfileNode] = {}
    edges: dict[tuple[str, str, str, str | None], ProfileEdge] = {}
    evidence = {}
    limitations: list[AnalysisLimitation] = []

    for fragment in ordered:
        framework = fragment.framework
        if framework.framework_id in frameworks:
            framework = _merge_framework(frameworks[framework.framework_id], framework)
        frameworks[framework.framework_id] = framework
        for item in fragment.evidence:
            evidence[item.evidence_id] = item
        limitations.extend(fragment.limitations)
        for node in fragment.nodes:
            current = nodes.get(node.node_id)
            if current is None:
                nodes[node.node_id] = node
                continue
            nodes[node.node_id], conflict = _merge_node(current, node)
            if conflict is not None:
                limitations.append(conflict)
        for edge in fragment.edges:
            key = (edge.source_node_id, edge.target_node_id, edge.edge_type, edge.condition)
            current = edges.get(key)
            edges[key] = (
                edge.model_copy(update={"edge_id": stable_id("edge", *key)})
                if current is None
                else _merge_edge(current, edge)
            )

    return MergedGraph(
        frameworks=tuple(frameworks[key] for key in sorted(frameworks)),
        nodes=tuple(nodes[key] for key in sorted(nodes)),
        edges=tuple(edges[key] for key in sorted(edges)),
        evidence=tuple(evidence[key] for key in sorted(evidence)),
        limitations=_merge_limitations(limitations),
    )


__all__ = ["merge_graph_fragments"]
