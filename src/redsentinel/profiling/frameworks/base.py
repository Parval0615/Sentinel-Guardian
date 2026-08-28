from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Literal

from redsentinel.core.image_profile_graph import (
    AnalysisLimitation,
    FrameworkDetection,
    ProfileEdge,
    ProfileEdgeType,
    ProfileNode,
    ProfileNodeType,
    ProfileRiskLevel,
)
from redsentinel.core.profile_evidence import EvidenceLocator, ProfileEvidence
from redsentinel.profiling.frameworks.models import FrameworkCandidate, GraphFragment
from redsentinel.profiling.static_facts import (
    EvidencedFact,
    StaticFactIndex,
)


FingerprintKind = Literal["dependency", "import", "call", "decorator", "base", "module", "entrypoint"]
RISK_ORDER: dict[ProfileRiskLevel, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
STATUS_ORDER = {"rejected": 0, "inferred": 1, "supported": 2, "verified": 3}


def stable_id(prefix: str, *parts: object) -> str:
    payload = "\x1f".join(str(part) for part in parts)
    return f"{prefix}:{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:20]}"


def node_id(module: str, identity: str) -> str:
    return stable_id("node", module, identity)


def _normalized_package(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _fact_value(kind: FingerprintKind, fact: EvidencedFact) -> str:
    if kind == "dependency":
        return _normalized_package(fact.name)  # type: ignore[attr-defined]
    if kind == "import":
        imported = fact.imported_module  # type: ignore[attr-defined]
        imported_name = fact.imported_name  # type: ignore[attr-defined]
        return f"{imported}.{imported_name}" if imported_name else imported
    if kind == "call":
        return fact.callee  # type: ignore[attr-defined]
    if kind == "decorator":
        return fact.decorator  # type: ignore[attr-defined]
    if kind == "base":
        return fact.base  # type: ignore[attr-defined]
    if kind == "module":
        return fact.module  # type: ignore[attr-defined]
    entrypoint = fact  # type: ignore[assignment]
    return ".".join(part for part in (entrypoint.name, entrypoint.module, entrypoint.symbol) if part)


def _kind_facts(index: StaticFactIndex, kind: FingerprintKind) -> Iterable[EvidencedFact]:
    if kind == "dependency":
        return index.dependencies
    if kind == "import":
        return index.imports
    if kind == "call":
        return index.calls
    if kind == "decorator":
        return index.decorators
    if kind == "base":
        return index.class_bases
    if kind == "module":
        return index.modules
    return index.entrypoints


def _matches(value: str, token: str, kind: FingerprintKind) -> bool:
    value = value.lower()
    token = token.lower()
    if kind == "dependency":
        return value == _normalized_package(token)
    if kind in {"import", "module"}:
        return value == token or value.startswith(f"{token}.")
    if kind in {"call", "decorator", "base"}:
        return value == token or value.endswith(f".{token}")
    return value == token or value.startswith(f"{token}.") or value.endswith(f".{token}")


class FrameworkAdapter(ABC):
    framework_id: str
    name: str
    threshold: float = 0.5
    fingerprints: tuple[tuple[FingerprintKind, tuple[str, ...], float], ...] = ()

    def detect(self, index: StaticFactIndex) -> tuple[FrameworkCandidate | None, tuple[ProfileEvidence, ...]]:
        matches: list[tuple[str, float, EvidencedFact]] = []
        for kind, tokens, weight in self.fingerprints:
            facts = _kind_facts(index, kind)
            matching = [fact for fact in facts if any(_matches(_fact_value(kind, fact), token, kind) for token in tokens)]
            if matching:
                matches.extend((kind, weight, fact) for fact in matching)
        if not matches:
            return None, ()

        evidence = _framework_evidence(self.framework_id, (fact.evidence for _, _, fact in matches))
        evidence_refs = tuple(item.evidence_id for item in evidence)
        signal_weights: dict[str, float] = {}
        for kind, weight, _ in matches:
            signal_weights[kind] = max(signal_weights.get(kind, 0.0), weight)
        confidence = min(0.99, sum(signal_weights.values()))
        version = self._version(index)
        candidate = FrameworkCandidate(
            framework_id=self.framework_id,
            name=self.name,
            version=version,
            confidence=confidence,
            evidence_refs=evidence_refs,
            signals=tuple(sorted(signal_weights)),
            selected=confidence >= self.threshold,
        )
        return candidate, evidence

    def _version(self, index: StaticFactIndex) -> str | None:
        package_names = {
            _normalized_package(token)
            for kind, tokens, _ in self.fingerprints
            if kind == "dependency"
            for token in tokens
        }
        versions = sorted(
            {
                dependency.version
                for dependency in index.dependencies
                if _normalized_package(dependency.name) in package_names and dependency.version
            }
        )
        return versions[0] if versions else None

    def adapt(self, index: StaticFactIndex) -> GraphFragment | None:
        candidate, evidence = self.detect(index)
        if candidate is None or not candidate.selected:
            return None
        return self._build_graph(index, candidate, evidence)

    @abstractmethod
    def _build_graph(
        self,
        index: StaticFactIndex,
        candidate: FrameworkCandidate,
        evidence: tuple[ProfileEvidence, ...],
    ) -> GraphFragment:
        raise NotImplementedError


def _framework_evidence(framework_id: str, source: Iterable[ProfileEvidence]) -> tuple[ProfileEvidence, ...]:
    result: dict[str, ProfileEvidence] = {}
    for item in source:
        evidence_id = stable_id("evidence", "framework", framework_id, item.evidence_id)
        result[evidence_id] = item.model_copy(
            update={
                "evidence_id": evidence_id,
                "extractor": f"{framework_id}_adapter",
                "method": "framework",
            }
        )
    return tuple(result[key] for key in sorted(result))








def index_evidence(index: StaticFactIndex, framework_id: str, summary: str) -> ProfileEvidence:
    return ProfileEvidence(
        evidence_id=stable_id("evidence", "framework", framework_id, index.artifact_digest),
        artifact_digest=index.artifact_digest,
        locator=EvidenceLocator(package_metadata_key="static-fact-index"),
        extractor=f"{framework_id}_adapter",
        method="framework",
        content_sha256=index.artifact_digest.removeprefix("sha256:"),
        summary=summary,
    )


class FragmentBuilder:
    def __init__(
        self,
        adapter: FrameworkAdapter,
        candidate: FrameworkCandidate,
        evidence: tuple[ProfileEvidence, ...],
    ) -> None:
        self.adapter = adapter
        self.candidate = candidate
        self.evidence = {item.evidence_id: item for item in evidence}
        self.nodes: dict[str, ProfileNode] = {}
        self.edges: dict[tuple[str, str, str, str | None], ProfileEdge] = {}
        self.limitations: list[AnalysisLimitation] = []

    @property
    def framework(self) -> FrameworkDetection:
        return FrameworkDetection(
            framework_id=self.candidate.framework_id,
            name=self.candidate.name,
            version=self.candidate.version,
            evidence_refs=list(self.candidate.evidence_refs),
            confidence=self.candidate.confidence,
            verification_status="supported",
        )

    def refs(self, facts: Iterable[EvidencedFact]) -> list[str]:
        refs = {
            evidence_id
            for fact in facts
            if (
                evidence_id := stable_id(
                    "evidence",
                    "framework",
                    self.adapter.framework_id,
                    fact.evidence.evidence_id,
                )
            )
            in self.evidence
        }
        if not refs:
            refs = set(self.candidate.evidence_refs)
        return sorted(refs)

    def add_node(
        self,
        *,
        module: str,
        identity: str,
        name: str,
        node_type: ProfileNodeType,
        facts: Iterable[EvidencedFact],
        risk_level: ProfileRiskLevel = "low",
    ) -> str:
        identifier = node_id(module, identity)
        refs = self.refs(facts)
        incoming = ProfileNode(
            node_id=identifier,
            node_type=node_type,
            name=name,
            framework_ids=[self.adapter.framework_id],
            risk_level=risk_level,
            evidence_refs=refs,
            confidence=self.candidate.confidence,
            verification_status="supported",
        )
        current = self.nodes.get(identifier)
        if current is None:
            self.nodes[identifier] = incoming
            return identifier
        if current.node_type != incoming.node_type:
            chosen = min((current, incoming), key=lambda item: (-item.confidence, item.node_type))
            refs = sorted(set(current.evidence_refs) | set(incoming.evidence_refs))
            self.nodes[identifier] = chosen.model_copy(
                update={
                    "evidence_refs": refs,
                    "framework_ids": sorted(set(current.framework_ids) | set(incoming.framework_ids)),
                    "risk_level": max(
                        (current.risk_level, incoming.risk_level),
                        key=RISK_ORDER.__getitem__,
                    ),
                }
            )
            self.limitations.append(
                AnalysisLimitation(
                    code="framework_node_type_conflict",
                    message=(
                        f"{self.adapter.name} produced conflicting node types for {name}: "
                        f"{current.node_type}, {incoming.node_type}; selected {chosen.node_type}"
                    ),
                    evidence_refs=refs,
                )
            )
        else:
            self.nodes[identifier] = current.model_copy(
                update={
                    "evidence_refs": sorted(set(current.evidence_refs) | set(incoming.evidence_refs)),
                    "risk_level": max(
                        (current.risk_level, incoming.risk_level),
                        key=RISK_ORDER.__getitem__,
                    ),
                }
            )
        return identifier

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: ProfileEdgeType,
        facts: Iterable[EvidencedFact],
        *,
        condition: str | None = None,
    ) -> None:
        if source == target:
            return
        key = (source, target, edge_type, condition)
        refs = self.refs(facts)
        current = self.edges.get(key)
        if current is None:
            self.edges[key] = ProfileEdge(
                edge_id=stable_id("edge", *key),
                edge_type=edge_type,
                source_node_id=source,
                target_node_id=target,
                condition=condition,
                evidence_refs=refs,
                confidence=self.candidate.confidence,
                verification_status="supported",
            )
            return
        self.edges[key] = current.model_copy(
            update={
                "evidence_refs": sorted(set(current.evidence_refs) | set(refs)),
                "confidence": max(current.confidence, self.candidate.confidence),
            }
        )

    def limitation(self, code: str, message: str, facts: Iterable[EvidencedFact]) -> None:
        self.limitations.append(AnalysisLimitation(code=code, message=message, evidence_refs=self.refs(facts)))

    def build(self) -> GraphFragment:
        return GraphFragment(
            framework=self.framework,
            nodes=tuple(self.nodes[key] for key in sorted(self.nodes)),
            edges=tuple(self.edges[key] for key in sorted(self.edges)),
            evidence=tuple(self.evidence[key] for key in sorted(self.evidence)),
            limitations=tuple(
                sorted(self.limitations, key=lambda item: (item.code, item.message, tuple(item.evidence_refs)))
            ),
        )


__all__ = [
    "FragmentBuilder",
    "FrameworkAdapter",
    "FingerprintKind",
    "RISK_ORDER",
    "STATUS_ORDER",
    "_framework_evidence",
    "index_evidence",
    "node_id",
    "stable_id",
]
