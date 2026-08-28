from __future__ import annotations

from collections.abc import Iterable

from redsentinel.profiling.frameworks.adapters import CustomFrameworkAdapter, DEFAULT_ADAPTERS
from redsentinel.profiling.frameworks.base import FrameworkAdapter
from redsentinel.profiling.frameworks.merge import merge_graph_fragments
from redsentinel.profiling.frameworks.models import FrameworkAnalysis, FrameworkCandidate, GraphFragment
from redsentinel.profiling.static_facts import StaticFactIndex


class FrameworkRegistry:
    def __init__(
        self,
        adapters: Iterable[FrameworkAdapter] = (),
        *,
        fallback: FrameworkAdapter | None = None,
    ) -> None:
        self._adapters: dict[str, FrameworkAdapter] = {}
        self._fallback = fallback or CustomFrameworkAdapter()
        for adapter in adapters:
            self.register(adapter)

    @property
    def adapters(self) -> tuple[FrameworkAdapter, ...]:
        return tuple(self._adapters[key] for key in sorted(self._adapters))

    def register(self, adapter: FrameworkAdapter) -> None:
        if adapter.framework_id in self._adapters:
            raise ValueError(f"framework adapter already registered: {adapter.framework_id}")
        if adapter.framework_id == self._fallback.framework_id:
            raise ValueError("custom fallback cannot be registered as a regular adapter")
        self._adapters[adapter.framework_id] = adapter

    def analyze(self, index: StaticFactIndex) -> FrameworkAnalysis:
        candidates: list[FrameworkCandidate] = []
        candidate_evidence = {}
        fragments: list[GraphFragment] = []

        for adapter in self.adapters:
            candidate, evidence = adapter.detect(index)
            if candidate is None:
                continue
            candidates.append(candidate)
            candidate_evidence.update((item.evidence_id, item) for item in evidence)
            if candidate.selected:
                fragment = adapter.adapt(index)
                if fragment is None:  # pragma: no cover - adapter contract violation
                    raise RuntimeError(f"selected adapter returned no graph: {adapter.framework_id}")
                fragments.append(fragment)

        if not fragments:
            candidate, evidence = self._fallback.detect(index)
            if candidate is None:  # pragma: no cover - fallback contract violation
                raise RuntimeError("custom framework fallback did not return a candidate")
            candidates.append(candidate)
            candidate_evidence.update((item.evidence_id, item) for item in evidence)
            fragment = self._fallback.adapt(index)
            if fragment is None:  # pragma: no cover - fallback contract violation
                raise RuntimeError("custom framework fallback returned no graph")
            fragments.append(fragment)

        merged = merge_graph_fragments(fragments)
        evidence = {item.evidence_id: item for item in merged.evidence}
        evidence.update(candidate_evidence)
        return FrameworkAnalysis(
            artifact_digest=index.artifact_digest,
            candidates=tuple(sorted(candidates, key=lambda item: item.framework_id)),
            frameworks=merged.frameworks,
            nodes=merged.nodes,
            edges=merged.edges,
            evidence=tuple(evidence[key] for key in sorted(evidence)),
            limitations=merged.limitations,
        )


DEFAULT_FRAMEWORK_REGISTRY = FrameworkRegistry(DEFAULT_ADAPTERS)


def analyze_frameworks(
    index: StaticFactIndex,
    *,
    registry: FrameworkRegistry = DEFAULT_FRAMEWORK_REGISTRY,
) -> FrameworkAnalysis:
    return registry.analyze(index)


__all__ = ["DEFAULT_FRAMEWORK_REGISTRY", "FrameworkRegistry", "analyze_frameworks"]
