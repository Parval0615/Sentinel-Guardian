"""Evidence-bound framework detection and deterministic graph reconstruction."""

from redsentinel.profiling.frameworks.adapters import (
    AutoGenAdapter,
    BasicFingerprintAdapter,
    CrewAIAdapter,
    CustomFrameworkAdapter,
    LangChainAdapter,
    LangGraphAdapter,
    MCPAdapter,
    OpenManusAdapter,
)
from redsentinel.profiling.frameworks.base import FrameworkAdapter
from redsentinel.profiling.frameworks.merge import merge_graph_fragments
from redsentinel.profiling.frameworks.models import (
    FrameworkAnalysis,
    FrameworkCandidate,
    GraphFragment,
    MergedGraph,
)
from redsentinel.profiling.frameworks.registry import (
    DEFAULT_FRAMEWORK_REGISTRY,
    FrameworkRegistry,
    analyze_frameworks,
)

__all__ = [
    "AutoGenAdapter",
    "BasicFingerprintAdapter",
    "CrewAIAdapter",
    "CustomFrameworkAdapter",
    "DEFAULT_FRAMEWORK_REGISTRY",
    "FrameworkAdapter",
    "FrameworkAnalysis",
    "FrameworkCandidate",
    "FrameworkRegistry",
    "GraphFragment",
    "LangChainAdapter",
    "LangGraphAdapter",
    "MCPAdapter",
    "MergedGraph",
    "OpenManusAdapter",
    "analyze_frameworks",
    "merge_graph_fragments",
]
