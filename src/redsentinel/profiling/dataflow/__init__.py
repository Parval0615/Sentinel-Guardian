"""Evidence-bound, finite Python dataflow analysis."""

from redsentinel.profiling.dataflow.analyzer import analyze_dataflow, analyze_dataflows
from redsentinel.profiling.dataflow.catalog import (
    CONTROL_CALLS,
    NORMALIZATION_CALLS,
    SINK_RULES,
    SOURCE_CALLS,
)
from redsentinel.profiling.dataflow.models import (
    DataflowAnalysisResult,
    DataflowSink,
    DataflowSource,
    SinkType,
    SourceType,
    UnresolvedFlow,
    WeakControlFact,
)

__all__ = [
    "CONTROL_CALLS",
    "DataflowAnalysisResult",
    "DataflowSink",
    "DataflowSource",
    "NORMALIZATION_CALLS",
    "SINK_RULES",
    "SOURCE_CALLS",
    "SinkType",
    "SourceType",
    "UnresolvedFlow",
    "WeakControlFact",
    "analyze_dataflow",
    "analyze_dataflows",
]
