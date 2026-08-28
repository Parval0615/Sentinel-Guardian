"""Versioned domain contracts shared by RedSentinel research modules."""

from redsentinel.core.converters import agent_profile_from_legacy
from redsentinel.core.models import (
    AgentProfile,
    AgentProfileNode,
    AgentProfileTool,
    AttackCandidate,
    DefenseCandidate,
    EvaluationCaseResult,
    EvaluationResult,
    EvidenceRef,
    EvolutionStage,
    EvolutionState,
    ExperimentManifest,
    Provenance,
    Trajectory,
    TrajectoryStep,
)
from redsentinel.core.profile_evidence import EvidenceLocator, EvidenceMethod, ProfileEvidence

__all__ = [
    "AgentProfile",
    "AgentProfileNode",
    "AgentProfileTool",
    "AttackCandidate",
    "DefenseCandidate",
    "EvaluationCaseResult",
    "EvaluationResult",
    "EvidenceLocator",
    "EvidenceMethod",
    "EvidenceRef",
    "EvolutionStage",
    "EvolutionState",
    "ExperimentManifest",
    "Provenance",
    "ProfileEvidence",
    "Trajectory",
    "TrajectoryStep",
    "agent_profile_from_legacy",
]
