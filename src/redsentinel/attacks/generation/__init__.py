"""Attack specification, profile-driven generation, and campaign APIs."""

from redsentinel.attacks.engine.attack_agent import (
    AttackAgent,
    AttackAttempt,
    CampaignResult,
    ReflectionEntry,
)
from redsentinel.attacks.engine.attack_spec import (
    AgentFramework,
    AttackIntensity,
    AttackRiskType,
    AttackSpec,
    ScenarioManifest,
    ScenarioPairRecord,
    load_scenario_manifest,
)
from redsentinel.attacks.engine.profile_driven import (
    ProfileDrivenAttackPlan,
    build_attack_profile_driven_attack_plan,
    build_image_profile_driven_attack_plan,
    build_profile_driven_attack_plan,
    build_profile_driven_attack_plan_from_candidate,
)

__all__ = [
    "AgentFramework",
    "AttackAgent",
    "AttackAttempt",
    "AttackIntensity",
    "AttackRiskType",
    "AttackSpec",
    "CampaignResult",
    "ProfileDrivenAttackPlan",
    "ReflectionEntry",
    "ScenarioManifest",
    "ScenarioPairRecord",
    "build_attack_profile_driven_attack_plan",
    "build_image_profile_driven_attack_plan",
    "build_profile_driven_attack_plan",
    "build_profile_driven_attack_plan_from_candidate",
    "load_scenario_manifest",
]
