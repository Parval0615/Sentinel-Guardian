from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class AttackStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(default="buyer_001", min_length=1)
    role: str = Field(default="buyer", min_length=1)
    message: str = Field(min_length=1)


class EcommerceAttackScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)
    attack_spec_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    business_flow: str = Field(min_length=1)
    severity: Literal["low", "medium", "high", "critical"]
    expected_decision: Literal["allow", "block"]
    business_impact: str = Field(min_length=1)
    success_criteria: list[str] = Field(min_length=1)
    clean_steps: list[AttackStep] = Field(min_length=1)
    controlled_steps: list[AttackStep] = Field(min_length=1)
    expected_tools: list[str] = Field(default_factory=list)
    baseline_success_markers: list[str] = Field(default_factory=list)
    guarded_block_rules: list[str] = Field(default_factory=list)
    source_reference: str | None = None
    mock_services: list[str] = Field(default_factory=list)
    requires_real_runtime: bool = False


class EcommerceAttackPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["ecommerce-attack-pack-v0.1"] = "ecommerce-attack-pack-v0.1"
    benchmark: Literal["ecommerce-security-v0.1"] = "ecommerce-security-v0.1"
    scenarios: list[EcommerceAttackScenario] = Field(min_length=1)


class OpenManusAttackPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["openmanus-attack-pack-v0.2"] = "openmanus-attack-pack-v0.2"
    benchmark: Literal["openmanus-security-v0.1"] = "openmanus-security-v0.1"
    scenarios: list[EcommerceAttackScenario] = Field(min_length=1)


def default_attack_pack_path() -> Path:
    return (
        _resource_root()
        / "configs"
        / "scenarios"
        / "ecommerce"
        / "attack-pack-v0.1.yaml"
    )


def _resource_root() -> Path:
    configured = os.environ.get("RED_SENTINEL_RESOURCE_ROOT")
    root = (
        Path(configured).expanduser().resolve()
        if configured
        else Path(__file__).resolve().parents[4]
    )
    if (root / "configs").is_dir():
        return root
    resources = root / "Resources"
    return resources if (resources / "configs").is_dir() else root


def default_openmanus_attack_pack_path() -> Path:
    return (
        _resource_root()
        / "configs"
        / "scenarios"
        / "openmanus"
        / "attack-pack-v0.2.yaml"
    )


def load_ecommerce_attack_pack(path: str | Path | None = None) -> EcommerceAttackPack:
    target = Path(path) if path else default_attack_pack_path()
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    return EcommerceAttackPack.model_validate(data)


def load_openmanus_attack_pack(path: str | Path | None = None) -> OpenManusAttackPack:
    target = Path(path) if path else default_openmanus_attack_pack_path()
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    return OpenManusAttackPack.model_validate(data)
