#!/usr/bin/env python3
"""Generate and verify Docker-backed Task 13/15 artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, TypeAdapter

from redsentinel.application.attack_profile import (
    build_attack_profile,
    image_profile_sha256,
)
from redsentinel.application.image_profile_contracts import (
    AgentDirectoryDescriptor,
    AttackProfile,
    ImageAgentProfile,
    profile_configuration_digest,
)
from redsentinel.attacks.engine.attack_spec import AttackSpec
from redsentinel.attacks.engine.profile_driven import (
    build_attack_profile_driven_attack_plan,
)


EXPECTED = {
    "ecommerce": {
        "directory": "电商",
        "entrypoint": [
            "python",
            "-m",
            "redsentinel.adapters.engine.ecommerce_agent.runtime",
        ],
        "frameworks": {"Custom Python"},
        "node_types": {"entrypoint", "agent", "tool", "external_input", "guard"},
        "node_names": {
            "call invoke_ecommerce_agent",
            "tool sink redsentinel.adapters.engine.ecommerce_agent.tools.product_search",
            "tool sink redsentinel.adapters.engine.ecommerce_agent.tools.get_product_detail",
        },
        "minimum_risk_paths": 1,
    },
    "openmanus": {
        "directory": "openmanus",
        "entrypoint": ["/entrypoint.sh"],
        "frameworks": {"OpenManus", "MCP"},
        "node_types": {"agent", "llm", "tool", "shell", "file", "browser"},
        "node_names": {
            "Manus",
            "AsyncOpenAI",
            "Bash",
            "shell sink exec",
            "file sink write_text",
            "browser sink page.goto",
        },
        "minimum_risk_paths": 1,
    },
}

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_ATTACK_SPEC_LIST = TypeAdapter(list[AttackSpec])


def _required_artifacts(artifacts_root: Path) -> list[Path]:
    paths = [
        artifacts_root / "task13-attack-handoff-summary.json",
        artifacts_root / "task13-desktop-http-smoke.json",
    ]
    for agent_id in EXPECTED:
        paths.extend(
            [
                artifacts_root / f"task13-{agent_id}-profile-summary.json",
                artifacts_root / "task15" / agent_id / "agent-profile-v0.2.json",
                artifacts_root / "task15" / agent_id / "attack-profile-v0.1.json",
                artifacts_root / "task15" / agent_id / "attack-specs.json",
                artifacts_root / "task15" / agent_id / "evidence-index.json",
                artifacts_root / "task15" / agent_id / "bundle-manifest.json",
            ]
        )
    return paths


def _ensure_artifacts(_repo_root: Path, artifacts_root: Path) -> None:
    missing = [path for path in _required_artifacts(artifacts_root) if not path.is_file()]
    if missing:
        names = ", ".join(str(path) for path in missing)
        raise RuntimeError(
            "Docker-backed artifacts are missing; run the verifier "
            f"without --existing to regenerate them: {names}"
        )


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"{path} must contain a JSON object")
    return payload


def _load_model(path: Path, model: type[_ModelT]) -> _ModelT:
    return model.model_validate_json(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _claim_collections(profile: ImageAgentProfile | AttackProfile) -> list[list[Any]]:
    return [
        profile.frameworks,
        profile.nodes,
        profile.edges,
        profile.capabilities,
        profile.permissions,
        profile.controls,
        profile.risk_paths,
    ]


def _verify_claim_evidence(profile: ImageAgentProfile | AttackProfile) -> None:
    evidence_ids = {item.evidence_id for item in profile.evidence}
    claims = [profile.image]
    for collection in _claim_collections(profile):
        claims.extend(collection)
    for claim in claims:
        assert set(claim.evidence_refs) <= evidence_ids


def _verify_profile_bundle(
    agent_id: str,
    profile: ImageAgentProfile,
    attack_profile: AttackProfile,
    attack_spec_payload: dict[str, Any],
    evidence_index: dict[str, Any] | None = None,
    manifest: dict[str, Any] | None = None,
    output_root: Path | None = None,
) -> list[AttackSpec]:
    artifact_arguments = (evidence_index, manifest, output_root)
    if any(item is not None for item in artifact_arguments) and not all(
        item is not None for item in artifact_arguments
    ):
        raise ValueError(
            "evidence_index, manifest, and output_root must be provided together"
        )
    verify_artifacts = all(item is not None for item in artifact_arguments)
    profile_sha256 = image_profile_sha256(profile)
    config_digest = profile.analysis.configuration_digest
    completeness = (
        profile.completeness.model_dump(mode="json")
        if profile.completeness is not None
        else None
    )
    binding = {
        "image_digest": profile.image.digest,
        "config_digest": config_digest,
        "profile_id": profile.profile_id,
        "profile_sha256": profile_sha256,
    }
    assert profile.agent_id == agent_id
    if verify_artifacts:
        assert profile.completeness is not None
        assert profile.analysis.status == "partial"
        assert profile.completeness.conclusion == "partial"
        assert "critical_dynamic_corroboration_incomplete" in (
            profile.completeness.blocking_limitations
        )
        assert next(
            stage for stage in profile.analysis.stages
            if stage.stage == "dynamic_verify"
        ).status == "completed"
        dynamic_evidence = [
            item for item in profile.evidence if item.method == "dynamic"
        ]
        assert dynamic_evidence
        assert all(item.trust_level == "attested" for item in dynamic_evidence)
    assert attack_profile.agent_id == agent_id
    assert attack_profile.source_profile_id == profile.profile_id
    assert attack_profile.source_profile_sha256 == profile_sha256
    assert attack_profile.image.digest == profile.image.digest

    rebuilt_attack_profile = build_attack_profile(profile)
    assert rebuilt_attack_profile is not None
    assert attack_profile == rebuilt_attack_profile
    _verify_claim_evidence(profile)
    _verify_claim_evidence(attack_profile)

    assert attack_spec_payload["schema_version"] == "attack-spec-set-v0.1"
    assert attack_spec_payload["agent_id"] == agent_id
    required_binding = binding if verify_artifacts else {
        key: value for key, value in binding.items() if key in attack_spec_payload
    }
    if verify_artifacts:
        assert attack_spec_payload["completeness"] == completeness
    for key, value in required_binding.items():
        assert attack_spec_payload[key] == value
    specs = _ATTACK_SPEC_LIST.validate_python(attack_spec_payload["specs"])
    rebuilt_specs = build_attack_profile_driven_attack_plan(
        attack_profile
    ).targeted_specs
    assert specs == rebuilt_specs
    assert attack_spec_payload["count"] == len(specs)

    if verify_artifacts:
        assert evidence_index is not None
        assert manifest is not None
        assert output_root is not None
        evidence_ids = {item.evidence_id for item in profile.evidence}
        assert evidence_index["schema_version"] == "image-profile-evidence-index-v0.1"
        assert evidence_index["agent_id"] == agent_id
        assert evidence_index["completeness"] == completeness
        assert {
            item["evidence_id"] for item in evidence_index["evidence"]
        } == evidence_ids
        for key, value in binding.items():
            assert evidence_index[key] == value

        assert manifest["schema_version"] == "task15-profile-bundle-v0.1"
        assert manifest["mode"] == "docker"
        assert manifest["completeness"] == completeness
        assert manifest["attack_profile_id"] == attack_profile.attack_profile_id
        for key, value in binding.items():
            assert manifest[key] == value
        assert set(manifest["files"]) == {
            "agent-profile-v0.2.json",
            "attack-profile-v0.1.json",
            "attack-specs.json",
            "evidence-index.json",
        }
        for name, digest in manifest["files"].items():
            assert digest == _sha256(output_root / name)

    paths = {item.path_id: item for item in attack_profile.risk_paths}
    for spec in specs:
        metadata = spec.metadata
        path = paths[metadata["path_id"]]
        assert metadata["image_digest"] == binding["image_digest"]
        assert metadata["profile_id"] == binding["profile_id"]
        assert metadata["profile_sha256"] == binding["profile_sha256"]
        assert metadata["attack_profile_id"] == attack_profile.attack_profile_id
        assert metadata["source_node_id"] == path.source_node_id
        assert metadata["sink_node_id"] == path.sink_node_id
        assert metadata["capability_ids"] == path.capability_ids
        assert metadata["permission_ids"] == path.permission_ids
        assert metadata["control_ids"] == path.control_ids
        assert metadata["evidence_refs"] == path.evidence_refs
        assert metadata["verification_status"] == path.verification_status
        assert metadata["path_risk_level"] == path.risk_level
    return specs


def _verify_display_summary(
    summary: dict[str, Any],
    profile: ImageAgentProfile,
    attack_profile: AttackProfile,
    specs: list[AttackSpec],
) -> None:
    assert profile.completeness is not None
    counts = {
        "nodes": len(profile.nodes),
        "edges": len(profile.edges),
        "capabilities": len(profile.capabilities),
        "permissions": len(profile.permissions),
        "controls": len(profile.controls),
        "evidence": len(profile.evidence),
        "risk_paths": len(profile.risk_paths),
    }
    assert summary["agent_id"] == profile.agent_id
    assert summary["status"] == "partial"
    assert summary["completeness"] == profile.completeness.model_dump(mode="json")
    assert summary["config_digest"] == profile.analysis.configuration_digest
    assert summary["profile_id"] == profile.profile_id
    assert summary["profile_sha256"] == image_profile_sha256(profile)
    assert summary["image"]["digest"] == profile.image.digest
    assert summary["image"]["entrypoint"] == profile.image.entrypoint
    assert summary["counts"] == counts
    assert summary["attack_counts"] == {
        "nodes": len(attack_profile.nodes),
        "paths": len(attack_profile.risk_paths),
        "evidence": len(attack_profile.evidence),
    }
    assert len(specs) == summary["attack_counts"]["paths"]


def verify(repo_root: Path, artifacts_root: Path) -> dict[str, Any]:
    """Validate real-image artifacts, bindings, evidence trust, and HTTP smoke."""
    _ensure_artifacts(repo_root, artifacts_root)
    attack_handoff = _load(artifacts_root / "task13-attack-handoff-summary.json")
    smoke = _load(artifacts_root / "task13-desktop-http-smoke.json")
    result: dict[str, Any] = {}

    for agent_id, expected in EXPECTED.items():
        output_root = artifacts_root / "task15" / agent_id
        profile = _load_model(
            output_root / "agent-profile-v0.2.json",
            ImageAgentProfile,
        )
        attack_profile = _load_model(
            output_root / "attack-profile-v0.1.json",
            AttackProfile,
        )
        attack_spec_payload = _load(output_root / "attack-specs.json")
        evidence_index = _load(output_root / "evidence-index.json")
        manifest = _load(output_root / "bundle-manifest.json")
        specs = _verify_profile_bundle(
            agent_id,
            profile,
            attack_profile,
            attack_spec_payload,
            evidence_index,
            manifest,
            output_root,
        )
        summary = _load(artifacts_root / f"task13-{agent_id}-profile-summary.json")
        agent_root = repo_root / "agents" / str(expected["directory"])
        descriptor = AgentDirectoryDescriptor.model_validate(
            _load(agent_root / "agent.json")
        )
        image_digest = _sha256(agent_root / "image.tar")
        config_digest = profile_configuration_digest(descriptor)

        assert descriptor.agent_id == agent_id
        assert descriptor.image.digest == image_digest
        assert profile.image.digest == image_digest
        assert profile.analysis.configuration_digest == config_digest
        assert profile.image.entrypoint == expected["entrypoint"]
        assert profile.analysis.status == "partial"
        assert profile.analysis.stages[-1].status == "completed"

        frameworks = {item.name for item in profile.frameworks}
        node_types = {item.node_type for item in profile.nodes}
        node_names = {item.name for item in profile.nodes}
        assert expected["frameworks"] <= frameworks
        assert expected["node_types"] <= node_types
        assert expected["node_names"] <= node_names
        assert len(profile.risk_paths) >= expected["minimum_risk_paths"]
        _verify_display_summary(summary, profile, attack_profile, specs)

        binding = attack_handoff[agent_id]
        assert binding["image_digest"] == image_digest
        assert binding["config_digest"] == config_digest
        assert binding["profile_id"] == profile.profile_id
        assert binding["profile_sha256"] == image_profile_sha256(profile)
        assert binding["completeness"] == profile.completeness.model_dump(mode="json")
        assert binding["attack_profile_id"] == attack_profile.attack_profile_id
        assert binding["attack_paths"] == len(attack_profile.risk_paths)
        assert binding["attack_specs"] == len(specs)
        assert binding["attack_paths"] >= expected["minimum_risk_paths"]

        result[agent_id] = {
            "image_digest": image_digest,
            "config_digest": config_digest,
            "status": profile.analysis.status,
            "completeness": profile.completeness.conclusion,
            "dynamic_corroborated": (
                profile.completeness.dynamic_corroboration_coverage.covered
            ),
            "nodes": len(profile.nodes),
            "risk_paths": len(profile.risk_paths),
            "attack_specs": len(specs),
            "profile_id": profile.profile_id,
            "profile_sha256": image_profile_sha256(profile),
        }

    assert smoke["health"] == 200
    assert smoke["agent_ids"] == ["ecommerce", "openmanus"]
    assert smoke["storage_root"] == "/tmp/sentinel-task15-*/smoke-storage"
    result["desktop_http_smoke"] = smoke
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate with real Docker and verify Task 13/15 artifacts."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--artifacts-root",
        type=Path,
        default=Path("artifacts"),
    )
    parser.add_argument(
        "--existing",
        action="store_true",
        help="verify existing complete artifacts without regenerating them",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    artifacts_root = args.artifacts_root
    if not artifacts_root.is_absolute():
        artifacts_root = repo_root / artifacts_root
    if not args.existing:
        try:
            from scripts.generate_task15_artifacts import generate
        except ModuleNotFoundError:
            from generate_task15_artifacts import generate
        generate(
            repo_root=repo_root,
            artifacts_root=artifacts_root,
            mode="docker",
        )
    print(json.dumps(verify(repo_root, artifacts_root), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
