#!/usr/bin/env python3
"""Generate offline or Docker-backed profile artifacts without overstating evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Literal
from unittest.mock import patch

from redsentinel.application.attack_profile import (
    build_attack_profile,
    image_profile_sha256,
)
from redsentinel.application.engine.agent_asset_index import AgentAssetIndexService
from redsentinel.application.engine.app import create_app
from redsentinel.application.engine.application import ProductApplicationService
from redsentinel.application.engine.image_profile_workflow import (
    ImageProfileWorkflowService,
)
from redsentinel.application.engine.service import ProductEvaluationService
from redsentinel.application.image_profile_contracts import ImageAgentProfile
from redsentinel.attacks.engine.profile_driven import (
    build_attack_profile_driven_attack_plan,
)


AGENT_IDS = ("ecommerce", "openmanus")
ArtifactMode = Literal["partial", "docker"]


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _profile_summary(
    profile: ImageAgentProfile,
    attack_profile: Any,
    profile_sha256: str,
) -> dict[str, Any]:
    assert profile.completeness is not None
    return {
        "agent_id": profile.agent_id,
        "status": profile.analysis.status,
        "completeness": profile.completeness.model_dump(mode="json"),
        "config_digest": profile.analysis.configuration_digest,
        "profile_id": profile.profile_id,
        "profile_sha256": profile_sha256,
        "image": profile.image.model_dump(mode="json"),
        "frameworks": [
            item.model_dump(mode="json") for item in profile.frameworks
        ],
        "counts": {
            "nodes": len(profile.nodes),
            "edges": len(profile.edges),
            "capabilities": len(profile.capabilities),
            "permissions": len(profile.permissions),
            "controls": len(profile.controls),
            "evidence": len(profile.evidence),
            "risk_paths": len(profile.risk_paths),
        },
        "nodes": [
            [
                item.node_id,
                item.name,
                item.node_type,
                item.risk_level,
                item.verification_status,
            ]
            for item in profile.nodes
        ],
        "node_types": sorted({item.node_type for item in profile.nodes}),
        "risk_paths": [
            [
                item.path_id,
                item.source_node_id,
                item.sink_node_id,
                item.node_ids,
                item.applicable_threats,
                item.control_gaps,
                item.risk_level,
                item.evidence_refs,
            ]
            for item in profile.risk_paths
        ],
        "stages": [
            item.model_dump(mode="json") for item in profile.analysis.stages
        ],
        "errors": [
            item.model_dump(mode="json") for item in profile.analysis.errors
        ],
        "limitations": [
            item.model_dump(mode="json") for item in profile.limitations
        ],
        "attack_counts": {
            "nodes": len(attack_profile.nodes),
            "paths": len(attack_profile.risk_paths),
            "evidence": len(attack_profile.evidence),
        },
    }


def _canonicalize_profile(profile: ImageAgentProfile) -> ImageAgentProfile:
    timestamp = profile.image.created_at or "1970-01-01T00:00:00+00:00"
    payload = profile.model_dump(mode="json")
    payload["generated_at"] = timestamp
    for stage in payload["analysis"]["stages"]:
        if stage["started_at"] is not None:
            stage["started_at"] = timestamp
        if stage["completed_at"] is not None:
            stage["completed_at"] = timestamp
    return ImageAgentProfile.model_validate(payload)


def _desktop_http_smoke(agents_root: Path, storage_root: Path) -> dict[str, Any]:
    try:
        from fastapi.testclient import TestClient
    except ImportError as exc:
        raise RuntimeError(
            "FastAPI test dependencies are required to generate Task 13 artifacts"
        ) from exc

    with patch.dict(
        os.environ,
        {"RED_SENTINEL_AGENT_ROOT": str(agents_root)},
    ):
        with TestClient(create_app(storage_root=storage_root)) as client:
            health = client.get("/health")
            registered = client.post(
                "/v1/auth/register",
                json={
                    "username": "task13_smoke",
                    "email": "task13_smoke@example.test",
                    "password": "correct-horse-battery-staple",
                },
            )
            if registered.status_code != 200:
                raise RuntimeError(
                    f"Task 13 smoke registration failed: {registered.status_code}"
                )
            client.headers["Authorization"] = (
                f"Bearer {registered.json()['access_token']}"
            )
            agent_responses = {
                agent_id: client.get(f"/v1/agents/{agent_id}")
                for agent_id in AGENT_IDS
            }
            if health.status_code != 200 or any(
                response.status_code != 200
                for response in agent_responses.values()
            ):
                raise RuntimeError("Task 13 desktop HTTP smoke failed")
    return {
        "health": health.status_code,
        "agent_ids": sorted(agent_responses),
        "storage_root": "/tmp/sentinel-task15-*/smoke-storage",
    }


def _workflow(
    *,
    mode: ArtifactMode,
    agents_root: Path,
    storage_root: Path,
) -> tuple[Any, ImageProfileWorkflowService]:
    if mode == "docker":
        application = ProductApplicationService(storage_root)
        return application, application.image_profiles
    product = ProductEvaluationService(storage_root)
    return product, ImageProfileWorkflowService(
        product.storage,
        asset_root_provider=lambda: agents_root,
        image_ref_resolver=lambda _inventory: None,
    )


def _artifact_names(
    artifacts_root: Path,
    mode: ArtifactMode,
) -> tuple[Path, str]:
    if mode == "docker":
        return artifacts_root / "task15", "task13"
    return artifacts_root / "task15-partial", "task13-partial"


def generate(
    *,
    repo_root: Path,
    artifacts_root: Path,
    mode: ArtifactMode = "partial",
) -> dict[str, Any]:
    agents_root = (repo_root / "agents").resolve()
    output_base, summary_prefix = _artifact_names(artifacts_root, mode)
    handoff_summary: dict[str, Any] = {}
    result: dict[str, Any] = {}

    with tempfile.TemporaryDirectory(
        prefix=f"sentinel-task15-{mode}-",
        dir="/tmp",
    ) as temporary, patch.dict(
        os.environ,
        {"RED_SENTINEL_AGENT_ROOT": str(agents_root)},
    ):
        product, workflow = _workflow(
            mode=mode,
            agents_root=agents_root,
            storage_root=Path(temporary) / "storage",
        )
        indexed = AgentAssetIndexService(product).refresh(
            agents_root,
            tenant_id="task15",
            username="task15",
        )
        indexed_ids = {item.agent_id for item in indexed}
        missing = sorted(set(AGENT_IDS) - indexed_ids)
        if missing:
            raise RuntimeError(
                f"required Agent assets are missing: {', '.join(missing)}"
            )

        for agent_id in AGENT_IDS:
            created = workflow.create(tenant_id="task15", agent_id=agent_id)
            status = workflow.run(
                tenant_id="task15",
                agent_id=agent_id,
                analysis_id=created.analysis.analysis_id,
            )
            profile = _canonicalize_profile(
                workflow.get_latest_profile(
                    tenant_id="task15",
                    agent_id=agent_id,
                )
            )
            expected_status = "partial"
            expected_completeness = "partial"
            dynamic_stage = next(
                item
                for item in profile.analysis.stages
                if item.stage == "dynamic_verify"
            )
            if (
                status.status != expected_status
                or profile.analysis.status != expected_status
                or profile.completeness is None
                or profile.completeness.conclusion != expected_completeness
                or status.stages[-1].status != "completed"
            ):
                raise RuntimeError(
                    f"{agent_id} did not produce a {mode} profile: "
                    f"status={status.status}, completeness="
                    f"{profile.completeness.conclusion if profile.completeness else None}, "
                    f"blockers="
                    f"{profile.completeness.blocking_limitations if profile.completeness else []}"
                )
            if mode == "docker":
                dynamic_evidence = [
                    item for item in profile.evidence if item.method == "dynamic"
                ]
                if (
                    dynamic_stage.status != "completed"
                    or not dynamic_evidence
                    or any(item.trust_level != "attested" for item in dynamic_evidence)
                    or "critical_dynamic_corroboration_incomplete"
                    not in profile.completeness.blocking_limitations
                ):
                    raise RuntimeError(
                        f"{agent_id} did not produce an attested Docker profile: "
                        f"dynamic_stage={dynamic_stage.status}, "
                        f"dynamic_evidence={len(dynamic_evidence)}, "
                        f"blockers={profile.completeness.blocking_limitations}"
                    )

            attack_profile = build_attack_profile(profile)
            if attack_profile is None:
                raise RuntimeError(
                    f"{agent_id} produced no attack-eligible risk path"
                )
            specs = build_attack_profile_driven_attack_plan(
                attack_profile
            ).targeted_specs
            profile_sha256 = image_profile_sha256(profile)
            config_digest = profile.analysis.configuration_digest
            output_root = output_base / agent_id
            profile_path = output_root / "agent-profile-v0.2.json"
            attack_profile_path = output_root / "attack-profile-v0.1.json"
            attack_specs_path = output_root / "attack-specs.json"
            evidence_index_path = output_root / "evidence-index.json"

            _write_json(profile_path, profile.model_dump(mode="json"))
            _write_json(
                attack_profile_path,
                attack_profile.model_dump(mode="json"),
            )
            _write_json(
                attack_specs_path,
                {
                    "schema_version": "attack-spec-set-v0.1",
                    "agent_id": agent_id,
                    "image_digest": profile.image.digest,
                    "config_digest": config_digest,
                    "profile_id": profile.profile_id,
                    "profile_sha256": profile_sha256,
                    "completeness": profile.completeness.model_dump(mode="json"),
                    "attack_profile_id": attack_profile.attack_profile_id,
                    "count": len(specs),
                    "specs": [
                        item.model_dump(mode="json") for item in specs
                    ],
                },
            )
            _write_json(
                evidence_index_path,
                {
                    "schema_version": "image-profile-evidence-index-v0.1",
                    "agent_id": agent_id,
                    "image_digest": profile.image.digest,
                    "config_digest": config_digest,
                    "profile_id": profile.profile_id,
                    "profile_sha256": profile_sha256,
                    "completeness": profile.completeness.model_dump(mode="json"),
                    "evidence": [
                        item.model_dump(mode="json")
                        for item in profile.evidence
                    ],
                },
            )
            binding = {
                "profile_id": profile.profile_id,
                "profile_sha256": profile_sha256,
                "image_digest": profile.image.digest,
                "config_digest": config_digest,
                "completeness": profile.completeness.model_dump(mode="json"),
                "attack_profile_id": attack_profile.attack_profile_id,
                "attack_paths": len(attack_profile.risk_paths),
                "attack_specs": len(specs),
                "risk_types": sorted(
                    {
                        str(spec.metadata.get("risk_type"))
                        for spec in specs
                        if spec.metadata.get("risk_type")
                    }
                ),
                "path_ids": [
                    item.path_id for item in attack_profile.risk_paths
                ],
            }
            _write_json(
                output_root / "bundle-manifest.json",
                {
                    "schema_version": "task15-profile-bundle-v0.1",
                    "mode": mode,
                    **binding,
                    "files": {
                        "agent-profile-v0.2.json": _sha256(profile_path),
                        "attack-profile-v0.1.json": _sha256(attack_profile_path),
                        "attack-specs.json": _sha256(attack_specs_path),
                        "evidence-index.json": _sha256(evidence_index_path),
                    },
                },
            )
            _write_json(
                artifacts_root
                / f"{summary_prefix}-{agent_id}-profile-summary.json",
                _profile_summary(profile, attack_profile, profile_sha256),
            )
            handoff_summary[agent_id] = binding
            result[agent_id] = {
                "status": status.status,
                "completeness": profile.completeness.conclusion,
                "nodes": len(profile.nodes),
                "risk_paths": len(profile.risk_paths),
                "attack_specs": len(specs),
                "config_digest": config_digest,
                "profile_id": profile.profile_id,
                "profile_sha256": profile_sha256,
            }

        smoke = _desktop_http_smoke(
            agents_root,
            Path(temporary) / "smoke-storage",
        )

    _write_json(
        artifacts_root / f"{summary_prefix}-attack-handoff-summary.json",
        handoff_summary,
    )
    _write_json(
        artifacts_root / f"{summary_prefix}-desktop-http-smoke.json",
        smoke,
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate offline or Docker-backed Task 15 artifacts."
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--artifacts-root",
        type=Path,
        default=Path("artifacts"),
    )
    parser.add_argument(
        "--mode",
        choices=("partial", "docker"),
        default="partial",
        help="partial is offline; docker runs the production probe but remains partial without an independent observer",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    artifacts_root = args.artifacts_root
    if not artifacts_root.is_absolute():
        artifacts_root = repo_root / artifacts_root
    result = generate(
        repo_root=repo_root,
        artifacts_root=artifacts_root,
        mode=args.mode,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
