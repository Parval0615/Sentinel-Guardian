from __future__ import annotations

import hashlib
import json
from typing import Any

from redsentinel.application.image_profile_contracts import AttackProfile, ImageAgentProfile


def image_profile_sha256(profile: ImageAgentProfile) -> str:
    canonical = json.dumps(
        profile.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def build_attack_profile(profile: ImageAgentProfile) -> AttackProfile | None:
    allowed_statuses = {"verified", "supported"}
    nodes_by_id = {item.node_id: item for item in profile.nodes}
    edges_by_id = {item.edge_id: item for item in profile.edges}
    capabilities_by_id = {item.capability_id: item for item in profile.capabilities}
    permissions_by_id = {item.permission_id: item for item in profile.permissions}
    controls_by_id = {item.control_id: item for item in profile.controls}

    def path_is_eligible(path: Any) -> bool:
        dependencies = [
            *(nodes_by_id.get(item) for item in path.node_ids),
            *(edges_by_id.get(item) for item in path.edge_ids),
            *(capabilities_by_id.get(item) for item in path.capability_ids),
            *(permissions_by_id.get(item) for item in path.permission_ids),
            *(controls_by_id.get(item) for item in path.control_ids),
        ]
        return (
            path.verification_status in allowed_statuses
            and all(item is not None for item in dependencies)
            and all(item.verification_status in allowed_statuses for item in dependencies)
        )

    eligible_paths = sorted(
        (item for item in profile.risk_paths if path_is_eligible(item)),
        key=lambda item: item.path_id,
    )
    if not eligible_paths:
        return None
    node_ids = {node_id for path in eligible_paths for node_id in path.node_ids}
    edge_ids = {edge_id for path in eligible_paths for edge_id in path.edge_ids}
    capability_ids = {item for path in eligible_paths for item in path.capability_ids}
    permission_ids = {item for path in eligible_paths for item in path.permission_ids}
    control_ids = {item for path in eligible_paths for item in path.control_ids}
    nodes = sorted(
        (item for item in profile.nodes if item.node_id in node_ids),
        key=lambda item: item.node_id,
    )
    edges = sorted(
        (item for item in profile.edges if item.edge_id in edge_ids),
        key=lambda item: item.edge_id,
    )
    capabilities = sorted(
        (item for item in profile.capabilities if item.capability_id in capability_ids),
        key=lambda item: item.capability_id,
    )
    permissions = sorted(
        (item for item in profile.permissions if item.permission_id in permission_ids),
        key=lambda item: item.permission_id,
    )
    controls = sorted(
        (item for item in profile.controls if item.control_id in control_ids),
        key=lambda item: item.control_id,
    )
    framework_ids = {framework_id for node in nodes for framework_id in node.framework_ids}
    frameworks = sorted(
        (
            item
            for item in profile.frameworks
            if item.framework_id in framework_ids
            and item.verification_status in allowed_statuses
        ),
        key=lambda item: item.framework_id,
    )
    references = set(profile.image.evidence_refs)
    for claim in [
        *frameworks,
        *nodes,
        *edges,
        *capabilities,
        *permissions,
        *controls,
        *eligible_paths,
    ]:
        references.update(claim.evidence_refs)
    evidence = sorted(
        (item for item in profile.evidence if item.evidence_id in references),
        key=lambda item: item.evidence_id,
    )
    sanitized_image = profile.image.model_copy(
        update={
            "entrypoint": [],
            "command": [],
            "working_directory": "/",
            "environment_variables": [],
            "layer_digests": [],
        }
    )
    return AttackProfile(
        attack_profile_id=f"attack-profile:{profile.profile_id}",
        source_profile_id=profile.profile_id,
        source_profile_sha256=image_profile_sha256(profile),
        tenant_id=profile.tenant_id,
        agent_id=profile.agent_id,
        image=sanitized_image,
        generated_at=profile.generated_at,
        frameworks=frameworks,
        nodes=nodes,
        edges=edges,
        capabilities=capabilities,
        permissions=permissions,
        controls=controls,
        evidence=evidence,
        risk_paths=eligible_paths,
    )


__all__ = ["build_attack_profile", "image_profile_sha256"]
