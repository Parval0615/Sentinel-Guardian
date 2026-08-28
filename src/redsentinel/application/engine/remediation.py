from __future__ import annotations

import hashlib
import json
from pathlib import Path

from redsentinel.application.audit_contracts import (
    AuditTask,
    DefensePlan,
    RemediationBundle,
    RemediationInstallation,
    RemediationPolicy,
)
from redsentinel.application.engine.storage import ProductStorage


def build_remediation_bundle(
    task: AuditTask,
    defense_plan: DefensePlan,
) -> RemediationBundle:
    payload = {
        "audit_id": task.audit_id,
        "agent_id": task.agent_id,
        "source_defense_plan_id": defense_plan.defense_plan_id,
        "source_evaluation_id": defense_plan.source_evaluation_id,
        "policies": [
            RemediationPolicy(
                action_id=action.action_id,
                target_node=action.target_node,
                guard=action.guard,
                parameters={
                    "enforcement": "block",
                    "evidence_refs": sorted({item.ref for item in action.evidence_refs}),
                },
            ).model_dump(mode="json")
            for action in defense_plan.actions
        ],
        "utility_constraints": defense_plan.utility_constraints,
        "prerequisites": [
            "Install only in an isolated audit sandbox.",
            "Preserve the baseline agent artifact unchanged.",
        ],
        "baseline_evidence": [
            evidence.model_dump(mode="json")
            for action in defense_plan.actions
            for evidence in action.evidence_refs
        ],
        "rollback_plan": [
            "Remove the generated runtime policy.",
            "Restore the frozen baseline agent artifact.",
        ],
    }
    bundle = RemediationBundle.model_validate(
        {**payload, "artifact_sha256": "0" * 64}
    )
    return bundle.model_copy(
        update={"artifact_sha256": _bundle_sha256(bundle)}
    )


def verify_remediation_bundle(bundle: RemediationBundle) -> None:
    if _bundle_sha256(bundle) != bundle.artifact_sha256:
        raise ValueError("Remediation bundle SHA-256 mismatch.")


class RemediationInstaller:
    def __init__(self, storage: ProductStorage) -> None:
        self.storage = storage

    def install(
        self,
        tenant_id: str,
        bundle: RemediationBundle,
    ) -> RemediationInstallation:
        verify_remediation_bundle(bundle)
        policy_path = self.storage.audit_remediation_policy_path(
            tenant_id,
            bundle.audit_id,
        )
        policy = {
            "schema_version": "remediation-runtime-policy-v0.1",
            "audit_id": bundle.audit_id,
            "bundle_id": bundle.bundle_id,
            "bundle_sha256": bundle.artifact_sha256,
            "active_guards": sorted({item.guard for item in bundle.policies}),
            "policies": [item.model_dump(mode="json") for item in bundle.policies],
        }
        self.storage.write_json(policy_path, policy)
        receipt = RemediationInstallation(
            audit_id=bundle.audit_id,
            bundle_id=bundle.bundle_id,
            bundle_sha256=bundle.artifact_sha256,
            policy_ref=str(policy_path),
            policy_sha256=_file_sha256(policy_path),
            active_guards=policy["active_guards"],
            installed_action_ids=[item.action_id for item in bundle.policies],
        )
        self.storage.write_audit_remediation_installation(
            tenant_id,
            bundle.audit_id,
            receipt.model_dump(mode="json"),
        )
        return receipt

    def verify(
        self,
        tenant_id: str,
        bundle: RemediationBundle,
        receipt: RemediationInstallation,
    ) -> None:
        verify_remediation_bundle(bundle)
        if receipt.audit_id != bundle.audit_id:
            raise ValueError("Remediation installation audit ID mismatch.")
        if receipt.bundle_id != bundle.bundle_id:
            raise ValueError("Remediation installation bundle ID mismatch.")
        if receipt.bundle_sha256 != bundle.artifact_sha256:
            raise ValueError("Remediation installation bundle SHA-256 mismatch.")
        policy_path = Path(receipt.policy_ref)
        tenant_root = self.storage.tenant_dir(tenant_id).resolve()
        if not policy_path.resolve().is_relative_to(tenant_root):
            raise ValueError("Remediation policy is outside the tenant storage root.")
        if not policy_path.is_file() or _file_sha256(policy_path) != receipt.policy_sha256:
            raise ValueError("Installed remediation policy SHA-256 mismatch.")
        expected_actions = [item.action_id for item in bundle.policies]
        if receipt.installed_action_ids != expected_actions:
            raise ValueError("Remediation installation action set mismatch.")

    @staticmethod
    def evaluation_policy(
        receipt: RemediationInstallation,
    ) -> dict[str, object]:
        return {
            "bundle_id": receipt.bundle_id,
            "bundle_sha256": receipt.bundle_sha256,
            "installation_id": receipt.installation_id,
            "policy_ref": receipt.policy_ref,
            "policy_sha256": receipt.policy_sha256,
            "active_guards": receipt.active_guards,
        }


def _payload_sha256(payload: dict[str, object]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _bundle_sha256(bundle: RemediationBundle) -> str:
    return _payload_sha256(
        bundle.model_dump(mode="json", exclude={"artifact_sha256"})
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "RemediationInstaller",
    "build_remediation_bundle",
    "verify_remediation_bundle",
]
