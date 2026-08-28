from __future__ import annotations

import pytest

from redsentinel.application.audit_contracts import (
    AuditTask,
    BusinessTask,
    DefenseAction,
    DefensePlan,
)
from redsentinel.application.engine.remediation import (
    RemediationInstaller,
    build_remediation_bundle,
    verify_remediation_bundle,
)
from redsentinel.application.engine.storage import ProductStorage
from redsentinel.core.models import EvidenceRef


def _task() -> AuditTask:
    return AuditTask(
        audit_id="audit-1",
        tenant_id="tenant-1",
        agent_id="agent-1",
        normal_tasks=[
            BusinessTask(
                task_id="normal-1",
                prompt="Summarize a public document.",
                success_criteria=["Summary is grounded."],
            )
        ],
        security_goals=["Reject prompt injection."],
        authorized_risk_surfaces=["prompt_injection"],
    )


def _plan() -> DefensePlan:
    return DefensePlan(
        audit_id="audit-1",
        source_evaluation_id="eval-baseline",
        actions=[
            DefenseAction(
                action_id="action-1",
                target_node="llm_input",
                guard="input_firewall",
                rationale="The baseline input boundary was bypassed.",
                evidence_refs=[
                    EvidenceRef(
                        ref="trajectory.json",
                        kind="trajectory",
                    )
                ],
            )
        ],
        utility_constraints={"minimum_clean_utility": 0.95},
    )


def test_bundle_hash_covers_remediation_policy() -> None:
    bundle = build_remediation_bundle(_task(), _plan())

    verify_remediation_bundle(bundle)
    tampered = bundle.model_copy(
        update={
            "policies": [
                bundle.policies[0].model_copy(
                    update={"guard": "monitor_policy"}
                )
            ]
        }
    )

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_remediation_bundle(tampered)


def test_installer_writes_and_verifies_sandbox_policy(tmp_path) -> None:
    storage = ProductStorage(tmp_path)
    installer = RemediationInstaller(storage)
    bundle = build_remediation_bundle(_task(), _plan())

    receipt = installer.install("tenant-1", bundle)
    installer.verify("tenant-1", bundle, receipt)
    policy = storage.read_json(storage.audit_remediation_policy_path("tenant-1", "audit-1"))

    assert receipt.status == "installed"
    assert receipt.active_guards == ["input_firewall"]
    assert receipt.installed_action_ids == ["action-1"]
    assert policy["bundle_sha256"] == bundle.artifact_sha256
    assert policy["policies"][0]["guard"] == "input_firewall"


def test_installer_rejects_modified_runtime_policy(tmp_path) -> None:
    storage = ProductStorage(tmp_path)
    installer = RemediationInstaller(storage)
    bundle = build_remediation_bundle(_task(), _plan())
    receipt = installer.install("tenant-1", bundle)
    policy_path = storage.audit_remediation_policy_path("tenant-1", "audit-1")
    policy_path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="policy SHA-256 mismatch"):
        installer.verify("tenant-1", bundle, receipt)
