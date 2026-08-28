from __future__ import annotations

from redsentinel.application.audit_contracts import (
    AuditPlan,
    AuditPlanItem,
    AuditTask,
    BusinessTask,
    DefensePlan,
)
from redsentinel.application.engine.storage import ProductStorage


def test_audit_documents_round_trip_without_undeclared_metadata(tmp_path) -> None:
    storage = ProductStorage(tmp_path)
    task = AuditTask(
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
        security_goals=["Prevent prompt injection."],
        authorized_risk_surfaces=["prompt_injection"],
    )
    plan = AuditPlan(
        audit_id=task.audit_id,
        profile_id="profile-1",
        source="rule_fallback",
        items=[
            AuditPlanItem(
                scenario_id="prompt-injection",
                risk_surface="prompt_injection",
                target_node="llm_input",
                rationale="Covers the authorized input boundary.",
                priority=1,
                expected_evidence=["trajectory"],
            )
        ],
        normal_task_ids=["normal-1"],
        stop_conditions=["all planned scenarios completed"],
    )
    defense_plan = DefensePlan(
        audit_id=task.audit_id,
        source_evaluation_id="eval-baseline",
        utility_constraints={"minimum_clean_utility": 0.95},
    )

    storage.write_audit_task("tenant-1", "audit-1", task.model_dump(mode="json"))
    storage.write_audit_plan("tenant-1", "audit-1", plan.model_dump(mode="json"))
    storage.write_audit_defense_plan(
        "tenant-1",
        "audit-1",
        defense_plan.model_dump(mode="json"),
    )

    assert AuditTask.model_validate(storage.read_audit_task("tenant-1", "audit-1")) == task
    assert AuditPlan.model_validate(storage.read_audit_plan("tenant-1", "audit-1")) == plan
    assert (
        DefensePlan.model_validate(storage.read_audit_defense_plan("tenant-1", "audit-1"))
        == defense_plan
    )
