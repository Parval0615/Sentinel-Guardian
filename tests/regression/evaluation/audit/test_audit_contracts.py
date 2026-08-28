from __future__ import annotations

import pytest
from pydantic import ValidationError

from redsentinel.application.audit_contracts import (
    AuditPlan,
    AuditPlanItem,
    AuditTask,
    BusinessTask,
    ReleaseDecision,
)
from redsentinel.core.models import EvidenceRef


def _plan_item(scenario_id: str) -> AuditPlanItem:
    return AuditPlanItem(
        scenario_id=scenario_id,
        risk_surface="prompt_injection",
        target_node="llm_input",
        rationale="Exercise the authorized prompt boundary.",
        priority=1,
        expected_evidence=["trajectory"],
    )


def test_audit_plan_rejects_duplicate_scenarios() -> None:
    with pytest.raises(ValidationError, match="scenario ids must be unique"):
        AuditPlan(
            audit_id="audit-1",
            profile_id="profile-1",
            source="rule_fallback",
            items=[_plan_item("prompt-injection"), _plan_item("prompt-injection")],
            normal_task_ids=["normal-1"],
            stop_conditions=["all planned scenarios completed"],
        )




















def test_audit_task_rejects_duplicate_normal_task_ids() -> None:
    task = BusinessTask(
        task_id="normal-1",
        prompt="Summarize the public document.",
        success_criteria=["Returns a grounded summary."],
    )

    with pytest.raises(ValidationError, match="normal task ids must be unique"):
        AuditTask(
            agent_id="agent-1",
            normal_tasks=[task, task],
            security_goals=["Reject injected instructions."],
            authorized_risk_surfaces=["prompt_injection"],
        )


def test_audit_task_rejects_blank_or_duplicate_policy_values() -> None:
    task = BusinessTask(
        task_id="normal-1",
        prompt="Summarize the public document.",
        success_criteria=["Returns a grounded summary."],
    )

    with pytest.raises(ValidationError, match="security goals must not contain blank"):
        AuditTask(
            agent_id="agent-1",
            normal_tasks=[task],
            security_goals=["  "],
            authorized_risk_surfaces=["prompt_injection"],
        )
    with pytest.raises(ValidationError, match="authorized risk surfaces must be unique"):
        AuditTask(
            agent_id="agent-1",
            normal_tasks=[task],
            security_goals=["Reject injected instructions."],
            authorized_risk_surfaces=["prompt_injection", "prompt_injection"],
        )


def test_audit_plan_rejects_duplicate_priorities() -> None:
    with pytest.raises(ValidationError, match="priorities must be unique"):
        AuditPlan(
            audit_id="audit-1",
            profile_id="profile-1",
            source="rule_fallback",
            items=[_plan_item("prompt-injection"), _plan_item("path-traversal")],
            normal_task_ids=["normal-1"],
            stop_conditions=["all planned scenarios completed"],
        )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"evidence_complete": False}, "complete evidence"),
        ({"comparison_id": None}, "baseline, guarded, and comparison ids"),
        ({"clean_utility_rate": None}, "measured clean utility"),
        (
            {"evidence_refs": [EvidenceRef(ref="report.json", kind="report")]},
            "report and trajectory evidence",
        ),
    ],
)
def test_allow_release_requires_complete_paired_evidence(
    updates: dict[str, object],
    message: str,
) -> None:
    payload = {
        "audit_id": "audit-1",
        "decision": "allow_release",
        "reasons": ["Guarded evaluation passed."],
        "baseline_evaluation_id": "eval-baseline",
        "guarded_evaluation_id": "eval-guarded",
        "comparison_id": "comparison-1",
        "clean_utility_rate": 1.0,
        "evidence_complete": True,
        "evidence_refs": [
            EvidenceRef(ref="report.json", kind="report"),
            EvidenceRef(ref="trajectory.jsonl", kind="trajectory"),
        ],
    }
    payload.update(updates)

    with pytest.raises(ValidationError, match=message):
        ReleaseDecision.model_validate(payload)


def test_non_release_decision_can_record_incomplete_evidence() -> None:
    decision = ReleaseDecision(
        audit_id="audit-1",
        decision="manual_review",
        reasons=["Runtime evidence is incomplete."],
        evidence_complete=False,
    )

    assert decision.decision == "manual_review"
