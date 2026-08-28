from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from redsentinel.application.audit_contracts import AuditPlan, AuditTask
from redsentinel.application.contracts import AgentProfile, BenchmarkCase

_PROFILE_RISK_ALIASES = {
    "direct_injection": {"prompt_injection"},
    "data_exfiltration": {"data_boundary_violation", "sensitive_output_leakage"},
    "goal_perturbation": {"goal_drift"},
    "privilege_escalation": {"tool_abuse"},
}


class AuditPolicyError(ValueError):
    pass


class AuditPolicyValidator:
    """Constrain generated plans to authorized, paired benchmark scenarios."""

    def candidate_scenarios(
        self,
        task: AuditTask,
        profile: AgentProfile,
        cases: Sequence[BenchmarkCase],
    ) -> dict[str, list[BenchmarkCase]]:
        grouped: dict[str, list[BenchmarkCase]] = defaultdict(list)
        for case in cases:
            grouped[_scenario_id(case)].append(case)

        allowed: dict[str, list[BenchmarkCase]] = {}
        for scenario_id, scenario_cases in sorted(grouped.items()):
            case_types = {case.case_type for case in scenario_cases}
            if case_types != {"attack", "clean"}:
                continue
            if task.allowed_scenarios and scenario_id not in task.allowed_scenarios:
                continue
            attack_case = next(case for case in scenario_cases if case.case_type == "attack")
            if not _risk_is_authorized(attack_case, task.authorized_risk_surfaces):
                continue
            if not _profile_supports_case(profile, attack_case):
                continue
            allowed[scenario_id] = sorted(scenario_cases, key=lambda item: item.case_type)
        return allowed

    def validate(
        self,
        task: AuditTask,
        profile: AgentProfile,
        cases: Sequence[BenchmarkCase],
        plan: AuditPlan,
        *,
        candidate_scenario_ids: set[str] | None = None,
    ) -> AuditPlan:
        if plan.audit_id != task.audit_id:
            raise AuditPolicyError("audit plan does not belong to the task")
        if plan.profile_id != profile.profile_id:
            raise AuditPolicyError("audit plan does not reference the current profile")

        candidates = self.candidate_scenarios(task, profile, cases)
        if not candidates:
            raise AuditPolicyError("no authorized paired benchmark scenarios are available")

        selected = []
        warnings = list(plan.warnings)
        for item in sorted(plan.items, key=lambda value: value.priority):
            if (
                item.scenario_id not in candidates
                or (
                    candidate_scenario_ids is not None
                    and item.scenario_id not in candidate_scenario_ids
                )
            ):
                warnings.append(f"Removed unauthorized or incompatible scenario: {item.scenario_id}")
                continue
            attack_case = next(case for case in candidates[item.scenario_id] if case.case_type == "attack")
            selected.append(
                item.model_copy(
                    update={
                        "risk_surface": _authorized_risk_surface(
                            attack_case,
                            task.authorized_risk_surfaces,
                        )
                        or attack_case.target_node,
                        "target_node": attack_case.target_node,
                        "metadata": {
                            **item.metadata,
                            "attack_case_id": attack_case.case_id,
                            "attack_tags": attack_case.tags,
                        },
                    }
                )
            )
            if len(selected) >= task.budget.max_scenarios:
                break

        if not selected:
            raise AuditPolicyError("generated plan contains no authorized executable scenarios")

        task_ids = [item.task_id for item in task.normal_tasks]
        return plan.model_copy(
            update={
                "items": [
                    item.model_copy(update={"priority": index})
                    for index, item in enumerate(selected, start=1)
                ],
                "normal_task_ids": task_ids,
                "warnings": warnings,
            }
        )


def _scenario_id(case: BenchmarkCase) -> str:
    if case.tags:
        return case.tags[0]
    suffix = f"-{case.case_type}"
    return case.case_id[: -len(suffix)] if case.case_id.endswith(suffix) else case.case_id


def _risk_is_authorized(case: BenchmarkCase, authorized: Sequence[str]) -> bool:
    return _authorized_risk_surface(case, authorized) is not None


def _authorized_risk_surface(
    case: BenchmarkCase,
    authorized: Sequence[str],
) -> str | None:
    values = {case.target_node.casefold(), *(tag.casefold() for tag in case.tags)}
    for risk in authorized:
        normalized = risk.casefold()
        if normalized in values or any(normalized in value or value in normalized for value in values):
            return risk
    return None


def _profile_supports_case(profile: AgentProfile, case: BenchmarkCase) -> bool:
    risk_values = {value.casefold() for value in profile.risk_surface}
    node_values = {
        value.casefold()
        for node in profile.nodes
        for value in (node.node_id, node.node_type, *node.risk_surfaces)
    }
    target = case.target_node.casefold()
    if not risk_values and not node_values:
        return True
    profile_values = risk_values | node_values
    if any(target in value or value in target for value in profile_values):
        return True
    return bool(_PROFILE_RISK_ALIASES.get(target, set()) & profile_values)


__all__ = ["AuditPolicyError", "AuditPolicyValidator"]
