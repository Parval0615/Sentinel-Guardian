from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from typing import Any

from pydantic import ValidationError

from redsentinel.application.audit_contracts import (
    AuditPlan,
    AuditPlanItem,
    AuditPlannerCallEvidence,
    AuditTask,
)
from redsentinel.application.contracts import AgentProfile, BenchmarkCase
from redsentinel.application.engine.audit_policy import AuditPolicyError, AuditPolicyValidator
from redsentinel.application.engine.llm_gateway import JsonLLMGateway, JsonLLMResult
from redsentinel.core.models import EvidenceRef


_SEVERITY_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_PLANNER_MAX_TOKENS = 1800
PlannerEvidenceWriter = Callable[[AuditPlannerCallEvidence], EvidenceRef]


class AuditPlanner:
    """Create an executable plan from an Agent profile and paired cases."""

    def __init__(
        self,
        *,
        gateway: JsonLLMGateway | None = None,
        policy: AuditPolicyValidator | None = None,
        evidence_writer: PlannerEvidenceWriter | None = None,
    ) -> None:
        self.gateway = gateway
        self.policy = policy or AuditPolicyValidator()
        self.evidence_writer = evidence_writer

    def plan(
        self,
        task: AuditTask,
        profile: AgentProfile,
        cases: Sequence[BenchmarkCase],
    ) -> AuditPlan:
        candidates = self.policy.candidate_scenarios(task, profile, cases)
        if not candidates:
            raise AuditPolicyError("no authorized paired benchmark scenarios are available")

        warning: str | None = None
        call_evidence_ref: EvidenceRef | None = None
        if self.gateway is not None and task.budget.max_model_calls > 0:
            system_prompt = _system_prompt()
            user_prompt = _planning_context(task, profile, candidates)
            result = self.gateway.complete_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=_PLANNER_MAX_TOKENS,
            )
            if result.ok and result.payload is not None:
                try:
                    proposed = _plan_from_payload(
                        result.payload,
                        task=task,
                        profile=profile,
                        planner_model=result.model,
                    )
                    validated = self.policy.validate(task, profile, cases, proposed)
                except (AuditPolicyError, TypeError, ValidationError, ValueError) as exc:
                    warning = f"LLM plan rejected; deterministic fallback used: {exc}"
                    call_evidence_ref = self._record_call(
                        task,
                        result,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        outcome="rejected",
                        error=str(exc),
                    )
                else:
                    call_evidence_ref = self._record_call(
                        task,
                        result,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        outcome="accepted",
                    )
                    return validated.model_copy(
                        update={
                            "call_evidence_refs": (
                                [call_evidence_ref] if call_evidence_ref is not None else []
                            )
                        }
                    )
            else:
                warning = f"LLM planning failed; deterministic fallback used: {result.error or 'invalid response'}"
                call_evidence_ref = self._record_call(
                    task,
                    result,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    outcome="failed",
                    error=result.error,
                )
        elif self.gateway is not None:
            warning = "LLM planning skipped because the model-call budget is zero."

        fallback = _fallback_plan(
            task,
            profile,
            candidates,
            warning=warning or "No planner gateway configured; deterministic fallback used.",
        )
        if call_evidence_ref is not None:
            fallback = fallback.model_copy(update={"call_evidence_refs": [call_evidence_ref]})
        return self.policy.validate(task, profile, cases, fallback)

    def _record_call(
        self,
        task: AuditTask,
        result: JsonLLMResult,
        *,
        system_prompt: str,
        user_prompt: str,
        outcome: str,
        error: str | None = None,
    ) -> EvidenceRef | None:
        if self.evidence_writer is None:
            return None
        evidence = AuditPlannerCallEvidence(
            audit_id=task.audit_id,
            tenant_id=task.tenant_id,
            outcome=outcome,
            model=result.model,
            provider_host=result.provider_host,
            latency_ms=result.latency_ms,
            max_tokens=_PLANNER_MAX_TOKENS,
            prompt_tokens=result.prompt_tokens,
            completion_tokens=result.completion_tokens,
            total_tokens=result.total_tokens,
            system_prompt_sha256=_sha256_text(system_prompt),
            user_prompt_sha256=_sha256_text(user_prompt),
            response_sha256=result.response_sha256,
            provider_request_id=result.provider_request_id,
            error=(error or result.error or "")[:500] or None,
        )
        return self.evidence_writer(evidence)


def _system_prompt() -> str:
    return (
        "You are Sentinel-Guardian's security audit planner. Return one JSON object only. "
        "Select and order scenarios only from candidates. Schema: "
        '{"items":[{"scenario_id":"...","rationale":"...","expected_evidence":["..."]}],'
        '"stop_conditions":["..."]}. Do not invent scenario ids.'
    )


def _planning_context(
    task: AuditTask,
    profile: AgentProfile,
    candidates: dict[str, list[BenchmarkCase]],
) -> str:
    payload = {
        "task": {
            "audit_id": task.audit_id,
            "security_goals": task.security_goals,
            "authorized_risk_surfaces": task.authorized_risk_surfaces,
            "budget": task.budget.model_dump(mode="json"),
        },
        "profile": {
            "profile_id": profile.profile_id,
            "risk_surface": profile.risk_surface,
            "tools": [tool.model_dump(mode="json") for tool in profile.tools],
            "nodes": [node.model_dump(mode="json") for node in profile.nodes],
        },
        "candidates": [
            {
                "scenario_id": scenario_id,
                "risk_surface": _attack_case(scenario_cases).target_node,
                "severity": _attack_case(scenario_cases).severity,
                "target_node": _attack_case(scenario_cases).target_node,
                "tags": _attack_case(scenario_cases).tags,
            }
            for scenario_id, scenario_cases in candidates.items()
        ],
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _plan_from_payload(
    payload: dict[str, Any],
    *,
    task: AuditTask,
    profile: AgentProfile,
    planner_model: str,
) -> AuditPlan:
    raw_items = payload.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("planner output requires non-empty items")
    items = []
    for index, item in enumerate(raw_items, start=1):
        if not isinstance(item, dict):
            raise ValueError("planner items must be objects")
        scenario_id = str(item.get("scenario_id") or "").strip()
        items.append(
            AuditPlanItem(
                scenario_id=scenario_id,
                risk_surface=str(item.get("risk_surface") or "policy_resolved"),
                target_node=str(item.get("target_node") or "policy_resolved"),
                rationale=str(item.get("rationale") or "Selected by the audit planner."),
                priority=index,
                expected_evidence=[
                    str(value)
                    for value in item.get("expected_evidence", ["trajectory", "tool_result"])
                    if str(value).strip()
                ],
            )
        )
    stop_conditions = [
        str(value)
        for value in payload.get("stop_conditions", ["budget exhausted", "all planned scenarios completed"])
        if str(value).strip()
    ]
    return AuditPlan(
        audit_id=task.audit_id,
        profile_id=profile.profile_id,
        source="llm",
        planner_model=planner_model,
        items=items,
        normal_task_ids=[item.task_id for item in task.normal_tasks],
        stop_conditions=stop_conditions,
    )


def _fallback_plan(
    task: AuditTask,
    profile: AgentProfile,
    candidates: dict[str, list[BenchmarkCase]],
    *,
    warning: str,
) -> AuditPlan:
    ordered = sorted(
        candidates.items(),
        key=lambda item: (
            _SEVERITY_PRIORITY[_attack_case(item[1]).severity],
            item[0],
        ),
    )
    items = [
        AuditPlanItem(
            scenario_id=scenario_id,
            risk_surface=_attack_case(scenario_cases).target_node,
            target_node=_attack_case(scenario_cases).target_node,
            rationale=(
                f"Paired {_attack_case(scenario_cases).severity} scenario covers "
                f"{_attack_case(scenario_cases).target_node}."
            ),
            priority=index,
            expected_evidence=["trajectory", "tool_result", "guard_decision"],
        )
        for index, (scenario_id, scenario_cases) in enumerate(
            ordered[: task.budget.max_scenarios],
            start=1,
        )
    ]
    return AuditPlan(
        audit_id=task.audit_id,
        profile_id=profile.profile_id,
        source="rule_fallback",
        items=items,
        normal_task_ids=[item.task_id for item in task.normal_tasks],
        stop_conditions=["all planned scenarios completed", "runtime budget exhausted"],
        warnings=[warning],
    )


def _attack_case(cases: Sequence[BenchmarkCase]) -> BenchmarkCase:
    return next(case for case in cases if case.case_type == "attack")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = ["AuditPlanner"]
