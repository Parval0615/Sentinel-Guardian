from __future__ import annotations

from redsentinel.application.audit_contracts import (
    AuditBudget,
    AuditPlannerCallEvidence,
    AuditTask,
    BusinessTask,
)
from redsentinel.application.contracts import AgentProfile, AgentProfileNode, BenchmarkCase
from redsentinel.application.engine.audit_planner import AuditPlanner
from redsentinel.application.engine.llm_gateway import JsonLLMResult
from redsentinel.core.models import EvidenceRef


def _task(*, max_scenarios: int = 2) -> AuditTask:
    return AuditTask(
        audit_id="audit-1",
        agent_id="agent-1",
        normal_tasks=[
            BusinessTask(
                task_id="normal-1",
                prompt="Summarize the public document.",
                success_criteria=["Returns a grounded summary."],
            )
        ],
        security_goals=["Reject injected instructions."],
        authorized_risk_surfaces=["prompt_injection"],
        allowed_scenarios=["prompt-injection", "unpaired"],
        benchmark_id="benchmark-1",
        benchmark_version="v0.1",
        budget=AuditBudget(max_scenarios=max_scenarios),
    )


def _profile() -> AgentProfile:
    return AgentProfile(
        profile_id="profile-1",
        agent_id="agent-1",
        nodes=[
            AgentProfileNode(
                node_id="llm_input",
                node_type="llm",
                risk_surfaces=["prompt_injection"],
            )
        ],
        risk_surface=["prompt_injection"],
    )


def _case(
    case_id: str,
    case_type: str,
    scenario_id: str,
    *,
    target_node: str = "llm_input",
) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        benchmark_id="benchmark-1",
        version="v0.1",
        case_type=case_type,
        prompt=f"{case_type} prompt",
        target_node=target_node,
        expected_decision="block" if case_type == "attack" else "allow",
        severity="high",
        tags=[scenario_id, "prompt_injection"],
    )


def _cases() -> list[BenchmarkCase]:
    return [
        _case("attack-1", "attack", "prompt-injection"),
        _case("clean-1", "clean", "prompt-injection"),
        _case("attack-2", "attack", "unpaired"),
    ]


class _Gateway:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.call_count = 0

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
    ) -> JsonLLMResult:
        self.call_count += 1
        return JsonLLMResult(
            ok=True,
            payload=self.payload,
            model="planner-test",
            provider_host="local",
            latency_ms=1.0,
        )


def test_fallback_selects_only_authorized_paired_scenarios() -> None:
    plan = AuditPlanner().plan(_task(), _profile(), _cases())

    assert plan.source == "rule_fallback"
    assert [item.scenario_id for item in plan.items] == ["prompt-injection"]
    assert plan.items[0].risk_surface == "prompt_injection"
    assert plan.normal_task_ids == ["normal-1"]
    assert "deterministic fallback" in plan.warnings[0]


def test_llm_cannot_add_scenarios_outside_policy_candidates() -> None:
    gateway = _Gateway(
        {
            "items": [
                {
                    "scenario_id": "invented",
                    "rationale": "Not present in the benchmark.",
                    "expected_evidence": ["trajectory"],
                }
            ],
            "stop_conditions": ["all planned scenarios completed"],
        }
    )

    plan = AuditPlanner(gateway=gateway).plan(_task(), _profile(), _cases())

    assert plan.source == "rule_fallback"
    assert [item.scenario_id for item in plan.items] == ["prompt-injection"]
    assert "LLM plan rejected" in plan.warnings[0]




















def test_rejected_llm_plan_keeps_sanitized_call_evidence() -> None:
    recorded: list[AuditPlannerCallEvidence] = []

    def write_evidence(evidence: AuditPlannerCallEvidence) -> EvidenceRef:
        recorded.append(evidence)
        return EvidenceRef(
            ref="/tenant/audits/audit-1/planner-call.json",
            kind="runtime",
        )

    gateway = _Gateway(
        {
            "items": [
                {
                    "scenario_id": "invented",
                    "rationale": "Not present in the benchmark.",
                    "expected_evidence": ["trajectory"],
                }
            ]
        }
    )
    plan = AuditPlanner(
        gateway=gateway,
        evidence_writer=write_evidence,
    ).plan(_task(), _profile(), _cases())

    assert plan.source == "rule_fallback"
    assert plan.call_evidence_refs[0].kind == "runtime"
    assert len(recorded) == 1
    evidence = recorded[0]
    assert evidence.outcome == "rejected"
    assert evidence.model == "planner-test"
    assert evidence.system_prompt_sha256
    assert evidence.user_prompt_sha256
    assert "invented" not in evidence.model_dump_json()


def test_zero_model_call_budget_skips_llm_planner() -> None:
    gateway = _Gateway({"items": []})
    task = _task().model_copy(
        update={"budget": AuditBudget(max_scenarios=2, max_model_calls=0)}
    )

    plan = AuditPlanner(gateway=gateway).plan(task, _profile(), _cases())

    assert gateway.call_count == 0
    assert plan.source == "rule_fallback"
    assert "model-call budget is zero" in plan.warnings[0]


def test_builtin_direct_injection_matches_prompt_injection_profile() -> None:
    task = _task().model_copy(
        update={
            "authorized_risk_surfaces": ["direct_injection"],
            "allowed_scenarios": ["direct-injection-system-prompt"],
        }
    )
    cases = [
        _case(
            "direct-attack",
            "attack",
            "direct-injection-system-prompt",
            target_node="direct_injection",
        ),
        _case(
            "direct-clean",
            "clean",
            "direct-injection-system-prompt",
            target_node="direct_injection",
        ),
    ]

    plan = AuditPlanner().plan(task, _profile(), cases)

    assert [item.scenario_id for item in plan.items] == ["direct-injection-system-prompt"]
    assert plan.items[0].risk_surface == "direct_injection"
