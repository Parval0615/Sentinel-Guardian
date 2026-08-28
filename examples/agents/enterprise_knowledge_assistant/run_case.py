from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .app import EnterpriseKnowledgeAssistant
except ImportError:
    from app import EnterpriseKnowledgeAssistant


ROOT = Path(__file__).resolve().parent


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_case(output_dir: str | Path) -> dict:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    assistant = EnterpriseKnowledgeAssistant(ROOT / "data")
    normal_tasks = load_json(ROOT / "tasks" / "normal-tasks.json")["tasks"]
    security_cases = load_json(ROOT / "tasks" / "security-cases.json")["cases"]

    baseline_normal = [assistant.run(task, guarded=False).to_dict() for task in normal_tasks]
    guarded_normal = [assistant.run(task, guarded=True).to_dict() for task in normal_tasks]
    baseline_attacks = [assistant.run(case, guarded=False).to_dict() for case in security_cases]
    guarded_attacks = [assistant.run(case, guarded=True).to_dict() for case in security_cases]

    trajectories = output / "trajectories"
    trajectories.mkdir(exist_ok=True)
    for case, baseline, guarded in zip(security_cases, baseline_attacks, guarded_attacks, strict=True):
        (trajectories / f"{case['task_id']}.json").write_text(
            json.dumps(
                {
                    "schema_version": "enterprise-knowledge-trajectory-v0.1",
                    "scenario": case,
                    "baseline": baseline,
                    "guarded": guarded,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    attack_count = len(security_cases)
    baseline_successes = sum(bool(item["effects"]) for item in baseline_attacks)
    guarded_successes = sum(bool(item["effects"]) for item in guarded_attacks)
    summary = {
        "schema_version": "enterprise-knowledge-case-result-v0.1",
        "case_id": "enterprise-knowledge-assistant-c4",
        "data_boundary": {
            "synthetic_data_only": True,
            "external_network_access": False,
            "real_enterprise_credentials": False,
        },
        "metrics": {
            "attack_case_count": attack_count,
            "baseline_asr": baseline_successes / attack_count,
            "guarded_asr": guarded_successes / attack_count,
            "defense_success_rate": (
                baseline_successes - guarded_successes
            )
            / baseline_successes,
            "baseline_clean_utility": _utility_rate(baseline_normal),
            "guarded_clean_utility": _utility_rate(guarded_normal),
        },
        "normal_tasks": {
            "baseline": baseline_normal,
            "guarded": guarded_normal,
        },
        "security_cases": {
            "baseline": baseline_attacks,
            "guarded": guarded_attacks,
        },
        "trajectory_dir": str(trajectories),
    }
    result_path = output / "case-result.json"
    result_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {**summary, "result_path": str(result_path)}


def _utility_rate(results: list[dict]) -> float:
    return sum(bool(item["business_success"]) for item in results) / len(results)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the C4 enterprise knowledge assistant fixture.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("runs/c4-enterprise-knowledge"),
    )
    args = parser.parse_args()
    result = run_case(args.output_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
