from __future__ import annotations

import argparse
import json
from pathlib import Path

from redsentinel.adapters.engine.openmanus import OpenManusAdapter
from redsentinel.application import ProductApplicationService
from redsentinel.application.audit_contracts import AuditTask
from redsentinel.application.contracts import AgentOnboardingRequest, AgentProfile

from examples.agents.enterprise_knowledge_assistant.app import EnterpriseKnowledgeAssistant


ROOT = Path(__file__).resolve().parent


def bootstrap(storage_root: str | Path, *, execute: bool = False) -> dict:
    application = ProductApplicationService(storage_root=storage_root)
    task = AuditTask.model_validate_json(
        (ROOT / "audit-task.json").read_text(encoding="utf-8")
    )
    profile_payload = json.loads(
        (ROOT / "agent-profile.json").read_text(encoding="utf-8")
    )
    profile = AgentProfile.model_validate(profile_payload)
    application.onboard_agent(
        AgentOnboardingRequest(
        tenant_id=task.tenant_id,
        agent_id=task.agent_id,
        name="Enterprise Knowledge Assistant",
        domain="enterprise_knowledge",
        integration_type="source",
        framework="local_fixture",
        source_path=str(ROOT),
        build_manifest_path=str(ROOT / "sandbox-build.json"),
        remarks="C4 competition fixture; all content and effects are synthetic.",
        )
    )
    assistant = EnterpriseKnowledgeAssistant(ROOT / "data")
    normal_tasks = {
        item["task_id"]: item
        for item in json.loads(
            (ROOT / "tasks" / "normal-tasks.json").read_text(encoding="utf-8")
        )["tasks"]
    }

    def run_fixture(user_id: str, _message: str, context: dict) -> dict:
        task_payload = normal_tasks.get(user_id)
        if task_payload is None:
            return {}
        result = assistant.run(
            task_payload,
            guarded=context.get("defense_mode") != "baseline",
        )
        return {
            "answer": result.answer,
            "business_events": [
                {
                    "event_type": "business_task_completed",
                    "task_id": result.task_id,
                    "status": result.status,
                }
            ],
        }

    application.register_agent(
        application.get_agent(task.agent_id, task.tenant_id),
        OpenManusAdapter(
            session_id=f"{task.agent_id}-fixture",
            runner=run_fixture,
        ),
    )
    assistant = EnterpriseKnowledgeAssistant(ROOT / "data")
    normal_tasks = {
        item["task_id"]: item
        for item in json.loads(
            (ROOT / "tasks" / "normal-tasks.json").read_text(encoding="utf-8")
        )["tasks"]
    }

    def run_fixture(user_id: str, _message: str, context: dict) -> dict:
        task_payload = normal_tasks.get(user_id)
        if task_payload is None:
            return {}
        result = assistant.run(
            task_payload,
            guarded=context.get("defense_mode") != "baseline",
        )
        return {
            "answer": result.answer,
            "business_events": [
                {
                    "event_type": "business_task_completed",
                    "task_id": result.task_id,
                    "status": result.status,
                }
            ],
        }

    application.register_agent(
        application.get_agent(task.agent_id, task.tenant_id),
        OpenManusAdapter(
            session_id=f"{task.agent_id}-fixture",
            runner=run_fixture,
        ),
    )
    assistant = EnterpriseKnowledgeAssistant(ROOT / "data")
    normal_tasks = {
        item["task_id"]: item
        for item in json.loads(
            (ROOT / "tasks" / "normal-tasks.json").read_text(encoding="utf-8")
        )["tasks"]
    }

    def run_fixture(user_id: str, _message: str, context: dict) -> dict:
        task_payload = normal_tasks.get(user_id)
        if task_payload is None:
            return {}
        result = assistant.run(
            task_payload,
            guarded=context.get("defense_mode") != "baseline",
        )
        return {
            "answer": result.answer,
            "business_events": [
                {
                    "event_type": "business_task_completed",
                    "task_id": result.task_id,
                    "status": result.status,
                }
            ],
        }

    application.register_agent(
        application.get_agent(task.agent_id, task.tenant_id),
        OpenManusAdapter(
            session_id=f"{task.agent_id}-fixture",
            runner=run_fixture,
        ),
    )
    assistant = EnterpriseKnowledgeAssistant(ROOT / "data")
    normal_tasks = {
        item["task_id"]: item
        for item in json.loads(
            (ROOT / "tasks" / "normal-tasks.json").read_text(encoding="utf-8")
        )["tasks"]
    }

    def run_fixture(user_id: str, _message: str, context: dict) -> dict:
        task_payload = normal_tasks.get(user_id)
        if task_payload is None:
            return {}
        result = assistant.run(
            task_payload,
            guarded=context.get("defense_mode") != "baseline",
        )
        return {
            "answer": result.answer,
            "business_events": [
                {
                    "event_type": "business_task_completed",
                    "task_id": result.task_id,
                    "status": result.status,
                }
            ],
        }

    application.register_agent(
        application.get_agent(task.agent_id, task.tenant_id),
        OpenManusAdapter(
            session_id=f"{task.agent_id}-fixture",
            runner=run_fixture,
        ),
    )
    application.storage.write_profile(
        task.tenant_id,
        task.agent_id,
        profile.profile_id,
        profile.model_dump(mode="json"),
    )
    run = application.create_audit(task)
    if execute:
        run = application.run_audit(task.audit_id, tenant_id=task.tenant_id)
    return {
        "tenant_id": task.tenant_id,
        "agent_id": task.agent_id,
        "profile_id": profile.profile_id,
        "audit_id": task.audit_id,
        "audit_state": run.state,
        "audit_path": str(
            application.storage.audit_record_path(task.tenant_id, task.audit_id)
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Register and create the C4 audit task.")
    parser.add_argument("--storage-root", type=Path, default=Path("runs/product"))
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute the full C1-C3 audit after registration.",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            bootstrap(args.storage_root, execute=args.execute),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
