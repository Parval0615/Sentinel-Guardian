import json
import shutil
from pathlib import Path

import pytest

from redsentinel.application.contracts import AgentRegistration
from redsentinel.application.engine.app import (
    ECOMMERCE_DEMO_SOURCE_PATH,
    _ecommerce_demo_source_path,
    create_app,
)
from redsentinel.application.engine.llm_gateway import JsonLLMResult


def _raw_client(tmp_path, *, raise_server_exceptions: bool = True):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    return TestClient(create_app(storage_root=tmp_path), raise_server_exceptions=raise_server_exceptions)


def _client(tmp_path, *, username: str = "private_tenant", raise_server_exceptions: bool = True):
    client = _raw_client(tmp_path, raise_server_exceptions=raise_server_exceptions)
    response = client.post(
        "/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.test",
            "password": "correct-horse-battery-staple",
        },
    )
    assert response.status_code == 200
    client.headers.update({"Authorization": f"Bearer {response.json()['access_token']}"})
    return client


def _assert_structured_error(response, status_code: int, error_code: str) -> None:
    assert response.status_code == status_code
    detail = response.json()["detail"]
    assert detail["error_code"] == error_code
    assert detail["message"]


def _source_material(tmp_path: Path, name: str = "agent-source") -> tuple[str, str]:
    source_root = tmp_path / "source-inputs" / name
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "agent.py").write_text("def run(task):\n    return task\n", encoding="utf-8")
    manifest = source_root / "sandbox-build.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "agent-sandbox-build-v0.1",
                "adapter_type": "external_sdk",
            }
        ),
        encoding="utf-8",
    )
    return str(source_root), str(manifest)


def _discovered_agent(
    root: Path,
    directory: str,
    *,
    agent_id: str,
    name: str,
    adapter_type: str,
) -> None:
    agent_root = root / directory
    agent_root.mkdir(parents=True)
    (agent_root / "agent.json").write_text(
        json.dumps(
            {
                "agent_id": agent_id,
                "name": name,
                "domain": "ecommerce" if adapter_type == "ecommerce_demo" else "general",
                "framework": "local-sdk" if adapter_type == "ecommerce_demo" else "OpenManus",
            }
        ),
        encoding="utf-8",
    )
    (agent_root / "sandbox-build.json").write_text(
        json.dumps(
            {
                "schema_version": "agent-sandbox-build-v0.1",
                "adapter_type": adapter_type,
            }
        ),
        encoding="utf-8",
    )


def test_fastapi_app_is_optional(tmp_path) -> None:
    pytest.importorskip("fastapi")
    app = create_app(storage_root=tmp_path)

    routes = {route.path for route in app.routes}
    assert "/v1/agents" in routes
    assert "/v1/agents/index-errors" in routes
    assert "/v1/agents/onboard" in routes
    assert "/v1/agents/{agent_id}" in routes
    assert "/v1/agents/{agent_id}/profile" in routes
    assert "/v1/evaluations" in routes
    assert "/v1/audits" in routes
    assert "/v1/audits/{audit_id}/execute" in routes
    assert "/v1/audits/{audit_id}" in routes
    assert "/v1/audits/{audit_id}/status" in routes
    assert "/v1/audits/{audit_id}/plan" in routes
    assert "/v1/audits/{audit_id}/evidence" in routes
    assert "/v1/audits/{audit_id}/decision" in routes
    assert "/v1/audits/{audit_id}/workspace" in routes
    assert "/v1/audits/{audit_id}/resume" in routes
    assert "/v1/audits/{audit_id}/next-round" in routes
    assert "/v1/runtime/openmanus/status" in routes
    assert "/v1/runtime/openmanus/config" in routes
    assert "/v1/runtime/models/status" in routes
    assert "/v1/runtime/audit-preflight/{agent_id}" in routes
    assert "/v1/runtime/models/{role}/test" in routes
    assert "/v1/evaluations/{evaluation_id}/next-round" in routes
    assert "/v1/reports/{report_id}" in routes
    assert "/v1/logs" in routes
    assert "/v1/logs/{evaluation_id}" in routes
    assert "/v1/dashboard/summary" in routes
    assert "/v1/benchmarks" in routes
    assert "/v1/benchmarks/{benchmark_id}/versions" in routes
    assert "/v1/benchmarks/{benchmark_id}/versions/{version}" in routes


def test_openmanus_runtime_configuration_stays_out_of_response(
    tmp_path,
    monkeypatch,
) -> None:
    for name in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL"):
        monkeypatch.delenv(name, raising=False)
    client = _client(tmp_path)

    before = client.get("/v1/runtime/openmanus/status")
    configured = client.post(
        "/v1/runtime/openmanus/config",
        json={
            "api_key": "competition-secret",
            "base_url": "https://models.example.test/v1",
            "model": "openmanus-test-model",
        },
    )
    after = client.get("/v1/runtime/openmanus/status")

    assert before.status_code == 200
    assert before.json()["configured"] is False
    assert configured.status_code == 200
    assert configured.json() == {
        "configured": True,
        "base_url": "https://models.example.test",
        "model": "openmanus-test-model",
    }
    assert after.json() == configured.json()
    assert "competition-secret" not in configured.text


def test_model_runtime_test_tracks_each_role_without_exposing_keys(
    tmp_path,
    monkeypatch,
) -> None:
    client = _client(tmp_path)
    registry = client.app.state.model_runtime

    class Gateway:
        def complete_json(self, **_kwargs):
            return JsonLLMResult(
                ok=True,
                payload={"ok": True},
                model="competition-model",
                provider_host="models.example.test",
                latency_ms=4.0,
            )

    monkeypatch.setattr(registry, "_gateway", lambda _configuration: Gateway())
    payload = {
        "api_key": "role-secret",
        "base_url": "https://models.example.test/v1",
        "model": "competition-model",
    }

    before = client.get("/v1/runtime/models/status")
    tested = client.post("/v1/runtime/models/attack/test", json=payload)
    after = client.get("/v1/runtime/models/status")

    assert before.status_code == 200
    assert all(item["tested"] is False for item in before.json())
    assert tested.status_code == 200
    assert tested.json()["role"] == "attack"
    assert tested.json()["tested"] is True
    assert "role-secret" not in tested.text
    assert next(item for item in after.json() if item["role"] == "attack") == tested.json()

    other = client.post(
        "/v1/auth/register",
        json={
            "username": "other_runtime_tenant",
            "email": "other_runtime_tenant@example.test",
            "password": "correct-horse-battery-staple",
        },
    )
    client.headers.update(
        {"Authorization": f"Bearer {other.json()['access_token']}"}
    )
    isolated = client.get("/v1/runtime/models/status")
    assert all(item["tested"] is False for item in isolated.json())


def test_model_runtime_failed_test_is_not_ready(tmp_path, monkeypatch) -> None:
    client = _client(tmp_path)
    registry = client.app.state.model_runtime

    class Gateway:
        def complete_json(self, **_kwargs):
            return JsonLLMResult(
                ok=False,
                payload=None,
                model="broken-model",
                provider_host="models.example.test",
                latency_ms=4.0,
                error="HTTP 401",
            )

    monkeypatch.setattr(registry, "_gateway", lambda _configuration: Gateway())
    response = client.post(
        "/v1/runtime/models/defense/test",
        json={
            "api_key": "invalid-secret",
            "base_url": "https://models.example.test/v1",
            "model": "broken-model",
        },
    )

    assert response.status_code == 200
    assert response.json()["configured"] is True
    assert response.json()["tested"] is False
    assert response.json()["error"] == "HTTP 401"
    assert "invalid-secret" not in response.text


def test_openmanus_audit_requires_all_model_roles_to_be_tested(tmp_path) -> None:
    client = _client(tmp_path)
    client.app.state.service.register_agent(
        AgentRegistration(
            agent_id="openmanus-model-gate",
            name="OpenManus Model Gate",
            integration_type="docker",
            adapter_type="openmanus",
            framework="OpenManus",
            status="ready",
        )
    )

    response = client.post(
        "/v1/audits",
        json={
            "agent_id": "openmanus-model-gate",
            "normal_tasks": [
                {
                    "task_id": "normal-1",
                    "prompt": "Calculate 17 times 23.",
                    "success_criteria": ["Returns 391."],
                }
            ],
            "security_goals": ["Reject prompt injection."],
            "authorized_risk_surfaces": ["prompt_injection"],
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"]["error_code"] == "audit_creation_failed"
    assert "target, attack, defense" in response.json()["detail"]["message"]


def test_product_api_returns_4xx_for_lookup_and_payload_errors(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path, raise_server_exceptions=False)

    _assert_structured_error(client.post("/v1/agents/missing_agent/sessions"), 404, "session_agent_not_found")
    _assert_structured_error(client.get("/v1/evaluations/missing_eval"), 404, "evaluation_not_found")
    _assert_structured_error(client.get("/v1/reports/missing_report"), 404, "report_not_found")
    _assert_structured_error(client.post("/v1/comparisons", json={}), 422, "invalid_comparison_request")
    _assert_structured_error(
        client.post("/v1/comparisons", json={"before_report_id": "missing_before", "after_report_id": "missing_after"}),
        404,
        "comparison_failed",
    )
    _assert_structured_error(client.post("/v1/trajectories", json={}), 422, "invalid_trajectory_request")
    _assert_structured_error(
        client.post("/v1/trajectories", json={"agent_id": "missing_agent", "trajectory": {"steps": []}}),
        404,
        "trajectory_upload_failed",
    )
    client.post("/v1/agents", json={"agent_id": "trace_agent", "name": "Trace Agent"})
    _assert_structured_error(
        client.post("/v1/trajectories", json={"agent_id": "trace_agent", "trajectory": {}}),
        422,
        "invalid_trajectory_request",
    )


def test_product_api_returns_structured_errors_for_empty_payloads(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path, raise_server_exceptions=False)

    _assert_structured_error(client.post("/v1/agents/onboard", json={}), 422, "invalid_onboarding_request")
    _assert_structured_error(client.post("/v1/evaluations", json={}), 422, "invalid_evaluation_request")
    _assert_structured_error(client.post("/v1/comparisons"), 422, "invalid_comparison_request")
    _assert_structured_error(client.post("/v1/trajectories"), 422, "invalid_trajectory_request")
    _assert_structured_error(client.get("/v1/logs"), 422, "invalid_log_request")


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("POST", "/v1/agents/onboard", {}),
        ("POST", "/v1/agents", {"agent_id": "agent_001", "name": "Agent"}),
        ("GET", "/v1/agents/agent_001", None),
        ("GET", "/v1/agents/agent_001/profile", None),
        ("POST", "/v1/agents/agent_001/sessions", None),
        ("GET", "/v1/dashboard/summary?agent_id=agent_001", None),
        ("POST", "/v1/evaluations", {}),
        ("POST", "/v1/audits", {}),
        ("POST", "/v1/audits/audit_001/execute", None),
        ("GET", "/v1/audits/audit_001", None),
        ("GET", "/v1/audits/audit_001/status", None),
        ("GET", "/v1/audits/audit_001/plan", None),
        ("GET", "/v1/audits/audit_001/evidence", None),
        ("GET", "/v1/audits/audit_001/decision", None),
        ("GET", "/v1/audits/audit_001/workspace", None),
        ("POST", "/v1/audits/audit_001/resume", None),
        ("GET", "/v1/evaluations/eval_001", None),
        ("POST", "/v1/evaluations/eval_001/next-round", None),
        ("GET", "/v1/reports/report_001", None),
        ("GET", "/v1/logs?agent_id=agent_001", None),
        ("GET", "/v1/logs/eval_001", None),
    ],
)
def test_tenant_product_api_requires_authentication(tmp_path, method: str, path: str, payload: dict | None) -> None:
    client = _raw_client(tmp_path, raise_server_exceptions=False)

    response = client.request(method, path, json=payload)

    _assert_structured_error(response, 401, "auth_required")
    assert response.json()["detail"]["schema_version"] == "auth-error-response-v0.1"


def test_public_product_api_routes_remain_accessible_without_auth(tmp_path) -> None:
    client = _raw_client(tmp_path, raise_server_exceptions=False)

    assert client.get("/").status_code == 200
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/v1/health").json() == {"status": "ok"}
    assert client.get("/v1/benchmarks").status_code == 200
    assert client.get("/v1/benchmarks/ecommerce-security-v0.1/versions").status_code == 200
    assert client.get("/v1/benchmarks/ecommerce-security-v0.1/versions/v0.1").status_code == 200
    assert client.get("/assets/missing.js").status_code != 401


def test_audit_preflight_skips_unused_runtime_checks_for_demo_agent(
    tmp_path,
) -> None:
    client = _client(tmp_path)
    registered = client.post(
        "/v1/agents",
        json={"agent_id": "preflight-agent", "name": "Preflight Agent"},
    )
    assert registered.status_code == 200

    response = client.get(
        "/v1/runtime/audit-preflight/preflight-agent"
    )

    assert response.status_code == 200
    assert response.json()["ready"] is True
    checks = {
        item["check_id"]: item["status"]
        for item in response.json()["checks"]
    }
    assert checks["agent_registration"] == "ready"
    assert checks["docker_daemon"] == "not_required"
    assert checks["model_attack"] == "not_required"


def test_onboard_source_agent_records_material_profile_and_stage_results(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)
    source_path, build_manifest_path = _source_material(
        tmp_path,
        "source-agent-no-adapter",
    )
    source_path, build_manifest_path = _source_material(
        tmp_path,
        "source-agent-no-adapter",
    )
    source_path, build_manifest_path = _source_material(
        tmp_path,
        "source-agent-no-adapter",
    )
    source_path, build_manifest_path = _source_material(
        tmp_path,
        "source-agent-no-adapter",
    )
    source_path, build_manifest_path = _source_material(tmp_path)

    response = client.post(
        "/v1/agents/onboard",
        json={
            "agent_id": "source_agent",
            "name": "Source Agent",
            "integration_type": "source",
            "source_path": source_path,
            "build_manifest_path": build_manifest_path,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == "private_tenant"
    assert body["ready"] is True
    assert body["status"] == "ready"
    assert body["agent"]["status"] == "ready"
    assert body["agent"]["integration_type"] == "source"
    assert body["material"]["source_path"] == source_path
    assert body["material"]["build_manifest_path"] == build_manifest_path
    assert body["material"]["source_snapshot_verified"] is True
    assert body["material"]["source_snapshot_sha256"]
    assert body["profile"]["profile_id"] == "profile-source_agent"
    assert body["profile"]["nodes"]
    assert {stage["name"]: stage["status"] for stage in body["stages"]} == {
        "agent_record": "completed",
        "source_snapshot": "completed",
        "profile_analysis": "completed",
        "sandbox_build_plan": "completed",
    }

    agent_response = client.get("/v1/agents/source_agent")
    profile_response = client.get("/v1/agents/source_agent/profile")

    assert agent_response.status_code == 200
    assert agent_response.json()["tenant_id"] == "private_tenant"
    assert profile_response.status_code == 200
    assert profile_response.json()["agent_id"] == "source_agent"

def test_ecommerce_demo_uses_packaged_source_when_available(
    tmp_path: Path,
    monkeypatch,
) -> None:
    resource_root = tmp_path / "resources"
    bundled_source = resource_root / "builtin-agents" / "ecommerce"
    shutil.copytree(ECOMMERCE_DEMO_SOURCE_PATH, bundled_source)
    client = _client(tmp_path / "storage", username="packaged_demo_owner")
    monkeypatch.setenv("RED_SENTINEL_RESOURCE_ROOT", str(resource_root))

    assert _ecommerce_demo_source_path() == bundled_source
    response = client.post("/v1/demo/agents/ecommerce")

    assert response.status_code == 200
    assert response.json()["agent_id"] == "ecommerce_customer_guide"
    assert [
        agent["agent_id"] for agent in client.get("/v1/agents").json()
    ] == ["ecommerce_customer_guide"]


def test_authenticated_tenant_requests_are_bound_to_jwt_user(tmp_path) -> None:
    owner = _client(tmp_path, username="tenant_owner")
    source_path, build_manifest_path = _source_material(tmp_path, "bound-agent")

    response = owner.post(
        "/v1/agents/onboard",
        json={
            "tenant_id": "other_tenant",
            "agent_id": "bound_agent",
            "name": "Bound Agent",
            "integration_type": "source",
            "source_path": source_path,
            "build_manifest_path": build_manifest_path,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == "tenant_owner"
    assert body["agent"]["tenant_id"] == "tenant_owner"
    assert body["agent"]["username"] == "tenant_owner"
    assert (tmp_path / "tenant_owner" / "agents" / "bound_agent.json").exists()
    assert not (tmp_path / "other_tenant").exists()

    other = _client(tmp_path, username="other_tenant", raise_server_exceptions=False)
    denied = other.get("/v1/agents/bound_agent?tenant_id=tenant_owner")
    _assert_structured_error(denied, 404, "agent_not_found")


def test_onboard_rejects_docker_agent_material(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path, username="tenant_demo")

    response = client.post(
        "/v1/agents/onboard",
        json={
            "tenant_id": "tenant_demo",
            "agent_id": "docker_agent",
            "name": "Docker Agent",
            "integration_type": "docker",
            "docker_image": "registry.example.test/agent:latest",
        },
    )

    assert response.status_code == 422
    assert "source" in response.text


def test_onboard_rejects_api_endpoint_and_credentials(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path, username="tenant_api")

    response = client.post(
        "/v1/agents/onboard",
        json={
            "tenant_id": "tenant_api",
            "agent_id": "api_agent",
            "name": "API Agent",
            "integration_type": "api",
            "endpoint_url": "https://example.test/v1/chat",
            "api_key": "sk-test-raw-secret",
        },
    )

    assert response.status_code == 422
    response_text = response.text
    persisted_text = "\n".join(path.read_text(encoding="utf-8") for path in tmp_path.rglob("*.json"))

    assert "source" in response_text
    assert "sk-test-raw-secret" not in response_text
    assert "sk-test-raw-secret" not in persisted_text


def test_e2e_source_onboarding_to_report_next_round_and_logs(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path, username="demo_tenant")
    source_path, build_manifest_path = _source_material(tmp_path, "e2e-agent")

    onboarding = client.post(
        "/v1/agents/onboard",
        json={
            "tenant_id": "demo_tenant",
            "username": "demo_tenant",
            "agent_id": "source_demo_agent",
            "name": "Source Demo Agent",
            "domain": "ecommerce",
            "integration_type": "source",
            "framework": "sdk",
            "source_path": source_path,
            "build_manifest_path": build_manifest_path,
            "remarks": "Source-only sandbox audit demo.",
        },
    )
    assert onboarding.status_code == 200
    onboard_body = onboarding.json()
    assert onboard_body["ready"] is True
    assert onboard_body["material"]["source_snapshot_verified"] is True
    assert onboard_body["agent"]["data_boundary"]["customer_runtime_access"] is False

    benchmarks = client.get("/v1/benchmarks")
    assert benchmarks.status_code == 200
    benchmark = next(item for item in benchmarks.json() if item["benchmark_id"] == "ecommerce-security-v0.1")
    versions = client.get(f"/v1/benchmarks/{benchmark['benchmark_id']}/versions")
    assert versions.status_code == 200
    selected_version = versions.json()[0]["version"]
    detail = client.get(f"/v1/benchmarks/{benchmark['benchmark_id']}/versions/{selected_version}")
    assert detail.status_code == 200
    assert {case["case_type"] for case in detail.json()["cases"]} == {"attack", "clean"}

    evaluation = client.post(
        "/v1/evaluations",
        json={
            "tenant_id": "demo_tenant",
            "agent_id": "source_demo_agent",
            "benchmark_id": benchmark["benchmark_id"],
            "benchmark_version": selected_version,
            "mode": "offline_trace",
            "scenarios": [
                "direct-injection-system-prompt",
                "support-pii-masking",
                "buyer-merchant-tool-abuse",
            ],
        },
    )
    assert evaluation.status_code == 200
    evaluation_body = evaluation.json()
    assert evaluation_body["status"] == "completed"
    assert evaluation_body["progress"]["total_cases"] == 6
    assert evaluation_body["progress"]["completed_cases"] == 6
    assert evaluation_body["report_id"] == evaluation_body["evaluation_id"]

    report = client.get(f"/v1/reports/{evaluation_body['report_id']}?tenant_id=demo_tenant")
    assert report.status_code == 200
    report_body = report.json()
    assert report_body["status"] == "complete"
    assert report_body["evaluation_id"] == evaluation_body["evaluation_id"]
    assert Path(report_body["artifacts"]["report_path"]).exists()
    assert report_body["deterministic_metrics"]["attack_case_count"] == 3
    assert "api_key" not in report.text

    dashboard = client.get("/v1/dashboard/summary?agent_id=source_demo_agent&tenant_id=demo_tenant")
    assert dashboard.status_code == 200
    dashboard_body = dashboard.json()
    assert dashboard_body["has_data"] is True
    assert dashboard_body["latest_evaluation_id"] == evaluation_body["evaluation_id"]
    assert dashboard_body["current_security_score"] == report_body["overall_score"]
    assert dashboard_body["trend"][0]["source"] == "report"

    next_round = client.post(f"/v1/evaluations/{evaluation_body['evaluation_id']}/next-round")
    assert next_round.status_code == 200
    next_round_body = next_round.json()
    assert next_round_body["source_report_id"] == evaluation_body["report_id"]
    assert next_round_body["version"]["source_report_id"] == evaluation_body["report_id"]
    assert any(
        evaluation_body["report_id"] in case["prompt"]
        for case in next_round_body["version"]["cases"]
        if case["case_type"] == "attack"
    )

    logs = client.get("/v1/logs?agent_id=source_demo_agent&tenant_id=demo_tenant")
    assert logs.status_code == 200
    assert logs.json()[0]["evaluation_id"] == evaluation_body["evaluation_id"]
    log_detail = client.get(f"/v1/logs/{evaluation_body['evaluation_id']}?tenant_id=demo_tenant")
    assert log_detail.status_code == 200
    detail_body = log_detail.json()
    assert detail_body["summary"]["evaluation_id"] == evaluation_body["evaluation_id"]
    assert detail_body["total_case_count"] == 6
    assert detail_body["prompts"]
    assert detail_body["rag_documents"]
    assert detail_body["target_nodes"]
    assert detail_body["trajectory_refs"]
    assert all(Path(ref).exists() for ref in detail_body["trajectory_refs"])


def test_onboard_requires_source_and_build_manifest_and_rejects_other_types(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)

    missing_source = client.post(
        "/v1/agents/onboard",
        json={"agent_id": "source_agent", "name": "Source Agent", "integration_type": "source"},
    )
    missing_docker = client.post(
        "/v1/agents/onboard",
        json={"agent_id": "docker_agent", "name": "Docker Agent", "integration_type": "docker"},
    )
    missing_api = client.post(
        "/v1/agents/onboard",
        json={"agent_id": "api_agent", "name": "API Agent", "integration_type": "api"},
    )

    assert missing_source.status_code == 422
    assert "source_path" in missing_source.text
    assert "build_manifest_path" in missing_source.text
    assert missing_docker.status_code == 422
    assert "source" in missing_docker.text
    assert missing_api.status_code == 422
    assert "source" in missing_api.text


def test_legacy_agent_registration_remains_compatible(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)

    response = client.post("/v1/agents", json={"agent_id": "legacy_agent", "name": "Legacy Agent"})
    lookup = client.get("/v1/agents/legacy_agent")

    assert response.status_code == 200
    assert response.json()["agent_id"] == "legacy_agent"
    assert lookup.status_code == 200
    assert lookup.json()["integration_type"] == "source"


def test_evaluation_api_accepts_benchmark_version_and_returns_progress(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)
    client.post("/v1/agents", json={"agent_id": "progress_agent", "name": "Progress Agent"})

    response = client.post(
        "/v1/evaluations",
        json={
            "agent_id": "progress_agent",
            "benchmark_id": "ecommerce-security-v0.1",
            "benchmark_version": "v0.1",
            "scenarios": ["support-pii-masking"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["benchmark_id"] == "ecommerce-security-v0.1"
    assert body["benchmark_version"] == "v0.1"
    assert body["progress"]["total_cases"] == 2
    assert body["progress"]["completed_cases"] == 2
    assert body["progress"]["percent"] == 100.0
    assert body["current_case"] == "support-pii-masking"
    assert body["current_node"]

    report = client.get(f"/v1/reports/{body['report_id']}")
    snapshot_path = tmp_path / "private_tenant" / "metric_snapshots" / f"snapshot-{body['evaluation_id']}.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

    assert report.status_code == 200
    assert report.json()["evaluation_id"] == body["evaluation_id"]
    assert Path(report.json()["artifacts"]["report_path"]).exists()
    assert snapshot["evaluation_id"] == body["evaluation_id"]
    assert snapshot["latest_report_id"] == body["report_id"]

    lookup = client.get(f"/v1/evaluations/{body['evaluation_id']}")

    assert lookup.status_code == 200
    assert lookup.json()["progress"] == body["progress"]
    assert lookup.json()["current_case"] == body["current_case"]
    assert lookup.json()["current_node"] == body["current_node"]


def test_evaluation_api_distinguishes_guarded_and_no_defense_modes(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)
    client.post("/v1/agents", json={"agent_id": "defense_mode_agent", "name": "Defense Mode Agent"})

    guarded = client.post(
        "/v1/evaluations",
        json={
            "agent_id": "defense_mode_agent",
            "scenarios": ["direct-injection-system-prompt"],
        },
    )
    baseline = client.post(
        "/v1/evaluations",
        json={
            "agent_id": "defense_mode_agent",
            "scenarios": ["direct-injection-system-prompt"],
            "defense_enabled": False,
        },
    )

    assert guarded.status_code == 200
    assert baseline.status_code == 200
    guarded_report = client.get(f"/v1/reports/{guarded.json()['report_id']}").json()
    baseline_report = client.get(f"/v1/reports/{baseline.json()['report_id']}").json()

    assert guarded_report["summary"]["defense_enabled"] is True
    assert guarded_report["summary"]["evaluation_mode"] == "guarded"
    assert guarded_report["scenario_results"][0]["actual_decision"] == "block"
    assert baseline_report["summary"]["defense_enabled"] is False
    assert baseline_report["summary"]["evaluation_mode"] == "baseline_no_defense"
    assert baseline_report["scenario_results"][0]["actual_decision"] == "allow"
    assert baseline_report["attack_success_rate"] >= guarded_report["attack_success_rate"]


def test_evaluation_api_rejects_missing_adapter_before_acceptance(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)
    source_path, build_manifest_path = _source_material(
        tmp_path,
        "source-agent-no-adapter",
    )
    client.post(
        "/v1/agents/onboard",
        json={
            "agent_id": "source_agent_no_adapter",
            "name": "Source Agent",
            "integration_type": "source",
            "source_path": source_path,
            "build_manifest_path": build_manifest_path,
        },
    )
    evaluation_root = tmp_path / "private_tenant" / "evaluations"
    existing_evaluations = set(evaluation_root.glob("*"))

    response = client.post(
        "/v1/evaluations",
        json={"agent_id": "source_agent_no_adapter", "scenarios": ["support-pii-masking"]},
    )

    assert 400 <= response.status_code < 500
    assert response.json()["detail"]["error_code"] == "missing_adapter"
    assert "offline_trace" in response.json()["detail"]["message"]
    assert set(evaluation_root.glob("*")) == existing_evaluations


def test_evaluation_api_rejects_unknown_scenario_before_acceptance(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)
    client.post("/v1/agents", json={"agent_id": "scenario_agent", "name": "Scenario Agent"})

    response = client.post(
        "/v1/evaluations",
        json={"agent_id": "scenario_agent", "scenarios": ["missing-scenario"]},
    )

    assert 400 <= response.status_code < 500
    assert response.json()["detail"] == {
        "error_code": "unknown_scenario",
        "message": "Unknown scenario ids: missing-scenario",
    }
    assert not (tmp_path / "private_tenant" / "evaluations").exists()


@pytest.mark.parametrize(
    ("payload", "error_code"),
    [
        ({"benchmark_id": "unknown-benchmark"}, "unknown_benchmark"),
        (
            {"benchmark_id": "ecommerce-security-v0.1", "benchmark_version": "v9.9"},
            "unknown_benchmark_version",
        ),
    ],
)
def test_evaluation_api_rejects_unknown_benchmark_before_acceptance(
    tmp_path,
    payload: dict[str, str],
    error_code: str,
) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)
    client.post("/v1/agents", json={"agent_id": "benchmark_agent", "name": "Benchmark Agent"})

    response = client.post(
        "/v1/evaluations",
        json={
            "agent_id": "benchmark_agent",
            "scenarios": ["support-pii-masking"],
            **payload,
        },
    )

    assert 400 <= response.status_code < 500
    assert response.json()["detail"]["error_code"] == error_code
    assert response.json()["detail"]["message"]
    assert not (tmp_path / "private_tenant" / "evaluations").exists()


def test_dashboard_summary_returns_empty_state_without_fake_metrics(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)
    client.post("/v1/agents", json={"agent_id": "empty_dashboard_agent", "name": "Empty Dashboard Agent"})

    response = client.get("/v1/dashboard/summary?agent_id=empty_dashboard_agent")

    assert response.status_code == 200
    body = response.json()
    assert body["has_data"] is False
    assert body["empty_reason"] == "no_completed_evaluation_metrics"
    assert body["current_security_score"] is None
    assert body["current_risk_level"] is None
    assert body["recent_asr"] is None
    assert body["recent_fpr"] is None
    assert body["trend"] == []


def test_dashboard_summary_uses_completed_report_metrics_and_trend(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)
    client.post("/v1/agents", json={"agent_id": "dashboard_agent", "name": "Dashboard Agent"})

    first = client.post(
        "/v1/evaluations",
        json={"agent_id": "dashboard_agent", "scenarios": ["support-pii-masking"]},
    )
    second = client.post(
        "/v1/evaluations",
        json={"agent_id": "dashboard_agent", "scenarios": ["direct-injection-system-prompt"]},
    )
    assert first.status_code == 200
    assert second.status_code == 200
    latest_report_id = second.json()["report_id"]
    report = client.get(f"/v1/reports/{latest_report_id}").json()
    snapshot_path = tmp_path / "private_tenant" / "metric_snapshots" / f"snapshot-{latest_report_id}.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

    response = client.get("/v1/dashboard/summary?agent_id=dashboard_agent")

    assert response.status_code == 200
    body = response.json()
    assert report["status"] == "complete"
    assert snapshot["latest_report_id"] == latest_report_id
    assert snapshot["benchmark_id"] == report["benchmark_id"]
    assert snapshot["benchmark_version"] == report["benchmark_version"]
    assert body["has_data"] is True
    assert body["latest_source"] == "report"
    assert body["latest_report_id"] == latest_report_id
    assert body["current_security_score"] == report["overall_score"]
    assert body["current_risk_level"] == report["risk_level"]
    assert body["recent_asr"] == report["attack_success_rate"]
    assert body["recent_fpr"] == report["false_positive_rate"]
    assert [point["label"] for point in body["trend"]] == ["Round 1", "Round 2"]
    assert {point["source"] for point in body["trend"]} == {"report"}


def test_benchmark_api_returns_preset_versions_and_case_details(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _raw_client(tmp_path)

    benchmarks = client.get("/v1/benchmarks")
    assert benchmarks.status_code == 200
    benchmark = next(item for item in benchmarks.json() if item["benchmark_id"] == "ecommerce-security-v0.1")
    assert benchmark["active_version"] == "v0.1"
    assert benchmark["case_count"] >= 32
    assert benchmark["attack_case_count"] == benchmark["clean_case_count"]

    versions = client.get("/v1/benchmarks/ecommerce-security-v0.1/versions")
    assert versions.status_code == 200
    assert versions.json()[0]["version"] == "v0.1"

    detail = client.get("/v1/benchmarks/ecommerce-security-v0.1/versions/v0.1")
    assert detail.status_code == 200
    body = detail.json()
    assert body["case_count"] == benchmark["case_count"]
    assert body["attack_case_count"] == benchmark["attack_case_count"]
    assert body["clean_case_count"] == benchmark["clean_case_count"]
    assert body["node_coverage"]
    case_types = {case["case_type"] for case in body["cases"]}
    assert case_types == {"attack", "clean"}
    first_case = body["cases"][0]
    assert first_case["prompt"]
    assert first_case["rag_document_summary"]
    assert first_case["target_node"]


def test_benchmark_api_returns_structured_errors_for_unknown_resources(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _raw_client(tmp_path, raise_server_exceptions=False)

    _assert_structured_error(client.get("/v1/benchmarks/unknown-benchmark/versions"), 404, "benchmark_not_found")
    _assert_structured_error(
        client.get("/v1/benchmarks/ecommerce-security-v0.1/versions/v9.9"),
        404,
        "benchmark_version_not_found",
    )


def test_next_round_api_generates_traceable_version_prompt_and_defense_suggestions(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)
    client.post("/v1/agents", json={"agent_id": "next_round_agent", "name": "Next Round Agent"})
    source_detail = client.get("/v1/benchmarks/ecommerce-security-v0.1/versions/v0.1").json()
    source_prompts = {case["case_id"]: case["prompt"] for case in source_detail["cases"]}

    evaluation = client.post(
        "/v1/evaluations",
        json={
            "agent_id": "next_round_agent",
            "benchmark_id": "ecommerce-security-v0.1",
            "benchmark_version": "v0.1",
            "scenarios": ["support-pii-masking"],
        },
    )
    evaluation_body = evaluation.json()

    response = client.post(f"/v1/evaluations/{evaluation_body['evaluation_id']}/next-round")

    assert response.status_code == 200
    body = response.json()
    assert body["source_evaluation_id"] == evaluation_body["evaluation_id"]
    assert body["source_report_id"] == evaluation_body["report_id"]
    assert body["benchmark_id"] == "ecommerce-security-v0.1"
    assert body["benchmark_version"] == "v0.2"
    assert body["version"]["source_report_id"] == evaluation_body["report_id"]
    assert body["version"]["generation_record"]["source_evaluation_id"] == evaluation_body["evaluation_id"]
    assert body["defense_suggestions"]
    generated_scenarios = body["version"]["generation_record"]["scenario_payloads"]
    assert generated_scenarios
    assert any(
        evaluation_body["report_id"] in step["message"]
        for scenario in generated_scenarios
        for step in scenario["controlled_steps"]
    )

    attack_cases = [case for case in body["version"]["cases"] if case["case_type"] == "attack"]
    assert any(
        evaluation_body["report_id"] in case["prompt"] and case["prompt"] != source_prompts[case["case_id"]]
        for case in attack_cases
    )

    detail = client.get("/v1/benchmarks/ecommerce-security-v0.1/versions/v0.2")
    assert detail.status_code == 200
    assert detail.json()["source_report_id"] == evaluation_body["report_id"]

    suggestion_path = (
        tmp_path / "private_tenant" / "evaluations" / evaluation_body["evaluation_id"] / "defense-suggestions.json"
    )
    suggestion_record = json.loads(suggestion_path.read_text(encoding="utf-8"))
    assert suggestion_record["source_report_id"] == evaluation_body["report_id"]
    assert suggestion_record["defense_suggestions"] == body["defense_suggestions"]

    missing = client.post("/v1/evaluations/missing_eval/next-round")
    assert missing.status_code == 404
    assert missing.json()["detail"]["error_code"] == "next_round_failed"


def test_next_round_api_rejects_evaluation_without_report(tmp_path) -> None:
    pytest.importorskip("fastapi")

    evaluation_path = tmp_path / "private_tenant" / "evaluations" / "eval_no_report" / "evaluation.json"
    evaluation_path.parent.mkdir(parents=True)
    evaluation_path.write_text(
        json.dumps(
            {
                "evaluation_id": "eval_no_report",
                "tenant_id": "private_tenant",
                "agent_id": "agent_no_report",
                "benchmark_id": "ecommerce-security-v0.1",
                "benchmark_version": "v0.1",
                "status": "failed",
            }
        ),
        encoding="utf-8",
    )
    client = _client(tmp_path, raise_server_exceptions=False)

    response = client.post("/v1/evaluations/eval_no_report/next-round")

    _assert_structured_error(response, 422, "next_round_failed")
    assert "no report" in response.json()["detail"]["message"]


def test_logs_api_returns_sorted_summaries_and_complete_detail(tmp_path) -> None:
    pytest.importorskip("fastapi")

    client = _client(tmp_path)
    client.post("/v1/agents", json={"agent_id": "log_agent", "name": "Log Agent"})

    first = client.post(
        "/v1/evaluations",
        json={"agent_id": "log_agent", "scenarios": ["support-pii-masking"]},
    )
    second = client.post(
        "/v1/evaluations",
        json={"agent_id": "log_agent", "scenarios": ["buyer-merchant-tool-abuse"]},
    )
    assert first.status_code == 200
    assert second.status_code == 200
    first_body = first.json()
    second_body = second.json()

    response = client.get("/v1/logs?agent_id=log_agent&tenant_id=private_tenant")

    assert response.status_code == 200
    summaries = response.json()
    assert [item["evaluation_id"] for item in summaries] == [
        second_body["evaluation_id"],
        first_body["evaluation_id"],
    ]
    latest = summaries[0]
    assert latest["score"] is not None
    assert latest["asr"] is not None
    assert latest["fpr"] is not None
    assert "weakest_link" in latest
    assert latest["benchmark_version"] == "v0.1"
    assert latest["evaluated_at"]
    assert latest["status"] == "completed"

    detail_response = client.get(f"/v1/logs/{second_body['evaluation_id']}")

    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["summary"]["evaluation_id"] == second_body["evaluation_id"]
    assert {"asr", "dsr", "fpr"} <= set(detail["metrics"])
    assert detail["total_case_count"] == 2
    assert any("商家改价" in prompt for prompt in detail["prompts"])
    assert detail["rag_documents"]
    assert detail["target_nodes"] == ["privilege_escalation"]
    assert "privilege_escalation" in detail["critical_node_blocked"]
    assert detail["trajectory_refs"]
    assert all(Path(ref).exists() for ref in detail["trajectory_refs"])


def test_log_and_report_api_preserve_tenant_scope_errors(tmp_path) -> None:
    pytest.importorskip("fastapi")

    _write_minimal_evaluation(tmp_path, tenant_id="tenant_a", evaluation_id="eval_shared", agent_id="agent")
    _write_minimal_evaluation(tmp_path, tenant_id="tenant_b", evaluation_id="eval_shared", agent_id="agent")
    _write_minimal_report(tmp_path, tenant_id="tenant_a", report_id="eval_shared", agent_id="agent")
    _write_minimal_report(tmp_path, tenant_id="tenant_b", report_id="eval_shared", agent_id="agent")
    client = _client(tmp_path, username="tenant_a", raise_server_exceptions=False)

    log_detail = client.get("/v1/logs/eval_shared?tenant_id=tenant_b")
    report = client.get("/v1/reports/eval_shared?tenant_id=tenant_b")

    assert log_detail.status_code == 200
    assert log_detail.json()["summary"]["tenant_id"] == "tenant_a"
    assert report.status_code == 200
    assert report.json()["tenant_id"] == "tenant_a"

    missing_tenant = _client(tmp_path, username="tenant_missing", raise_server_exceptions=False)
    _assert_structured_error(missing_tenant.get("/v1/logs/eval_shared"), 404, "log_lookup_failed")
    _assert_structured_error(missing_tenant.get("/v1/reports/eval_shared"), 404, "report_not_found")


def test_comparison_api_returns_structured_error_for_cross_tenant_reports(tmp_path) -> None:
    pytest.importorskip("fastapi")

    _write_minimal_report(tmp_path, tenant_id="tenant_a", report_id="eval_before", agent_id="agent")
    _write_minimal_report(tmp_path, tenant_id="tenant_b", report_id="eval_after", agent_id="agent")
    client = _client(tmp_path, username="tenant_a", raise_server_exceptions=False)

    response = client.post(
        "/v1/comparisons",
        json={"before_report_id": "eval_before", "after_report_id": "eval_after"},
    )

    _assert_structured_error(response, 404, "comparison_failed")
    assert "tenant_a/eval_after" in response.json()["detail"]["message"]


def _write_minimal_evaluation(tmp_path: Path, *, tenant_id: str, evaluation_id: str, agent_id: str) -> None:
    path = tmp_path / tenant_id / "evaluations" / evaluation_id / "evaluation.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "evaluation_id": evaluation_id,
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "benchmark_id": "ecommerce-security-v0.1",
                "benchmark_version": "v0.1",
                "status": "completed",
            }
        ),
        encoding="utf-8",
    )


def _write_minimal_report(tmp_path: Path, *, tenant_id: str, report_id: str, agent_id: str) -> None:
    report_path = tmp_path / tenant_id / "evaluations" / report_id / "agent-security-report-v0.1.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "schema_version": "agent-security-report-v0.1",
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "benchmark": "ecommerce-security-v0.1",
                "benchmark_id": "ecommerce-security-v0.1",
                "benchmark_version": "v0.1",
                "evaluation_id": report_id,
                "overall_score": 100,
                "risk_level": "low",
                "artifacts": {"report_path": str(report_path)},
            }
        ),
        encoding="utf-8",
    )
