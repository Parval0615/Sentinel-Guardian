from pathlib import Path

import pytest

import redsentinel.application.engine.application as application_module
from redsentinel.application.engine.application import ProductApplicationService
from redsentinel.application.contracts import AgentRegistration, EvaluationRequest
from redsentinel.application.engine.dynamic_profile_probe import DynamicProfileProbe
from redsentinel.application.engine.llm_gateway import OpenAIJsonGateway
from redsentinel.application.engine.local_image_ref import LocalDockerImageRefResolver


def test_product_application_facade_preserves_product_workflow(tmp_path: Path) -> None:
    application = ProductApplicationService(storage_root=tmp_path)
    agent = application.register_agent(
        AgentRegistration(agent_id="research_agent", name="Research Agent")
    )

    status = application.run_evaluation(
        EvaluationRequest(
            tenant_id=agent.tenant_id,
            agent_id=agent.agent_id,
            scenarios=["support-pii-masking"],
        )
    )
    report = application.get_report(status.report_id or status.evaluation_id)

    assert status.status == "completed"
    assert report.agent_id == agent.agent_id
    assert application.agents.get_agent(agent.agent_id) == agent
    assert application.evaluations.get_evaluation(status.evaluation_id) == status
    assert application.reporting.get_dashboard_summary(agent.agent_id).has_data is True


def test_product_application_exposes_single_supervision_store(tmp_path: Path) -> None:
    application = ProductApplicationService(storage_root=tmp_path)

    assert application.supervision.storage is application.storage


def test_product_application_builds_image_profile_workflow_once_with_configured_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker_binary = "/opt/docker/bin/docker"
    real_factory = application_module.ImageProfileWorkflowService
    factory_calls: list[dict[str, object]] = []

    def recording_factory(*args: object, **kwargs: object):
        factory_calls.append(kwargs)
        return real_factory(*args, **kwargs)

    monkeypatch.setenv("RED_SENTINEL_DOCKER_BINARY", docker_binary)
    monkeypatch.setattr(application_module, "ImageProfileWorkflowService", recording_factory)

    application = ProductApplicationService(storage_root=tmp_path)

    assert len(factory_calls) == 1
    resolver = factory_calls[0]["image_ref_resolver"]
    assert isinstance(resolver, LocalDockerImageRefResolver)
    assert resolver.docker_binary == docker_binary
    probe = application.image_profiles._dynamic_probe_factory(tmp_path / "probe")
    assert isinstance(probe, DynamicProfileProbe)
    assert probe.docker_binary == docker_binary














def test_product_application_configures_planner_gateway_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RED_SENTINEL_PLANNER_API_KEY", "planner-secret")
    monkeypatch.setenv("RED_SENTINEL_PLANNER_BASE_URL", "https://planner.example.test/v1")
    monkeypatch.setenv("RED_SENTINEL_PLANNER_MODEL", "planner-model")
    monkeypatch.setenv("RED_SENTINEL_PLANNER_TIMEOUT_SECONDS", "7.5")

    application = ProductApplicationService(storage_root=tmp_path)
    gateway = application.audits._workflow.planner.gateway

    assert isinstance(gateway, OpenAIJsonGateway)
    assert gateway.model == "planner-model"
    assert gateway.timeout_seconds == 7.5
    assert "planner-secret" not in repr(gateway)


def test_product_application_rejects_partial_planner_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RED_SENTINEL_PLANNER_API_KEY", raising=False)
    monkeypatch.delenv("RED_SENTINEL_PLANNER_BASE_URL", raising=False)
    monkeypatch.setenv("RED_SENTINEL_PLANNER_MODEL", "planner-model")

    with pytest.raises(ValueError, match="Incomplete LLM planner configuration"):
        ProductApplicationService(storage_root=tmp_path)
