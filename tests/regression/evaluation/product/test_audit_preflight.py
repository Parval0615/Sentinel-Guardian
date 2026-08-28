from __future__ import annotations

import subprocess
from types import SimpleNamespace

from redsentinel.application.audit_contracts import ModelRuntimeStatus
from redsentinel.application.engine.audit_preflight import AuditPreflightService
from redsentinel.application.engine.image_profile_workflow import (
    ImageProfileWorkflowError,
)


class _Models:
    def __init__(self, *, tested: bool) -> None:
        self.tested = tested

    def statuses(self, _tenant_id: str) -> list[ModelRuntimeStatus]:
        return [
            ModelRuntimeStatus(
                role=role,
                configured=self.tested,
                tested=self.tested,
                model="competition-model" if self.tested else None,
            )
            for role in ("target", "attack", "defense")
        ]


class _Profiles:
    def __init__(self, *, available: bool) -> None:
        self.available = available

    def get_latest_profile(self, **_kwargs):
        if not self.available:
            raise ImageProfileWorkflowError(
                "image_profile_not_found",
                "Published image profile not found.",
                status_code=404,
            )
        return SimpleNamespace(profile_id="profile-openmanus")


class _Product:
    def __init__(self, *, profile_available: bool = True) -> None:
        self.image_profiles = _Profiles(available=profile_available)

    def get_agent(self, **_kwargs):
        return SimpleNamespace(
            name="OpenManus",
            adapter_type="openmanus",
        )


def test_openmanus_preflight_checks_docker_image_profile_and_models(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "RED_SENTINEL_DOCKER_BINARY",
        "/opt/docker/bin/docker",
    )
    commands: list[list[str]] = []

    def run(command, **_kwargs):
        commands.append(command)
        output = "29.6.1" if "version" in command else "sha256:image"
        return subprocess.CompletedProcess(command, 0, output, "")

    status = AuditPreflightService(
        _Product(),
        _Models(tested=True),
        command_runner=run,
    ).check(tenant_id="tenant-1", agent_id="openmanus")

    assert status.ready is True
    assert all(check.status == "ready" for check in status.checks)
    assert commands == [
        [
            "/opt/docker/bin/docker",
            "version",
            "--format",
            "{{.Server.Version}}",
        ],
        [
            "/opt/docker/bin/docker",
            "image",
            "inspect",
            "redsentinel/openmanus-real:local",
            "--format",
            "{{.Id}}",
        ],
    ]


def test_openmanus_preflight_reports_all_independent_blockers() -> None:
    def unavailable(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            "Cannot connect to Docker daemon",
        )

    status = AuditPreflightService(
        _Product(profile_available=False),
        _Models(tested=False),
        command_runner=unavailable,
    ).check(tenant_id="tenant-1", agent_id="openmanus")

    blockers = {
        check.check_id
        for check in status.checks
        if check.status == "blocked"
    }
    assert status.ready is False
    assert blockers == {
        "static_profile",
        "docker_daemon",
        "openmanus_image",
        "model_target",
        "model_attack",
        "model_defense",
    }
