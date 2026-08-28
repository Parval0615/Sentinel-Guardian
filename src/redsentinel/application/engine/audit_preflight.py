from __future__ import annotations

import os
import subprocess
from collections.abc import Callable

from redsentinel.application.audit_contracts import (
    AuditPreflightCheck,
    AuditPreflightStatus,
)
from redsentinel.application.contracts import utc_now_iso
from redsentinel.application.engine.image_profile_workflow import (
    ImageProfileWorkflowError,
)
from redsentinel.application.engine.model_runtime import ModelRuntimeRegistry
from redsentinel.core.docker_runtime import resolve_docker_binary


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


class AuditPreflightService:
    def __init__(
        self,
        product_service,
        model_runtime: ModelRuntimeRegistry,
        *,
        command_runner: CommandRunner = subprocess.run,
    ) -> None:
        self._product_service = product_service
        self._model_runtime = model_runtime
        self._command_runner = command_runner

    def check(self, *, tenant_id: str, agent_id: str) -> AuditPreflightStatus:
        agent = self._product_service.get_agent(
            agent_id=agent_id,
            tenant_id=tenant_id,
        )
        checks = [
            AuditPreflightCheck(
                check_id="agent_registration",
                status="ready",
                message="Agent registration is available.",
                detail=agent.name,
            )
        ]
        if agent.adapter_type != "openmanus":
            checks.extend(
                [
                    _not_required("static_profile", "Docker image profile is not required."),
                    _not_required("docker_daemon", "Docker runtime is not required."),
                    _not_required("openmanus_image", "OpenManus image is not required."),
                    _not_required("model_target", "Target model is not required."),
                    _not_required("model_attack", "Attack model is not required."),
                    _not_required("model_defense", "Defense model is not required."),
                ]
            )
            return _status(agent_id, agent.adapter_type, checks)

        checks.append(self._profile_check(tenant_id, agent_id))
        checks.extend(self._docker_checks())
        checks.extend(self._model_checks(tenant_id))
        return _status(agent_id, agent.adapter_type, checks)

    def _profile_check(
        self,
        tenant_id: str,
        agent_id: str,
    ) -> AuditPreflightCheck:
        try:
            profile = self._product_service.image_profiles.get_latest_profile(
                tenant_id=tenant_id,
                agent_id=agent_id,
            )
        except ImageProfileWorkflowError as exc:
            return AuditPreflightCheck(
                check_id="static_profile",
                status="blocked",
                message="Published static profile is required.",
                detail=exc.message,
            )
        return AuditPreflightCheck(
            check_id="static_profile",
            status="ready",
            message="Published static profile is available.",
            detail=profile.profile_id,
        )

    def _docker_checks(self) -> list[AuditPreflightCheck]:
        docker_binary = resolve_docker_binary()
        image = os.environ.get(
            "RED_SENTINEL_OPENMANUS_IMAGE",
            "redsentinel/openmanus-real:local",
        ).strip()
        daemon = self._run(
            [docker_binary, "version", "--format", "{{.Server.Version}}"],
            timeout=5,
        )
        if daemon is None or daemon.returncode != 0:
            detail = _command_detail(daemon) if daemon is not None else docker_binary
            return [
                AuditPreflightCheck(
                    check_id="docker_daemon",
                    status="blocked",
                    message="Docker daemon is unavailable.",
                    detail=detail,
                ),
                AuditPreflightCheck(
                    check_id="openmanus_image",
                    status="blocked",
                    message="OpenManus image cannot be inspected.",
                    detail=image or "Image name is empty.",
                ),
            ]

        daemon_check = AuditPreflightCheck(
            check_id="docker_daemon",
            status="ready",
            message="Docker daemon is available.",
            detail=(daemon.stdout or "").strip() or docker_binary,
        )
        if not image:
            return [
                daemon_check,
                AuditPreflightCheck(
                    check_id="openmanus_image",
                    status="blocked",
                    message="OpenManus image is not configured.",
                ),
            ]
        inspected = self._run(
            [docker_binary, "image", "inspect", image, "--format", "{{.Id}}"],
            timeout=10,
        )
        image_ready = inspected is not None and inspected.returncode == 0
        return [
            daemon_check,
            AuditPreflightCheck(
                check_id="openmanus_image",
                status="ready" if image_ready else "blocked",
                message=(
                    "OpenManus runtime image is available."
                    if image_ready
                    else "OpenManus runtime image is unavailable."
                ),
                detail=(
                    (inspected.stdout or "").strip()
                    if image_ready and inspected is not None
                    else _command_detail(inspected) if inspected is not None else image
                ),
            ),
        ]

    def _model_checks(self, tenant_id: str) -> list[AuditPreflightCheck]:
        checks = []
        for status in self._model_runtime.statuses(tenant_id):
            checks.append(
                AuditPreflightCheck(
                    check_id=f"model_{status.role}",
                    status="ready" if status.tested else "blocked",
                    message=(
                        f"{status.role} model passed connection testing."
                        if status.tested
                        else f"{status.role} model must pass connection testing."
                    ),
                    detail=status.model or status.error,
                )
            )
        return checks

    def _run(
        self,
        command: list[str],
        *,
        timeout: int,
    ) -> subprocess.CompletedProcess[str] | None:
        try:
            return self._command_runner(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None


def _not_required(check_id: str, message: str) -> AuditPreflightCheck:
    return AuditPreflightCheck(
        check_id=check_id,
        status="not_required",
        message=message,
    )


def _status(
    agent_id: str,
    adapter_type: str,
    checks: list[AuditPreflightCheck],
) -> AuditPreflightStatus:
    return AuditPreflightStatus(
        agent_id=agent_id,
        adapter_type=adapter_type,
        ready=all(check.status != "blocked" for check in checks),
        checked_at=utc_now_iso(),
        checks=checks,
    )


def _command_detail(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stderr or result.stdout or "").strip()[:500] or (
        f"Command exited with code {result.returncode}."
    )


__all__ = ["AuditPreflightService"]
