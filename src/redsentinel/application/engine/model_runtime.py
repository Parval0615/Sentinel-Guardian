from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from redsentinel.application.audit_contracts import (
    ModelRuntimeConfiguration,
    ModelRuntimeRole,
    ModelRuntimeStatus,
)
from redsentinel.application.contracts import utc_now_iso
from redsentinel.application.engine.llm_gateway import (
    JsonLLMGateway,
    JsonLLMResult,
    OpenAIJsonGateway,
)


_ROLE_ENVIRONMENT = {
    "target": ("OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL"),
    "attack": (
        "RED_SENTINEL_PLANNER_API_KEY",
        "RED_SENTINEL_PLANNER_BASE_URL",
        "RED_SENTINEL_PLANNER_MODEL",
    ),
    "defense": (
        "RED_SENTINEL_DEFENSE_API_KEY",
        "RED_SENTINEL_DEFENSE_BASE_URL",
        "RED_SENTINEL_DEFENSE_MODEL",
    ),
}


@dataclass(frozen=True)
class _RuntimeEntry:
    configuration: ModelRuntimeConfiguration
    tested: bool = False
    tested_at: str | None = None
    error: str | None = None


class ModelRuntimeRegistry:
    """Keep model credentials in memory and expose only redacted status."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, ModelRuntimeRole], _RuntimeEntry] = {}
        self._lock = threading.Lock()
        self._execution_lock = threading.RLock()
        self._active_tenant: ContextVar[str | None] = ContextVar(
            "model_runtime_tenant",
            default=None,
        )

    def statuses(self, tenant_id: str) -> list[ModelRuntimeStatus]:
        return [
            self.status(tenant_id, role)
            for role in ("target", "attack", "defense")
        ]

    def status(
        self,
        tenant_id: str,
        role: ModelRuntimeRole,
    ) -> ModelRuntimeStatus:
        with self._lock:
            entry = self._entries.get((tenant_id, role))
        if entry is None:
            return ModelRuntimeStatus(role=role, configured=False, tested=False)
        return ModelRuntimeStatus(
            role=role,
            configured=True,
            tested=entry.tested,
            base_url=entry.configuration.base_url,
            model=entry.configuration.model,
            tested_at=entry.tested_at,
            error=entry.error,
        )

    def test_and_store(
        self,
        tenant_id: str,
        role: ModelRuntimeRole,
        configuration: ModelRuntimeConfiguration,
    ) -> ModelRuntimeStatus:
        with self._lock:
            self._entries[(tenant_id, role)] = _RuntimeEntry(
                configuration=configuration
            )

        secret = configuration.api_key.get_secret_value()
        try:
            result = self._gateway(configuration).complete_json(
                system_prompt=(
                    "You are a model connectivity probe. Return one JSON object only."
                ),
                user_prompt='Return exactly {"ok":true}.',
                max_tokens=32,
            )
            passed = bool(
                result.ok
                and result.payload
                and result.payload.get("ok") is True
            )
            error = (
                None
                if passed
                else result.error or "Model response did not confirm connectivity."
            )
        except Exception as exc:
            passed = False
            error = f"{type(exc).__name__}: {exc}"
        if error is not None:
            error = error.replace(secret, "[redacted]")[:500]
        tested_at = utc_now_iso()
        with self._lock:
            current = self._entries.get((tenant_id, role))
            if current is not None and current.configuration == configuration:
                self._entries[(tenant_id, role)] = _RuntimeEntry(
                    configuration=configuration,
                    tested=passed,
                    tested_at=tested_at,
                    error=error,
                )
        return self.status(tenant_id, role)

    def configure(
        self,
        tenant_id: str,
        role: ModelRuntimeRole,
        configuration: ModelRuntimeConfiguration,
    ) -> ModelRuntimeStatus:
        with self._lock:
            self._entries[(tenant_id, role)] = _RuntimeEntry(
                configuration=configuration
            )
        return self.status(tenant_id, role)

    def require_ready(
        self,
        tenant_id: str,
        roles: tuple[ModelRuntimeRole, ...],
    ) -> None:
        missing = [
            role for role in roles if not self.status(tenant_id, role).tested
        ]
        if missing:
            raise ValueError(
                "Model configuration must be tested before audit: "
                + ", ".join(missing)
            )

    def gateway(self, role: ModelRuntimeRole) -> JsonLLMGateway:
        return _RoleGateway(self, role)

    def configured_gateway(
        self,
        tenant_id: str,
        role: ModelRuntimeRole,
    ) -> OpenAIJsonGateway | None:
        with self._lock:
            entry = self._entries.get((tenant_id, role))
        if entry is None or not entry.tested:
            return None
        return self._gateway(entry.configuration)

    @contextmanager
    def tenant_context(self, tenant_id: str) -> Iterator[None]:
        with self._execution_lock:
            token = self._active_tenant.set(tenant_id)
            previous_environment = self._activate_environment(tenant_id)
            try:
                yield
            finally:
                self._restore_environment(previous_environment)
                self._active_tenant.reset(token)

    def active_tenant(self) -> str | None:
        return self._active_tenant.get()

    @staticmethod
    def _gateway(configuration: ModelRuntimeConfiguration) -> OpenAIJsonGateway:
        return OpenAIJsonGateway(
            api_key=configuration.api_key.get_secret_value(),
            base_url=configuration.base_url,
            model=configuration.model,
        )

    def _activate_environment(
        self,
        tenant_id: str,
    ) -> dict[str, str | None]:
        updates: dict[str, str] = {}
        with self._lock:
            entries = {
                role: self._entries.get((tenant_id, role))
                for role in ("target", "attack", "defense")
            }
        for role, entry in entries.items():
            if entry is None or not entry.tested:
                continue
            values = (
                entry.configuration.api_key.get_secret_value(),
                entry.configuration.base_url,
                entry.configuration.model,
            )
            updates.update(
                dict(zip(_ROLE_ENVIRONMENT[role], values, strict=True))
            )
        previous = {name: os.environ.get(name) for name in updates}
        os.environ.update(updates)
        return previous

    @staticmethod
    def _restore_environment(previous: dict[str, str | None]) -> None:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class _RoleGateway:
    def __init__(self, registry: ModelRuntimeRegistry, role: ModelRuntimeRole) -> None:
        self._registry = registry
        self._role = role

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
    ) -> JsonLLMResult:
        tenant_id = self._registry.active_tenant()
        gateway = (
            self._registry.configured_gateway(tenant_id, self._role)
            if tenant_id is not None
            else None
        )
        if gateway is None:
            return JsonLLMResult(
                ok=False,
                payload=None,
                model="unconfigured",
                provider_host="unconfigured",
                latency_ms=0,
                error=f"{self._role} model is not configured and tested",
            )
        return gateway.complete_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
        )


__all__ = ["ModelRuntimeRegistry"]
