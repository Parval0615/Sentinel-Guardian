from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr


JWT_SECRET_ENV = "RED_SENTINEL_JWT_SECRET"
RUNTIME_ENV_ENV = "RED_SENTINEL_ENV"
ACCESS_TOKEN_EXPIRE_MINUTES_ENV = "RED_SENTINEL_ACCESS_TOKEN_EXPIRE_MINUTES"
REMEMBER_ME_EXPIRE_MINUTES_ENV = "RED_SENTINEL_REMEMBER_ME_EXPIRE_MINUTES"

DEFAULT_JWT_SECRET = "red-sentinel-development-jwt-secret-do-not-use-in-production"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 60
DEFAULT_REMEMBER_ME_EXPIRE_MINUTES = 60 * 24 * 30
MIN_PRODUCTION_JWT_SECRET_LENGTH = 32
PRODUCTION_JWT_SECRET_HINT = (
    f"Set {JWT_SECRET_ENV} to a unique random secret with at least "
    f"{MIN_PRODUCTION_JWT_SECRET_LENGTH} characters in production."
)


class JwtAuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret_key: SecretStr = Field(min_length=1)
    algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = Field(default=DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES, ge=1)
    remember_me_expire_minutes: int = Field(default=DEFAULT_REMEMBER_ME_EXPIRE_MINUTES, ge=1)
    environment: str = Field(default="development", min_length=1)
    uses_development_secret: bool = False

    @property
    def access_token_expires_in_seconds(self) -> int:
        return self.access_token_expire_minutes * 60

    @property
    def remember_me_expires_in_seconds(self) -> int:
        return self.remember_me_expire_minutes * 60


@dataclass(frozen=True)
class RouteRule:
    method: str
    path_template: str

    def matches(self, method: str, path: str) -> bool:
        return self.method == method.upper() and bool(re.fullmatch(_template_pattern(self.path_template), _clean_path(path)))


PUBLIC_ROUTE_RULES: tuple[RouteRule, ...] = (
    RouteRule("GET", "/"),
    RouteRule("GET", "/health"),
    RouteRule("GET", "/v1/health"),
    RouteRule("POST", "/v1/auth/register"),
    RouteRule("POST", "/v1/auth/login"),
    RouteRule("GET", "/v1/benchmarks"),
    RouteRule("GET", "/v1/benchmarks/{benchmark_id}/versions"),
    RouteRule("GET", "/v1/benchmarks/{benchmark_id}/versions/{version}"),
    RouteRule("GET", "/v1/research/experiments"),
    RouteRule("GET", "/v1/research/experiments/{rq_id}"),
)

PUBLIC_STATIC_PATH_PREFIXES: tuple[str, ...] = (
    "/assets/",
    "/static/",
    "/favicon",
    "/robots.txt",
    "/manifest.webmanifest",
)

PROTECTED_ROUTE_RULES: tuple[RouteRule, ...] = (
    RouteRule("GET", "/v1/auth/me"),
    RouteRule("POST", "/v1/auth/logout"),
    RouteRule("POST", "/v1/demo/agents/ecommerce"),
    RouteRule("POST", "/v1/agents/onboard"),
    RouteRule("POST", "/v1/agents"),
    RouteRule("GET", "/v1/agents"),
    RouteRule("POST", "/v1/agents/import-image"),
    RouteRule("GET", "/v1/agents/index-errors"),
    RouteRule("DELETE", "/v1/agents/{agent_id}"),
    RouteRule("GET", "/v1/agents/{agent_id}"),
    RouteRule("GET", "/v1/agents/{agent_id}/profile"),
    RouteRule("POST", "/v1/agents/{agent_id}/profiles"),
    RouteRule("GET", "/v1/agents/{agent_id}/profiles/latest"),
    RouteRule("GET", "/v1/agents/{agent_id}/profiles/{analysis_id}/status"),
    RouteRule("POST", "/v1/agents/{agent_id}/profiles/{analysis_id}/retry"),
    RouteRule("POST", "/v1/agents/{agent_id}/sessions"),
    RouteRule("POST", "/v1/evaluations"),
    RouteRule("GET", "/v1/evaluations/{evaluation_id}"),
    RouteRule("POST", "/v1/evaluations/{evaluation_id}/next-round"),
    RouteRule("POST", "/v1/audits"),
    RouteRule("POST", "/v1/audits/{audit_id}/execute"),
    RouteRule("GET", "/v1/audits/{audit_id}"),
    RouteRule("GET", "/v1/audits/{audit_id}/status"),
    RouteRule("GET", "/v1/audits/{audit_id}/plan"),
    RouteRule("GET", "/v1/audits/{audit_id}/evidence"),
    RouteRule("GET", "/v1/audits/{audit_id}/decision"),
    RouteRule("GET", "/v1/audits/{audit_id}/workspace"),
    RouteRule("POST", "/v1/audits/{audit_id}/resume"),
    RouteRule("POST", "/v1/audits/{audit_id}/next-round"),
    RouteRule("GET", "/v1/runtime/openmanus/status"),
    RouteRule("POST", "/v1/runtime/openmanus/config"),
    RouteRule("GET", "/v1/runtime/models/status"),
    RouteRule("GET", "/v1/runtime/audit-preflight/{agent_id}"),
    RouteRule("POST", "/v1/runtime/models/{role}/test"),
    RouteRule("GET", "/v1/reports/{report_id}"),
    RouteRule("GET", "/v1/logs"),
    RouteRule("GET", "/v1/logs/{evaluation_id}"),
    RouteRule("GET", "/v1/dashboard/summary"),
    RouteRule("GET", "/v1/supervision/latest"),
    RouteRule("GET", "/v1/supervision/events"),
    RouteRule("POST", "/v1/supervision/demo-seed"),
    RouteRule("POST", "/v1/supervision/ask/{event_id}/respond"),
    RouteRule("POST", "/v1/comparisons"),
    RouteRule("POST", "/v1/trajectories"),
)

ADMIN_ROUTE_RULES: tuple[RouteRule, ...] = (
    RouteRule("GET", "/v1/monitor/events"),
    RouteRule("GET", "/v1/monitor/events/summary"),
    RouteRule("POST", "/v1/admin/agents/openmanus"),
    RouteRule("GET", "/v1/admin/agent-library"),
    RouteRule("POST", "/v1/admin/agent-library"),
    RouteRule("GET", "/v1/admin/agent-library/{agent_id}"),
)


def read_jwt_auth_settings(environ: Mapping[str, str] | None = None) -> JwtAuthSettings:
    env = os.environ if environ is None else environ
    environment = _env_text(env, RUNTIME_ENV_ENV, default="development").lower()
    secret = _env_text(env, JWT_SECRET_ENV, default=DEFAULT_JWT_SECRET)
    uses_development_secret = secret == DEFAULT_JWT_SECRET

    if environment in {"prod", "production"} and (
        uses_development_secret or len(secret) < MIN_PRODUCTION_JWT_SECRET_LENGTH
    ):
        raise ValueError(PRODUCTION_JWT_SECRET_HINT)

    return JwtAuthSettings(
        secret_key=secret,
        access_token_expire_minutes=_env_minutes(
            env,
            ACCESS_TOKEN_EXPIRE_MINUTES_ENV,
            DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES,
        ),
        remember_me_expire_minutes=_env_minutes(
            env,
            REMEMBER_ME_EXPIRE_MINUTES_ENV,
            DEFAULT_REMEMBER_ME_EXPIRE_MINUTES,
        ),
        environment=environment,
        uses_development_secret=uses_development_secret,
    )


def is_public_route(method: str, path: str) -> bool:
    clean_path = _clean_path(path)
    return clean_path.startswith(PUBLIC_STATIC_PATH_PREFIXES) or any(
        rule.matches(method, clean_path) for rule in PUBLIC_ROUTE_RULES
    )


def is_protected_route(method: str, path: str) -> bool:
    return is_admin_route(method, path) or any(rule.matches(method, path) for rule in PROTECTED_ROUTE_RULES)


def is_admin_route(method: str, path: str) -> bool:
    return any(rule.matches(method, path) for rule in ADMIN_ROUTE_RULES)


def _env_text(env: Mapping[str, str], name: str, *, default: str) -> str:
    value = env.get(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def _env_minutes(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer number of minutes.") from exc
    if value < 1:
        raise ValueError(f"{name} must be a positive integer number of minutes.")
    return value


def _clean_path(path: str) -> str:
    clean = path.split("?", 1)[0] or "/"
    return clean.rstrip("/") if clean != "/" else clean


def _template_pattern(path_template: str) -> str:
    segments = _clean_path(path_template).split("/")
    return "/".join(
        r"[^/]+"
        if re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*\}", segment)
        else re.escape(segment)
        for segment in segments
    )
