import pytest
from pydantic import ValidationError

from redsentinel.application.engine.auth_config import (
    ACCESS_TOKEN_EXPIRE_MINUTES_ENV,
    DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES,
    DEFAULT_JWT_SECRET,
    DEFAULT_REMEMBER_ME_EXPIRE_MINUTES,
    JWT_SECRET_ENV,
    REMEMBER_ME_EXPIRE_MINUTES_ENV,
    RUNTIME_ENV_ENV,
    is_protected_route,
    is_admin_route,
    is_public_route,
    read_jwt_auth_settings,
)
from redsentinel.application.contracts import (
    AuthCurrentUserResponse,
    AuthErrorResponse,
    AuthFieldError,
    AuthLoginRequest,
    AuthLoginResponse,
    AuthLogoutResponse,
    AuthRegisterRequest,
    AuthRegisterResponse,
    AuthUserSummary,
)


def test_auth_contracts_validate_core_fields_and_exclude_passwords() -> None:
    register = AuthRegisterRequest(
        username="demo-user",
        email="demo@example.test",
        password="strong-password",
    )
    login = AuthLoginRequest(
        account="demo@example.test",
        password="strong-password",
        remember_me=True,
    )
    user = AuthUserSummary(user_id="usr_001", username=register.username, email=register.email)
    register_response = AuthRegisterResponse(access_token="jwt-token", expires_in=3600, user=user)
    login_response = AuthLoginResponse(access_token="jwt-token", expires_in=3600, user=user)

    assert register.schema_version == "auth-register-request-v0.1"
    assert register.password.get_secret_value() == "strong-password"
    assert "password" not in register.model_dump(mode="json")
    assert login.remember_me is True
    assert "password" not in login.model_dump(mode="json")
    assert register_response.token_type == "bearer"
    assert register_response.user.status == "active"
    assert login_response.schema_version == "auth-login-response-v0.1"
    assert AuthCurrentUserResponse(user=user).user.user_id == "usr_001"
    assert AuthLogoutResponse().success is True


def test_auth_error_contract_supports_field_errors() -> None:
    response = AuthErrorResponse(
        error_code="invalid_auth_request",
        message="Request validation failed.",
        field_errors=[
            AuthFieldError(
                field="email",
                message="Email is invalid.",
                error_code="invalid_email",
            )
        ],
    )

    assert response.schema_version == "auth-error-response-v0.1"
    assert response.field_errors[0].field == "email"
    assert response.model_dump(mode="json")["field_errors"][0]["error_code"] == "invalid_email"


def test_auth_contracts_reject_invalid_shapes() -> None:
    with pytest.raises(ValidationError):
        AuthRegisterRequest(username="bad user", email="demo@example.test", password="strong-password")

    with pytest.raises(ValidationError):
        AuthRegisterRequest(username="demo", email="not-an-email", password="strong-password")

    with pytest.raises(ValidationError):
        AuthLoginRequest(account="demo@example.test", password="")

    with pytest.raises(ValidationError):
        AuthErrorResponse(error_code="unknown_error", message="Invalid.")


def test_jwt_auth_settings_use_development_defaults() -> None:
    settings = read_jwt_auth_settings({})

    assert settings.secret_key.get_secret_value() == DEFAULT_JWT_SECRET
    assert settings.algorithm == "HS256"
    assert settings.environment == "development"
    assert settings.uses_development_secret is True
    assert settings.access_token_expire_minutes == DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES
    assert settings.remember_me_expire_minutes == DEFAULT_REMEMBER_ME_EXPIRE_MINUTES
    assert settings.access_token_expires_in_seconds == DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert settings.remember_me_expires_in_seconds == DEFAULT_REMEMBER_ME_EXPIRE_MINUTES * 60


def test_jwt_auth_settings_read_environment_overrides_and_guard_production_secret() -> None:
    settings = read_jwt_auth_settings(
        {
            JWT_SECRET_ENV: "prod-secret-value-with-enough-length",
            RUNTIME_ENV_ENV: "production",
            ACCESS_TOKEN_EXPIRE_MINUTES_ENV: "15",
            REMEMBER_ME_EXPIRE_MINUTES_ENV: "43200",
        }
    )

    assert settings.secret_key.get_secret_value() == "prod-secret-value-with-enough-length"
    assert settings.environment == "production"
    assert settings.uses_development_secret is False
    assert settings.access_token_expire_minutes == 15
    assert settings.remember_me_expire_minutes == 43200

    with pytest.raises(ValueError, match=JWT_SECRET_ENV):
        read_jwt_auth_settings({RUNTIME_ENV_ENV: "production"})

    with pytest.raises(ValueError, match=ACCESS_TOKEN_EXPIRE_MINUTES_ENV):
        read_jwt_auth_settings({ACCESS_TOKEN_EXPIRE_MINUTES_ENV: "0"})


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/"),
        ("GET", "/assets/app.js"),
        ("GET", "/static/app.css"),
        ("GET", "/favicon.ico"),
        ("GET", "/robots.txt"),
        ("GET", "/manifest.webmanifest"),
        ("GET", "/health"),
        ("GET", "/v1/health"),
        ("POST", "/v1/auth/register"),
        ("POST", "/v1/auth/login"),
        ("GET", "/v1/benchmarks"),
        ("GET", "/v1/benchmarks/ecommerce-security-v0.1/versions"),
        ("GET", "/v1/benchmarks/ecommerce-security-v0.1/versions/v1?include=cases"),
    ],
)
def test_public_route_rules(method: str, path: str) -> None:
    assert is_public_route(method, path) is True
    assert is_protected_route(method, path) is False


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/auth/me"),
        ("POST", "/v1/auth/logout"),
        ("POST", "/v1/agents/onboard"),
        ("POST", "/v1/agents"),
        ("GET", "/v1/agents/agent_001"),
        ("GET", "/v1/agents/agent_001/profile"),
        ("POST", "/v1/agents/agent_001/sessions"),
        ("POST", "/v1/evaluations"),
        ("POST", "/v1/audits"),
        ("POST", "/v1/audits/audit_001/execute"),
        ("GET", "/v1/audits/audit_001"),
        ("GET", "/v1/audits/audit_001/status"),
        ("GET", "/v1/audits/audit_001/plan"),
        ("GET", "/v1/audits/audit_001/evidence"),
        ("POST", "/v1/audits/audit_001/resume"),
        ("POST", "/v1/audits/audit_001/next-round"),
        ("GET", "/v1/runtime/openmanus/status"),
        ("POST", "/v1/runtime/openmanus/config"),
        ("GET", "/v1/runtime/models/status"),
        ("POST", "/v1/runtime/models/attack/test"),
        ("GET", "/v1/runtime/audit-preflight/agent_001"),
        ("GET", "/v1/evaluations/eval_001"),
        ("POST", "/v1/evaluations/eval_001/next-round"),
        ("GET", "/v1/reports/report_001"),
        ("GET", "/v1/logs?agent_id=agent_001"),
        ("GET", "/v1/logs/eval_001"),
        ("GET", "/v1/dashboard/summary?agent_id=agent_001"),
        ("POST", "/v1/comparisons"),
        ("POST", "/v1/trajectories"),
        ("GET", "/v1/admin/agent-library"),
        ("POST", "/v1/admin/agent-library"),
        ("GET", "/v1/admin/agent-library/openmanus_official"),
    ],
)
def test_protected_route_rules(method: str, path: str) -> None:
    assert is_protected_route(method, path) is True
    assert is_public_route(method, path) is False


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/admin/agent-library"),
        ("POST", "/v1/admin/agent-library"),
        ("GET", "/v1/admin/agent-library/openmanus_official"),
    ],
)
def test_admin_route_rules(method: str, path: str) -> None:
    assert is_admin_route(method, path) is True
    assert is_protected_route(method, path) is True
