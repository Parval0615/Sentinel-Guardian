import pytest

from redsentinel.application.engine.app import create_app
from redsentinel.application.engine.auth_config import (
    DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES,
    DEFAULT_REMEMBER_ME_EXPIRE_MINUTES,
)
from redsentinel.application.engine.auth_service import ProductAuthService


def _client(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    return TestClient(create_app(storage_root=tmp_path), raise_server_exceptions=False)


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _register_payload(
    *,
    username: str = "demo-user",
    email: str = "demo@example.test",
    password: str = "correct-horse-battery-staple",
) -> dict[str, str]:
    return {"username": username, "email": email, "password": password}


def _assert_auth_error(response, status_code: int, error_code: str) -> dict:
    assert response.status_code == status_code
    detail = response.json()["detail"]
    assert detail["schema_version"] == "auth-error-response-v0.1"
    assert detail["error_code"] == error_code
    assert detail["message"]
    assert "field_errors" in detail
    return detail


def test_auth_register_success_returns_token_and_persists_hashed_password(tmp_path) -> None:
    client = _client(tmp_path)

    response = client.post("/v1/auth/register", json=_register_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "auth-register-response-v0.1"
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert body["access_token"].count(".") == 2
    assert body["user"]["username"] == "demo-user"
    assert body["user"]["email"] == "demo@example.test"
    assert "correct-horse-battery-staple" not in response.text
    claims = ProductAuthService(storage_root=tmp_path).verify_access_token(body["access_token"])
    assert claims["user_id"] == body["user"]["user_id"]
    assert claims["username"] == body["user"]["username"]
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert claims["exp"] > claims["iat"]

    persisted = "\n".join(path.read_text(encoding="utf-8") for path in (tmp_path / "users").glob("*.json"))
    assert "correct-horse-battery-staple" not in persisted
    assert "password_hash" in persisted
    assert "password_salt" in persisted


def test_auth_register_rejects_duplicate_username_and_email(tmp_path) -> None:
    client = _client(tmp_path)
    client.post("/v1/auth/register", json=_register_payload())

    response = client.post("/v1/auth/register", json=_register_payload())

    detail = _assert_auth_error(response, 409, "user_conflict")
    assert {error["field"] for error in detail["field_errors"]} == {"username", "email"}


def test_auth_login_success_uses_remember_me_expiry_and_me_returns_current_user(tmp_path) -> None:
    client = _client(tmp_path)
    client.post("/v1/auth/register", json=_register_payload())

    login = client.post(
        "/v1/auth/login",
        json={"account": "demo@example.test", "password": "correct-horse-battery-staple", "remember_me": True},
    )

    assert login.status_code == 200
    body = login.json()
    assert body["schema_version"] == "auth-login-response-v0.1"
    assert body["expires_in"] == DEFAULT_REMEMBER_ME_EXPIRE_MINUTES * 60
    assert body["user"]["username"] == "demo-user"

    me = client.get("/v1/auth/me", headers=_auth_header(body["access_token"]))
    assert me.status_code == 200
    assert me.json()["schema_version"] == "auth-current-user-response-v0.1"
    assert me.json()["user"] == body["user"]


def test_auth_login_failure_uses_generic_invalid_credentials_error(tmp_path) -> None:
    client = _client(tmp_path)
    client.post("/v1/auth/register", json=_register_payload())

    response = client.post(
        "/v1/auth/login",
        json={"account": "demo@example.test", "password": "wrong-password"},
    )

    detail = _assert_auth_error(response, 401, "invalid_credentials")
    assert detail["message"] == "Invalid account or password."


def test_auth_me_rejects_missing_invalid_and_expired_tokens(tmp_path) -> None:
    client = _client(tmp_path)
    client.post("/v1/auth/register", json=_register_payload())

    missing = client.get("/v1/auth/me")
    invalid = client.get("/v1/auth/me", headers=_auth_header("not-a-valid-jwt"))

    auth_service = ProductAuthService(storage_root=tmp_path)
    user = auth_service.storage.find_user_by_username("demo-user")
    assert user is not None
    expired_token = auth_service.issue_access_token(user, expires_in_seconds=-60)
    expired = client.get("/v1/auth/me", headers=_auth_header(expired_token))

    _assert_auth_error(missing, 401, "auth_required")
    _assert_auth_error(invalid, 401, "token_invalid")
    _assert_auth_error(expired, 401, "token_expired")


def test_auth_logout_confirms_valid_session_and_malformed_authorization_is_400(tmp_path) -> None:
    client = _client(tmp_path)
    client.post("/v1/auth/register", json=_register_payload())
    login = client.post(
        "/v1/auth/login",
        json={"account": "demo-user", "password": "correct-horse-battery-staple"},
    )

    logout = client.post("/v1/auth/logout", headers=_auth_header(login.json()["access_token"]))
    invalidated = client.get("/v1/auth/me", headers=_auth_header(login.json()["access_token"]))
    malformed = client.get("/v1/auth/me", headers={"Authorization": "Token not-a-bearer-token"})

    assert logout.status_code == 200
    assert logout.json() == {
        "schema_version": "auth-logout-response-v0.1",
        "success": True,
        "message": "Logged out.",
    }
    _assert_auth_error(invalidated, 401, "token_invalid")
    _assert_auth_error(malformed, 400, "invalid_auth_request")


def test_auth_register_validation_errors_are_structured_422(tmp_path) -> None:
    client = _client(tmp_path)

    response = client.post(
        "/v1/auth/register",
        json={"username": "ab", "email": "not-an-email", "password": "short"},
    )

    detail = _assert_auth_error(response, 422, "invalid_auth_request")
    assert {"username", "email", "password"} <= {error["field"] for error in detail["field_errors"]}
