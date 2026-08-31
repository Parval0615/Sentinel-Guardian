from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from redsentinel.application.engine.auth_config import JwtAuthSettings, read_jwt_auth_settings
from redsentinel.application.engine.auth_password import hash_password, verify_password
from redsentinel.application.contracts import (
    AuthCurrentUserResponse,
    AuthErrorCode,
    AuthErrorResponse,
    AuthFieldError,
    AuthLoginRequest,
    AuthLoginResponse,
    AuthLogoutResponse,
    AuthRegisterRequest,
    AuthRegisterResponse,
    AuthUserSummary,
    utc_now_iso,
)
from redsentinel.application.engine.storage import ProductStorage


JWT_TYPE = "JWT"
JWT_PURPOSE = "access"


class AuthServiceError(ValueError):
    def __init__(
        self,
        status_code: int,
        error_code: AuthErrorCode,
        message: str,
        *,
        field_errors: list[AuthFieldError] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = AuthErrorResponse(
            error_code=error_code,
            message=message,
            field_errors=field_errors or [],
        )

    def to_detail(self) -> dict[str, Any]:
        return self.response.model_dump(mode="json")


class ProductAuthService:
    def __init__(
        self,
        storage_root: str | Path = "runs/product",
        *,
        storage: ProductStorage | None = None,
        settings: JwtAuthSettings | None = None,
    ) -> None:
        self.storage = storage or ProductStorage(storage_root)
        self.settings = settings or read_jwt_auth_settings()

    def register(self, request: AuthRegisterRequest) -> AuthRegisterResponse:
        username = request.username.strip()
        email = request.email.strip()
        self._raise_if_user_conflict(username, email)

        now = utc_now_iso()
        password_hash, password_salt = hash_password(request.password.get_secret_value())
        user = self.storage.write_user(
            f"usr_{uuid4().hex[:12]}",
            {
                "username": username,
                "email": email,
                "password_hash": password_hash,
                "password_salt": password_salt,
                "created_at": now,
                "updated_at": now,
                "last_login_at": now,
                "status": "active",
                "role": "user",
            },
        )
        return AuthRegisterResponse(
            access_token=self.issue_access_token(user, expires_in_seconds=self.settings.access_token_expires_in_seconds),
            expires_in=self.settings.access_token_expires_in_seconds,
            user=_user_summary(user),
        )

    def login(self, request: AuthLoginRequest) -> AuthLoginResponse:
        account = request.account.strip()
        if not account:
            raise AuthServiceError(
                400,
                "invalid_auth_request",
                "Account is required.",
                field_errors=[AuthFieldError(field="account", message="Account is required.")],
            )

        user = self._find_user_for_account(account)
        if user is None or not verify_password(
            request.password.get_secret_value(),
            user["password_hash"],
            user["password_salt"],
        ):
            raise AuthServiceError(401, "invalid_credentials", "Invalid account or password.")
        self._raise_if_user_disabled(user)

        now = utc_now_iso()
        user = self.storage.write_user(
            user["user_id"],
            {
                **user,
                "updated_at": now,
                "last_login_at": now,
            },
        )
        expires_in = (
            self.settings.remember_me_expires_in_seconds
            if request.remember_me
            else self.settings.access_token_expires_in_seconds
        )
        return AuthLoginResponse(
            access_token=self.issue_access_token(user, expires_in_seconds=expires_in),
            expires_in=expires_in,
            user=_user_summary(user),
        )

    def current_user_from_authorization(self, authorization: str | None) -> AuthCurrentUserResponse:
        user = self.require_user_from_authorization(authorization)
        return AuthCurrentUserResponse(user=_user_summary(user))

    def logout(self, authorization: str | None) -> AuthLogoutResponse:
        user = self.require_user_from_authorization(authorization)
        self.storage.write_user(
            user["user_id"],
            {
                **user,
                "token_version": int(user.get("token_version", 0)) + 1,
                "updated_at": utc_now_iso(),
            },
        )
        return AuthLogoutResponse()

    def require_user_from_authorization(self, authorization: str | None) -> dict[str, Any]:
        token = self._bearer_token(authorization)
        claims = self.verify_access_token(token)
        user_id = str(claims["user_id"])
        try:
            user = self.storage.read_user(user_id)
        except (FileNotFoundError, ValueError) as exc:
            raise AuthServiceError(401, "token_invalid", "Authentication token is invalid.") from exc
        if user["username"] != claims["username"]:
            raise AuthServiceError(401, "token_invalid", "Authentication token is invalid.")
        if int(user.get("token_version", 0)) != claims["token_version"]:
            raise AuthServiceError(401, "token_invalid", "Authentication token is invalid.")
        self._raise_if_user_disabled(user)
        return user

    def issue_access_token(self, user: dict[str, Any], *, expires_in_seconds: int) -> str:
        now = _utc_timestamp()
        payload = {
            "sub": user["user_id"],
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "iat": now,
            "exp": now + expires_in_seconds,
            "purpose": JWT_PURPOSE,
            "token_version": int(user.get("token_version", 0)),
        }
        return _encode_jwt(payload, self.settings)

    def verify_access_token(self, token: str) -> dict[str, Any]:
        try:
            payload = _decode_jwt(token, self.settings)
        except _TokenExpiredError as exc:
            raise AuthServiceError(401, "token_expired", "Authentication token has expired.") from exc
        except _TokenInvalidError as exc:
            raise AuthServiceError(401, "token_invalid", "Authentication token is invalid.") from exc

        user_id = payload.get("user_id") or payload.get("sub")
        username = payload.get("username")
        role = payload.get("role") or "user"
        iat = payload.get("iat")
        exp = payload.get("exp")
        token_version = payload.get("token_version")
        if (
            not isinstance(user_id, str)
            or not user_id
            or not isinstance(username, str)
            or not username
            or role not in {"user", "admin"}
            or not _is_int_claim(iat)
            or not _is_int_claim(exp)
            or not _is_int_claim(token_version)
            or token_version < 0
            or payload.get("purpose") != JWT_PURPOSE
        ):
            raise AuthServiceError(401, "token_invalid", "Authentication token is invalid.")
        return {
            "user_id": user_id,
            "username": username,
            "role": role,
            "iat": iat,
            "exp": exp,
            "purpose": JWT_PURPOSE,
            "token_version": token_version,
        }

    def _bearer_token(self, authorization: str | None) -> str:
        if authorization is None or not authorization.strip():
            raise AuthServiceError(401, "auth_required", "Authentication token is required.")

        parts = authorization.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthServiceError(400, "invalid_auth_request", "Authorization header must use Bearer token.")
        return parts[1]

    def _find_user_for_account(self, account: str) -> dict[str, Any] | None:
        if "@" in account:
            return self.storage.find_user_by_email(account)
        return self.storage.find_user_by_username(account)

    def _raise_if_user_conflict(self, username: str, email: str) -> None:
        field_errors: list[AuthFieldError] = []
        if self.storage.find_user_by_username(username) is not None:
            field_errors.append(
                AuthFieldError(
                    field="username",
                    message="Username already exists.",
                    error_code="username_exists",
                )
            )
        if self.storage.find_user_by_email(email) is not None:
            field_errors.append(
                AuthFieldError(
                    field="email",
                    message="Email already exists.",
                    error_code="email_exists",
                )
            )
        if field_errors:
            raise AuthServiceError(
                409,
                "user_conflict",
                "Username or email already exists.",
                field_errors=field_errors,
            )

    def _raise_if_user_disabled(self, user: dict[str, Any]) -> None:
        if user["status"] != "active":
            raise AuthServiceError(401, "user_disabled", "User account is disabled.")


class _TokenInvalidError(ValueError):
    pass


class _TokenExpiredError(_TokenInvalidError):
    pass


def _user_summary(user: dict[str, Any]) -> AuthUserSummary:
    return AuthUserSummary(
        user_id=user["user_id"],
        username=user["username"],
        email=user["email"],
        status=user["status"],
        role=user["role"],
    )


def _encode_jwt(payload: dict[str, Any], settings: JwtAuthSettings) -> str:
    header = {"alg": settings.algorithm, "typ": JWT_TYPE}
    signing_input = f"{_base64url_json(header)}.{_base64url_json(payload)}"
    signature = _sign(signing_input.encode("ascii"), settings)
    return f"{signing_input}.{_base64url_encode(signature)}"


def _decode_jwt(token: str, settings: JwtAuthSettings) -> dict[str, Any]:
    try:
        header_segment, payload_segment, signature_segment = token.split(".", 2)
    except ValueError as exc:
        raise _TokenInvalidError("Token must contain header, payload, and signature.") from exc

    try:
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        signature_segment.encode("ascii")
    except UnicodeEncodeError as exc:
        raise _TokenInvalidError("Token segments must be ASCII.") from exc
    expected_signature = _base64url_encode(_sign(signing_input, settings))
    if not hmac.compare_digest(signature_segment, expected_signature):
        raise _TokenInvalidError("Token signature is invalid.")

    header = _decode_json_segment(header_segment)
    payload = _decode_json_segment(payload_segment)
    if header.get("alg") != settings.algorithm or header.get("typ") != JWT_TYPE:
        raise _TokenInvalidError("Token header is invalid.")
    exp = payload.get("exp")
    if not _is_int_claim(exp):
        raise _TokenInvalidError("Token expiration is invalid.")
    if exp <= _utc_timestamp():
        raise _TokenExpiredError("Token has expired.")
    return payload


def _sign(signing_input: bytes, settings: JwtAuthSettings) -> bytes:
    return hmac.new(
        settings.secret_key.get_secret_value().encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()


def _base64url_json(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _base64url_encode(encoded)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_json_segment(segment: str) -> dict[str, Any]:
    try:
        payload = json.loads(_base64url_decode(segment))
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError, UnicodeEncodeError) as exc:
        raise _TokenInvalidError("Token segment is invalid.") from exc
    if not isinstance(payload, dict):
        raise _TokenInvalidError("Token segment must be an object.")
    return payload


def _base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.b64decode((value + padding).encode("ascii"), altchars=b"-_", validate=True)


def _utc_timestamp() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _is_int_claim(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


__all__ = ["AuthServiceError", "ProductAuthService"]
