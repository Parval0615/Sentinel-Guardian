from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_SENSITIVE_FIELD_NAMES = {
    "access_key",
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "bearer_token",
    "client_secret",
    "credential",
    "credentials",
    "password",
    "passwd",
    "private_key",
    "pwd",
    "refresh_token",
    "secret",
    "token",
}
_SENSITIVE_NAME = (
    r"(?:api[_-]?key|authorization|access[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"bearer[_-]?token|client[_-]?secret|private[_-]?key|credential(?:s)?|"
    r"password|passwd|pwd|secret|token)"
)
_AUTHORIZATION_RE = re.compile(
    rf"(?i)(\b(?:authorization|auth)\b[\"']?\s*[:=]\s*)"
    r"(?:(?:bearer|basic)\s+)?[A-Za-z0-9._~+/=-]+"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIAL_RE = re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@")
_ASSIGNMENT_RE = re.compile(
    rf"(?i)(\b[\"']?{_SENSITIVE_NAME}[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&]+)"
)
_OPTION_RE = re.compile(
    rf"(?i)(--?{_SENSITIVE_NAME}(?:=|\s+))"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&]+)"
)


def redact_image_profile_text(value: str) -> str:
    redacted = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", value)
    redacted = _AUTHORIZATION_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _BEARER_RE.sub(r"\1 [REDACTED]", redacted)
    redacted = _OPTION_RE.sub(r"\1[REDACTED]", redacted)
    return _ASSIGNMENT_RE.sub(r"\1[REDACTED]", redacted)


def sanitize_image_profile_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): (
                "[REDACTED]"
                if _is_sensitive_field(str(key))
                else sanitize_image_profile_payload(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_image_profile_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_image_profile_payload(item) for item in value)
    if isinstance(value, str):
        return redact_image_profile_text(value)
    return value


def safe_image_profile_error(exc: BaseException, *, max_length: int = 500) -> str:
    return redact_image_profile_text(f"{type(exc).__name__}: {exc}")[:max_length]


def sanitize_image_profile_log(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        return
    content = path.read_text(encoding="utf-8", errors="replace")
    redacted = redact_image_profile_text(content)
    if redacted != content:
        path.write_text(redacted, encoding="utf-8")


def sanitize_image_profile_json_lines(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        return
    sanitized_lines: list[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
        except json.JSONDecodeError:
            sanitized_lines.append(redact_image_profile_text(raw_line))
            continue
        sanitized_lines.append(
            json.dumps(
                sanitize_image_profile_payload(payload),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    path.write_text(
        "".join(f"{line}\n" for line in sanitized_lines),
        encoding="utf-8",
    )


def _is_sensitive_field(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return (
        normalized in _SENSITIVE_FIELD_NAMES
        or normalized.endswith("_api_key")
        or normalized.endswith("_access_token")
        or normalized.endswith("_refresh_token")
    )


__all__ = [
    "redact_image_profile_text",
    "safe_image_profile_error",
    "sanitize_image_profile_json_lines",
    "sanitize_image_profile_log",
    "sanitize_image_profile_payload",
]
