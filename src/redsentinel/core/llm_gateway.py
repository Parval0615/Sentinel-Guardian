from __future__ import annotations

import hashlib
import json
import math
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse


@dataclass(frozen=True)
class JsonLLMResult:
    ok: bool
    payload: dict[str, Any] | None
    model: str
    provider_host: str
    latency_ms: float
    response_sha256: str | None = None
    provider_request_id: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    error: str | None = None


class JsonLLMGateway(Protocol):
    """Return one JSON object without exposing provider credentials."""

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
    ) -> JsonLLMResult: ...


class OpenAIJsonGateway:
    """Minimal OpenAI-compatible JSON gateway."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        timeout_seconds: float = 30.0,
        opener: Any = urllib.request.urlopen,
    ) -> None:
        if not api_key.strip():
            raise ValueError("api_key is required")
        if not base_url.strip():
            raise ValueError("base_url is required")
        if not model.strip():
            raise ValueError("model is required")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive finite number")
        self._api_key = api_key
        self._base_url = _normalize_base_url(base_url)
        self.model = model
        self.timeout_seconds = timeout_seconds
        self._opener = opener

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
    ) -> JsonLLMResult:
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        started = time.monotonic()
        url = self._base_url.rstrip("/") + "/chat/completions"
        request = urllib.request.Request(
            url,
            data=json.dumps(
                {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0,
                    "max_tokens": max_tokens,
                    "response_format": {"type": "json_object"},
                },
                ensure_ascii=False,
            ).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener(request, timeout=self.timeout_seconds) as response:
                body = response.read().decode("utf-8", errors="replace")
            response_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
            envelope = json.loads(body)
            usage = envelope.get("usage") if isinstance(envelope.get("usage"), dict) else {}
            metadata = {
                "provider_request_id": _optional_string(envelope.get("id")),
                "prompt_tokens": _optional_non_negative_int(usage.get("prompt_tokens")),
                "completion_tokens": _optional_non_negative_int(usage.get("completion_tokens")),
                "total_tokens": _optional_non_negative_int(usage.get("total_tokens")),
            }
            content = str(envelope.get("choices", [{}])[0].get("message", {}).get("content") or "")
            payload = _extract_json_object(content)
            if payload is None:
                return self._result(
                    started,
                    ok=False,
                    payload=None,
                    response_sha256=response_sha256,
                    error="response did not contain a JSON object",
                    **metadata,
                )
            return self._result(
                started,
                ok=True,
                payload=payload,
                response_sha256=response_sha256,
                **metadata,
            )
        except urllib.error.HTTPError as exc:
            error = f"HTTP {exc.code}"
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        error = error.replace(self._api_key, "[redacted]")
        return self._result(started, ok=False, payload=None, error=error)

    def _result(
        self,
        started: float,
        *,
        ok: bool,
        payload: dict[str, Any] | None,
        response_sha256: str | None = None,
        provider_request_id: str | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
        total_tokens: int | None = None,
        error: str | None = None,
    ) -> JsonLLMResult:
        return JsonLLMResult(
            ok=ok,
            payload=payload,
            model=self.model,
            provider_host=urlparse(self._base_url).netloc,
            latency_ms=round((time.monotonic() - started) * 1000, 3),
            response_sha256=response_sha256,
            provider_request_id=provider_request_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            error=error,
        )


def _normalize_base_url(value: str) -> str:
    stripped = value.strip().rstrip("/")
    parsed = urlparse(stripped)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("base_url must be an HTTP(S) URL")
    if not parsed.hostname:
        raise ValueError("base_url must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must not include user credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not include a query or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("base_url contains an invalid port") from exc
    return stripped


def _extract_json_object(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        lines = lines[1:] if lines else lines
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    decoder = json.JSONDecoder()
    for index, char in enumerate(stripped):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(stripped[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _optional_string(value: Any) -> str | None:
    stripped = str(value or "").strip()
    return stripped or None


def _optional_non_negative_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


__all__ = ["JsonLLMGateway", "JsonLLMResult", "OpenAIJsonGateway"]
