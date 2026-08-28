import json

import pytest

from redsentinel.application.engine.llm_gateway import OpenAIJsonGateway


class _Response:
    def __init__(self, payload: dict) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self) -> bytes:
        return self.body


@pytest.mark.parametrize(
    "base_url",
    [
        "ftp://api.example.test/v1",
        "https:///v1",
        "https://user:password@api.example.test/v1",
        "https://api.example.test/v1?tenant=secret",
        "https://api.example.test/v1#internal",
        "https://api.example.test:invalid/v1",
    ],
)
def test_gateway_rejects_unsafe_or_malformed_base_urls(base_url: str) -> None:
    with pytest.raises(ValueError, match="base_url"):
        OpenAIJsonGateway(
            api_key="test-key",
            base_url=base_url,
            model="planner-model",
        )


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_gateway_rejects_invalid_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        OpenAIJsonGateway(
            api_key="test-key",
            base_url="https://api.example.test/v1",
            model="planner-model",
            timeout_seconds=timeout,
        )


def test_gateway_uses_normalized_endpoint_without_exposing_credentials() -> None:
    captured = {}

    def opener(request, *, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.headers["Authorization"]
        captured["timeout"] = timeout
        return _Response(
            {
                "id": "request-123",
                "choices": [
                    {
                        "message": {
                            "content": '{"items": [{"scenario_id": "prompt-injection"}]}'
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 40,
                    "completion_tokens": 12,
                    "total_tokens": 52,
                },
            }
        )

    gateway = OpenAIJsonGateway(
        api_key="private-test-key",
        base_url="https://api.example.test/v1/",
        model="planner-model",
        timeout_seconds=5,
        opener=opener,
    )
    result = gateway.complete_json(
        system_prompt="Return JSON.",
        user_prompt="Plan the audit.",
        max_tokens=128,
    )

    assert result.ok is True
    assert result.provider_host == "api.example.test"
    assert result.provider_request_id == "request-123"
    assert result.prompt_tokens == 40
    assert result.completion_tokens == 12
    assert result.total_tokens == 52
    assert "private-test-key" not in repr(result)
    assert captured == {
        "url": "https://api.example.test/v1/chat/completions",
        "authorization": "Bearer private-test-key",
        "timeout": 5,
    }


def test_gateway_rejects_non_positive_token_budget() -> None:
    gateway = OpenAIJsonGateway(
        api_key="test-key",
        base_url="https://api.example.test/v1",
        model="planner-model",
    )

    with pytest.raises(ValueError, match="max_tokens"):
        gateway.complete_json(
            system_prompt="Return JSON.",
            user_prompt="Plan the audit.",
            max_tokens=0,
        )








def test_gateway_redacts_api_key_from_transport_errors() -> None:
    def opener(_request, *, timeout):
        raise RuntimeError(f"transport failed after {timeout}s with private-test-key")

    gateway = OpenAIJsonGateway(
        api_key="private-test-key",
        base_url="https://api.example.test/v1",
        model="planner-model",
        opener=opener,
    )

    result = gateway.complete_json(
        system_prompt="Return JSON.",
        user_prompt="Plan the audit.",
    )

    assert result.ok is False
    assert result.error is not None
    assert "private-test-key" not in result.error
    assert "[redacted]" in result.error
