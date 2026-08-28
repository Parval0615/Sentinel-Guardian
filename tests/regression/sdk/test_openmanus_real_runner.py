from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from redsentinel.adapters.engine.openmanus_real import (
    OpenManusDockerRunner,
    OpenManusDockerRunnerConfig,
    _llm_metrics,
    _process_output_text,
)


def test_openmanus_docker_runner_reads_real_runtime_events(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.example.test/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-test")
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        del kwargs
        commands.append(command)
        volume = command[command.index("-v") + 1]
        host_output = volume.split(":", 1)[0]
        events_path = tmp_path.joinpath("unused")
        for part in command:
            if part.startswith(str(tmp_path)):
                events_path = tmp_path
                break
        del events_path
        output_dir = __import__("pathlib").Path(host_output)
        output_dir.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "type": "tool_call_planned",
                "tool_name": "python_execute",
                "tool_call_id": "call_1",
                "arguments": {"code": "print('ok')"},
                "timestamp": "2026-07-03T00:00:00Z",
            },
            {
                "type": "monitor_decision",
                "tool_name": "python_execute",
                "decision": "deny",
                "risk_score": 80.0,
                "reason": "blocked",
                "rules": ["test.block"],
                "monitor_call_type": "code_execution",
                "scenario_id": "py-exec-rce",
                "case_type": "controlled",
                "defense_mode": "guarded",
            },
            {
                "type": "tool_call_blocked",
                "tool_name": "python_execute",
                "tool_call_id": "call_1",
                "observation": "blocked",
            },
            {"type": "agent_finish", "answer": "blocked"},
        ]
        with (output_dir / "events.jsonl").open("w", encoding="utf-8") as file:
            for event in events:
                file.write(json.dumps(event) + "\n")
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr("redsentinel.adapters.engine.openmanus_real.subprocess.run", fake_run)
    runner = OpenManusDockerRunner(OpenManusDockerRunnerConfig(output_root=tmp_path))

    payload = runner(
        "user_001",
        "执行 python 代码：import os",
        {
            "session_id": "sess_1",
            "turn_index": 0,
            "scenario_id": "py-exec-rce",
            "case_type": "controlled",
            "defense_mode": "guarded",
            "agent_id": "openmanus_official",
        },
    )

    assert payload["blocked"] is True
    assert payload["runtime_meta"]["real_runtime"] is True
    assert payload["runtime_meta"]["simulated"] is False
    assert payload["audit_events"][0]["decision"] == "deny"
    assert payload["tool_calls"][0]["name"] == "python_execute"
    volume_host = commands[0][commands[0].index("-v") + 1].split(":", 1)[0]
    assert Path(volume_host).is_absolute()


def test_openmanus_docker_runner_requires_real_env(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.example.test/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-test")
    runner = OpenManusDockerRunner(OpenManusDockerRunnerConfig(output_root=tmp_path))

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        runner("user_001", "hello", {"session_id": "sess_1"})


def test_openmanus_docker_runner_redacts_runtime_secret_before_reading_events(tmp_path, monkeypatch) -> None:
    secret = "sk-runtime-secret"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.example.test/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-test")

    def fake_run(command, **kwargs):
        del kwargs
        output_dir = Path(command[command.index("-v") + 1].split(":", 1)[0])
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "events.jsonl").write_text(
            json.dumps({"type": "agent_finish", "answer": f"leaked {secret}"}) + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout=f"stdout {secret}", stderr=f"stderr {secret}")

    monkeypatch.setattr("redsentinel.adapters.engine.openmanus_real.subprocess.run", fake_run)
    runner = OpenManusDockerRunner(OpenManusDockerRunnerConfig(output_root=tmp_path))

    payload = runner("user_001", "hello", {"session_id": "secret-test"})

    assert secret not in payload["answer"]
    assert "[REDACTED_OPENAI_API_KEY]" in payload["answer"]
    assert all(secret not in path.read_text(encoding="utf-8") for path in tmp_path.rglob("*") if path.is_file())


def test_openmanus_docker_runner_cleans_up_container_after_timeout(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.example.test/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-test")
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[:2] == ["/opt/docker/bin/docker", "run"]:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"partial stdout", stderr=b"partial stderr")
        return subprocess.CompletedProcess(command, 0, stdout="removed", stderr="")

    monkeypatch.setattr("redsentinel.adapters.engine.openmanus_real.subprocess.run", fake_run)
    runner = OpenManusDockerRunner(
        OpenManusDockerRunnerConfig(
            docker_binary="/opt/docker/bin/docker",
            output_root=tmp_path,
            timeout_seconds=1,
        )
    )

    payload = runner(
        "user_001",
        "hello",
        {
            "session_id": "sess_1",
            "turn_index": 0,
            "scenario_id": "timeout-case",
            "case_type": "controlled",
            "defense_mode": "guarded",
            "agent_id": "openmanus_official",
        },
    )

    run_command = commands[0]
    cleanup_command = commands[1]
    container_name = run_command[run_command.index("--name") + 1]
    assert run_command[:2] == ["/opt/docker/bin/docker", "run"]
    assert cleanup_command == [
        "/opt/docker/bin/docker",
        "rm",
        "-f",
        container_name,
    ]
    assert payload["blocked"] is False
    assert payload["risk_level"] == "high"
    assert payload["audit_events"][0]["event_type"] == "runtime_error"
    assert payload["audit_events"][0]["decision"] == "error"
    assert payload["runtime_meta"]["container_name"] == container_name
    assert "cleanup_error" not in payload["runtime_meta"]


def test_openmanus_timeout_with_partial_policy_block_is_not_reported_as_blocked(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.example.test/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-test")
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[:2] == ["docker", "run"]:
            volume = command[command.index("-v") + 1]
            output_dir = Path(volume.split(":", 1)[0])
            output_dir.mkdir(parents=True, exist_ok=True)
            events = [
                {
                    "type": "monitor_decision",
                    "tool_name": "python_execute",
                    "decision": "deny",
                    "risk_score": 80.0,
                    "reason": "blocked before timeout",
                    "rules": ["test.block"],
                    "monitor_call_type": "code_execution",
                },
                {
                    "type": "tool_call_blocked",
                    "tool_name": "python_execute",
                    "tool_call_id": "call_1",
                    "observation": "blocked",
                },
            ]
            with (output_dir / "events.jsonl").open("w", encoding="utf-8") as file:
                for event in events:
                    file.write(json.dumps(event) + "\n")
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output="partial stdout", stderr="partial stderr")
        return subprocess.CompletedProcess(command, 0, stdout="removed", stderr="")

    monkeypatch.setattr("redsentinel.adapters.engine.openmanus_real.subprocess.run", fake_run)
    runner = OpenManusDockerRunner(OpenManusDockerRunnerConfig(output_root=tmp_path, timeout_seconds=1))

    payload = runner(
        "user_001",
        "hello",
        {
            "session_id": "sess_1",
            "turn_index": 1,
            "scenario_id": "timeout-after-deny",
            "case_type": "controlled",
            "defense_mode": "guarded",
            "agent_id": "openmanus_official",
        },
    )

    assert commands[1] == ["docker", "rm", "-f", commands[0][commands[0].index("--name") + 1]]
    assert payload["blocked"] is False
    assert payload["risk_level"] == "high"
    assert [event["decision"] for event in payload["audit_events"]] == ["deny", "error"]
    assert payload["audit_events"][-1]["event_type"] == "runtime_error"


def test_process_output_text_decodes_timeout_bytes() -> None:
    assert _process_output_text(None) == ""
    assert _process_output_text("plain") == "plain"
    assert _process_output_text(b"ok\n") == "ok\n"
    assert "\ufffd" in _process_output_text(b"\xff")


def test_llm_metrics_record_completed_and_inflight_calls() -> None:
    metrics = _llm_metrics(
        [
            {"type": "llm_call_started", "call_index": 1},
            {
                "type": "llm_call_completed",
                "call_index": 1,
                "latency_ms": 1250.5,
                "input_tokens": 100,
                "output_tokens": 20,
            },
            {"type": "llm_call_started", "call_index": 2},
        ]
    )

    assert metrics == {
        "llm_call_started_count": 2,
        "llm_call_completed_count": 1,
        "llm_call_failed_count": 0,
        "llm_call_inflight_count": 1,
        "llm_latency_ms": [1250.5],
        "llm_latency_total_ms": 1250.5,
        "llm_latency_max_ms": 1250.5,
        "llm_input_tokens": 100,
        "llm_output_tokens": 20,
    }
