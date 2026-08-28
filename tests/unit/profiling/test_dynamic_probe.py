from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from redsentinel.application import (
    DynamicProbeError,
    DynamicProbeEvent,
    DynamicProbeLimits,
    DynamicProbeRisk,
    DynamicProfileProbe,
    align_dynamic_events,
    read_dynamic_probe_events,
)
from redsentinel.application import ImageAgentProfile
from redsentinel.runtime.engine.sandbox.docker.capture import BoundedCaptureResult


IMAGE_DIGEST = f"sha256:{'a' * 64}"
CONTENT_SHA256 = "b" * 64
COMPLETED_AT = "2026-08-24T00:00:00Z"
EVENT_PREFIX = "REDSENTINEL_DYNAMIC_EVENT:"


def _evidence(evidence_id: str = "ev:static") -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "artifact_digest": IMAGE_DIGEST,
        "locator": {"image_path": "/app/agent.py", "line_start": 1, "line_end": 20},
        "extractor": "python_ast",
        "method": "static",
        "content_sha256": CONTENT_SHA256,
        "summary": "Static fixture evidence.",
    }


def _claim() -> dict[str, object]:
    return {
        "evidence_refs": ["ev:static"],
        "confidence": 0.82,
        "verification_status": "supported",
    }


def _profile(*, os_name: str = "linux", architecture: str = "arm64") -> ImageAgentProfile:
    stages = []
    for stage in (
        "inventory",
        "unpack",
        "static_extract",
        "framework_detect",
        "graph_reconstruct",
        "semantic_enrich",
        "dynamic_verify",
        "finalize",
    ):
        status = "skipped" if stage == "dynamic_verify" else "completed"
        stages.append({"stage": stage, "status": status, "completed_at": COMPLETED_AT})
    claim = _claim()
    return ImageAgentProfile.model_validate(
        {
            "profile_id": "profile:dynamic-test",
            "tenant_id": "tenant",
            "agent_id": "agent",
            "generated_at": COMPLETED_AT,
            "image": {
                "digest": IMAGE_DIGEST,
                "os": os_name,
                "architecture": architecture,
                "entrypoint": ["python", "-m", "demo_agent"],
                "working_directory": "/app",
                **claim,
            },
            "analysis": {
                "analysis_id": "analysis:dynamic-test",
                "agent_id": "agent",
                "image_digest": IMAGE_DIGEST,
                "status": "completed",
                "stages": stages,
            },
            "nodes": [
                {
                    "node_id": "node:agent",
                    "node_type": "agent",
                    "name": "Demo Agent",
                    **claim,
                },
                {
                    "node_id": "node:router",
                    "node_type": "router",
                    "name": "Main Router",
                    **claim,
                },
                {
                    "node_id": "node:tool",
                    "node_type": "tool",
                    "name": "send_email",
                    **claim,
                },
                {
                    "node_id": "node:guard",
                    "node_type": "guard",
                    "name": "Input Guard",
                    "control_ids": ["control:guard"],
                    **claim,
                },
            ],
            "edges": [
                {
                    "edge_id": "edge:agent-tool",
                    "edge_type": "calls",
                    "source_node_id": "node:agent",
                    "target_node_id": "node:tool",
                    **claim,
                },
                {
                    "edge_id": "edge:route-tool",
                    "edge_type": "routes_to",
                    "source_node_id": "node:router",
                    "target_node_id": "node:tool",
                    **claim,
                },
            ],
            "controls": [
                {
                    "control_id": "control:guard",
                    "control_type": "input_guard",
                    "name": "Input Guard",
                    "node_ids": ["node:guard"],
                    "description": "Validates synthetic probe input.",
                    **claim,
                }
            ],
            "evidence": [_evidence()],
        }
    )


def _event(
    event_id: str,
    event_type: str,
    name: str,
    **updates: object,
) -> DynamicProbeEvent:
    payload: dict[str, object] = {
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": COMPLETED_AT,
        "name": name,
        "trust_level": "observed",
    }
    payload.update(updates)
    return DynamicProbeEvent.model_validate(payload)


def _write_protocol_events(path: Path, events: list[DynamicProbeEvent]) -> None:
    path.write_text(
        "".join(EVENT_PREFIX + json.dumps(event.model_dump(mode="json")) + "\n" for event in events),
        encoding="utf-8",
    )


def _write_success_events(path: Path) -> None:
    events = [
        _event("event:startup", "startup", "dynamic-profile-probe"),
        _event("event:import", "import_succeeded", "demo_agent"),
        _event(
            "event:coverage",
            "coverage_target",
            "Demo Agent",
            node_type="agent",
            details={"required": True},
        ),
        _event("event:start", "invocation_started", "normal-smoke"),
        _event(
            "event:agent-invoked",
            "agent_invoked",
            "Demo Agent",
            node_type="agent",
            static_node_id="node:agent",
            details={"executed": True},
        ),
        _event(
            "event:tool",
            "tool_called",
            "send_email",
            node_type="tool",
            static_node_id="node:tool",
            source_node_id="node:agent",
            target_node_id="node:tool",
            details={"executed": True},
        ),
        _event("event:output", "output_observed", "normal-smoke"),
        _event(
            "event:complete",
            "invocation_completed",
            "normal-smoke",
            details={"success": True},
        ),
    ]
    _write_protocol_events(path, events)


def _capture_result(
    command: list[str],
    stdout_path: Path,
    stderr_path: Path,
    *,
    returncode: int = 0,
    timed_out: bool = False,
    error: str | None = None,
) -> BoundedCaptureResult:
    if not stdout_path.exists():
        stdout_path.write_text("", encoding="utf-8")
    if not stderr_path.exists():
        stderr_path.write_text("", encoding="utf-8")
    return BoundedCaptureResult(
        args=command,
        returncode=returncode,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timed_out=timed_out,
        error=error,
    )


def test_probe_builds_strongly_isolated_docker_command_with_fake_subprocess(tmp_path: Path) -> None:
    captured: list[str] = []

    def fake_capture(command: list[str], **kwargs: object) -> BoundedCaptureResult:
        captured.extend(command)
        stdout_path = Path(str(kwargs["stdout_path"]))
        stderr_path = Path(str(kwargs["stderr_path"]))
        _write_success_events(stdout_path)
        return _capture_result(command, stdout_path, stderr_path)

    result = DynamicProfileProbe(tmp_path, capture_runner=fake_capture).run(
        _profile(),
        image_ref="local/agent:test",
    )

    assert result.succeeded
    assert result.profile.analysis.status == "completed"
    assert ["--network", "none"] == captured[captured.index("--network") : captured.index("--network") + 2]
    assert "--read-only" in captured
    assert ["--cap-drop", "ALL"] == captured[captured.index("--cap-drop") : captured.index("--cap-drop") + 2]
    assert ["--security-opt", "no-new-privileges:true"] == captured[
        captured.index("--security-opt") : captured.index("--security-opt") + 2
    ]
    for option in ("--pids-limit", "--memory", "--cpus", "--tmpfs"):
        assert option in captured
    mounts = [captured[index + 1] for index, value in enumerate(captured) if value == "--mount"]
    assert len(mounts) == 1
    assert "src=" in mounts[0]
    assert "dst=/redsentinel-probe.py" in mounts[0]
    assert mounts[0].endswith(",readonly")
    assert "/events.jsonl" not in " ".join(captured)
    assert "/artifacts" not in " ".join(captured)
    joined = " ".join(captured).lower()
    assert "docker.sock" not in joined
    assert "api_key" not in joined
    assert "password" not in joined
    assert "token" not in joined
    assert result.profile.nodes[2].verification_status == "supported"
    assert all(
        event.trust_level == "attested"
        for event in result.events
    )


@pytest.mark.parametrize(
    "structure_events",
    [
        [],
        [
            _event(
                "event:unresolved-route",
                "route",
                "missing-route",
                source_node_id="missing-source",
                target_node_id="missing-target",
            )
        ],
    ],
)
def test_probe_requires_the_behavior_protocol(
    tmp_path: Path,
    structure_events: list[DynamicProbeEvent],
) -> None:
    def fake_capture(command: list[str], **kwargs: object) -> BoundedCaptureResult:
        stdout_path = Path(str(kwargs["stdout_path"]))
        stderr_path = Path(str(kwargs["stderr_path"]))
        events = [
            _event("event:startup", "startup", "dynamic-profile-probe"),
            _event("event:import", "import_succeeded", "demo_agent"),
            *structure_events,
        ]
        _write_protocol_events(stdout_path, events)
        return _capture_result(command, stdout_path, stderr_path)

    result = DynamicProfileProbe(tmp_path, capture_runner=fake_capture).run(
        _profile(),
        image_ref="local/agent:test",
    )

    assert not result.succeeded
    assert result.profile.analysis.status == "partial"
    assert result.profile.analysis.errors[-1].code == "incomplete_probe_output"
    assert "required behavioral events" in (result.error or "")


@pytest.mark.parametrize(
    ("profile", "risk", "phase_code"),
    [
        (_profile(os_name="windows"), DynamicProbeRisk(), "unsupported_platform"),
        (_profile(), DynamicProbeRisk(phase="finalize"), "invalid_probe_phase"),
        (_profile(), DynamicProbeRisk(requires_privileged=True), "privileged_runtime_required"),
        (_profile(), DynamicProbeRisk(required_host_mounts=("/var/run/docker.sock",)), "dangerous_mount_required"),
    ],
)
def test_risk_gate_refuses_unsafe_probe_without_starting_subprocess(
    tmp_path: Path,
    profile: ImageAgentProfile,
    risk: DynamicProbeRisk,
    phase_code: str,
) -> None:
    called = False

    def forbidden_capture(*args: object, **kwargs: object) -> BoundedCaptureResult:
        nonlocal called
        called = True
        raise AssertionError("risk gate must run before subprocess")

    result = DynamicProfileProbe(tmp_path, capture_runner=forbidden_capture).run(
        profile,
        image_ref="local/agent:test",
        risk=risk,
    )

    assert not called
    assert result.profile.analysis.status == "partial"
    assert result.profile.analysis.stages[6].status == "failed"
    assert result.profile.analysis.errors[-1].code == phase_code
    assert [node.node_id for node in result.profile.nodes] == [node.node_id for node in profile.nodes]


def test_probe_uses_configured_docker_binary_for_run_and_timeout_cleanup(tmp_path: Path) -> None:
    cleanup_commands: list[list[str]] = []
    docker_binary = "/opt/docker/bin/docker"

    def fake_capture(command: list[str], **kwargs: object) -> BoundedCaptureResult:
        return _capture_result(
            command,
            Path(str(kwargs["stdout_path"])),
            Path(str(kwargs["stderr_path"])),
            returncode=-9,
            timed_out=True,
            error="process timed out after 1 seconds",
        )

    def fake_subprocess(command: list[str], **kwargs: object) -> object:
        cleanup_commands.append(command)
        return object()

    result = DynamicProfileProbe(
        tmp_path,
        docker_binary=docker_binary,
        limits=DynamicProbeLimits(timeout_seconds=1),
        capture_runner=fake_capture,
        cleanup_runner=fake_subprocess,
    ).run(_profile(), image_ref="local/agent:test")

    assert result.timed_out
    assert result.profile.analysis.status == "partial"
    assert result.profile.analysis.errors[-1].code == "dynamic_probe_timeout"
    assert result.command[:2] == (docker_binary, "run")
    assert cleanup_commands == [[docker_binary, "rm", "-f", result.command[result.command.index("--name") + 1]]]


def test_probe_nonzero_exit_returns_partial_profile_even_with_partial_events(tmp_path: Path) -> None:
    def fake_capture(command: list[str], **kwargs: object) -> BoundedCaptureResult:
        stdout_path = Path(str(kwargs["stdout_path"]))
        stderr_path = Path(str(kwargs["stderr_path"]))
        event = _event(
            "event:failure",
            "import_failed",
            "demo_agent",
            details={"error_type": "ModuleNotFoundError", "error": "missing dependency"},
        )
        result = _capture_result(command, stdout_path, stderr_path, returncode=2)
        _write_protocol_events(stdout_path, [event])
        return result

    original = _profile()
    result = DynamicProfileProbe(tmp_path, capture_runner=fake_capture).run(
        original,
        image_ref="local/agent:test",
    )

    assert not result.succeeded
    assert result.profile.analysis.status == "partial"
    assert result.profile.analysis.errors[-1].code == "dynamic_probe_failed"
    assert result.profile.nodes == original.nodes
    assert any(item.code == "dynamic_probe_failed" for item in result.profile.limitations)


def test_probe_start_exception_returns_partial_static_profile(tmp_path: Path) -> None:
    def failing_capture(*args: object, **kwargs: object) -> BoundedCaptureResult:
        raise OSError("docker unavailable")

    original = _profile()
    result = DynamicProfileProbe(tmp_path, capture_runner=failing_capture).run(
        original,
        image_ref="local/agent:test",
    )

    assert result.profile.analysis.status == "partial"
    assert result.profile.analysis.errors[-1].code == "dynamic_probe_start_failed"
    assert result.profile.nodes == original.nodes


def test_probe_redacts_errors_and_captured_logs(tmp_path: Path) -> None:
    secret = "task14-probe-secret"

    def leaking_capture(command: list[str], **kwargs: object) -> BoundedCaptureResult:
        stdout_path = Path(str(kwargs["stdout_path"]))
        stderr_path = Path(str(kwargs["stderr_path"]))
        result = _capture_result(
            command,
            stdout_path,
            stderr_path,
            returncode=None,
            error=f"RuntimeError: credential={secret}",
        )
        event = _event(
            "event:secret-error",
            "import_failed",
            "demo_agent",
            details={"error": f"token: {secret}"},
        )
        stdout_path.write_text(
            f"password={secret}\n{EVENT_PREFIX}{json.dumps(event.model_dump(mode='json'))}\n",
            encoding="utf-8",
        )
        stderr_path.write_text(
            f"Authorization: Bearer {secret}\napi_key='{secret}'\n",
            encoding="utf-8",
        )
        return result

    result = DynamicProfileProbe(tmp_path, capture_runner=leaking_capture).run(
        _profile(),
        image_ref="local/agent:test",
    )
    run_dir = next(tmp_path.glob("dynamic-probe-*"))
    visible = json.dumps(result.profile.model_dump(mode="json")) + (result.error or "")

    assert secret not in visible
    assert "RuntimeError" in visible
    assert "[REDACTED]" in visible
    for name in ("stdout.log", "stderr.log", "events.jsonl"):
        content = (run_dir / name).read_text(encoding="utf-8")
        assert secret not in content
        assert "[REDACTED]" in content


def test_aligns_static_nodes_edges_and_controls_while_retaining_dynamic_limitations() -> None:
    events = [
        _event(
            "event:tool",
            "tool_registered",
            "send_email",
            node_type="tool",
            static_node_id="node:tool",
        ),
        _event(
            "event:guard",
            "guard_registered",
            "Input Guard",
            node_type="guard",
            static_node_id="node:guard",
        ),
        _event(
            "event:route",
            "route",
            "safe-route",
            source_node_id="node:router",
            target_node_id="node:tool",
        ),
        _event(
            "event:plan",
            "call_plan",
            "send_email",
            source_node_id="node:agent",
            target_node_id="node:tool",
            details={"executed": False},
        ),
        _event("event:mcp", "mcp_registered", "Runtime MCP", node_type="mcp"),
        _event(
            "event:conflict",
            "agent_registered",
            "send_email",
            node_type="agent",
            static_node_id="node:tool",
        ),
    ]

    profile = align_dynamic_events(_profile(), events)
    nodes = {node.node_id: node for node in profile.nodes}
    edges = {edge.edge_id: edge for edge in profile.edges}

    assert nodes["node:tool"].verification_status == "verified"
    assert nodes["node:guard"].verification_status == "verified"
    assert edges["edge:route-tool"].verification_status == "verified"
    assert edges["edge:agent-tool"].verification_status == "verified"
    dynamic_mcp = next(node for node in profile.nodes if node.name == "Runtime MCP")
    assert dynamic_mcp.verification_status == "supported"
    assert profile.controls[0].verification_status == "verified"
    assert {item.code for item in profile.limitations} >= {
        "dynamic_only_node",
        "dynamic_static_conflict",
    }


def test_registration_matches_one_prefixed_static_node_without_creating_a_duplicate() -> None:
    payload = _profile().model_dump(mode="json")
    payload["nodes"][0]["name"] = "call invoke_ecommerce_agent"
    profile = align_dynamic_events(
        ImageAgentProfile.model_validate(payload),
        [
            _event(
                "event:ecommerce-agent",
                "agent_registered",
                "invoke_ecommerce_agent",
                node_type="agent",
                details={"symbol": "invoke_ecommerce_agent"},
            )
        ],
    )

    matches = [node for node in profile.nodes if "invoke_ecommerce_agent" in node.name]
    assert len(matches) == 1
    assert matches[0].node_id == "node:agent"
    assert matches[0].verification_status == "verified"
    assert matches[0].evidence_refs == [
        "ev:static",
        "dynamic:event:ecommerce-agent",
    ]
    assert not any(item.code == "dynamic_only_node" for item in profile.limitations)


def test_attested_event_does_not_upgrade_static_claim_to_verified() -> None:
    profile = align_dynamic_events(
        _profile(),
        [
            _event(
                "event:attested-agent",
                "agent_invoked",
                "Demo Agent",
                node_type="agent",
                static_node_id="node:agent",
                details={"executed": True},
                trust_level="attested",
            )
        ],
    )

    node = next(item for item in profile.nodes if item.node_id == "node:agent")
    evidence = next(item for item in profile.evidence if item.evidence_id == "dynamic:event:attested-agent")
    assert node.verification_status == "supported"
    assert evidence.trust_level == "attested"


def test_observed_guard_decision_corroborates_matching_control() -> None:
    profile = align_dynamic_events(
        _profile(),
        [
            _event(
                "event:observed-guard",
                "guard_decision",
                "Input Guard",
                node_type="guard",
                static_node_id="node:guard",
                details={"executed": True, "decision": "deny"},
            )
        ],
    )

    control = next(item for item in profile.controls if item.control_id == "control:guard")
    assert control.verification_status == "verified"
    assert control.evidence_refs == ["ev:static", "dynamic:event:observed-guard"]


def test_executed_tool_matches_static_tool_sink_alias() -> None:
    payload = _profile().model_dump(mode="json")
    payload["nodes"][2]["name"] = "tool sink demo.send_email"
    profile = align_dynamic_events(
        ImageAgentProfile.model_validate(payload),
        [
            _event(
                "event:executed-tool",
                "tool_called",
                "send_email",
                node_type="tool",
                source_node_id="node:agent",
                target_node_id="send_email",
                details={"executed": True},
            )
        ],
    )

    tool = next(node for node in profile.nodes if node.node_id == "node:tool")
    assert tool.verification_status == "verified"


def test_registration_does_not_guess_between_multiple_prefixed_static_nodes() -> None:
    payload = _profile().model_dump(mode="json")
    payload["nodes"][0]["name"] = "call invoke_ecommerce_agent"
    payload["nodes"].append(
        {
            "node_id": "node:agent-duplicate",
            "node_type": "agent",
            "name": "call invoke ecommerce agent",
            **_claim(),
        }
    )
    profile = align_dynamic_events(
        ImageAgentProfile.model_validate(payload),
        [
            _event(
                "event:ambiguous-agent",
                "agent_registered",
                "invoke_ecommerce_agent",
                node_type="agent",
            )
        ],
    )

    static_nodes = [node for node in profile.nodes if node.node_id in {"node:agent", "node:agent-duplicate"}]
    assert all(node.verification_status == "supported" for node in static_nodes)
    dynamic_node = next(node for node in profile.nodes if node.name == "invoke_ecommerce_agent")
    assert dynamic_node.node_id.startswith("node:dynamic:agent:")
    assert any(item.code == "dynamic_only_node" for item in profile.limitations)


def test_route_uses_static_connection_to_disambiguate_same_named_targets() -> None:
    payload = _profile().model_dump(mode="json")
    payload["nodes"].append(
        {
            "node_id": "node:tool-duplicate",
            "node_type": "tool",
            "name": "send email",
            **_claim(),
        }
    )
    profile = align_dynamic_events(
        ImageAgentProfile.model_validate(payload),
        [
            _event(
                "event:connected-route",
                "route",
                "safe-route",
                source_node_id="node:router",
                target_node_id="send_email",
            )
        ],
    )

    assert not any(item.code == "dynamic_edge_unresolved" for item in profile.limitations)
    assert any(edge.source_node_id == "node:router" and edge.target_node_id == "node:tool" for edge in profile.edges)


def test_dynamic_events_do_not_corroborate_ambiguous_static_edges_or_controls() -> None:
    payload = _profile().model_dump(mode="json")
    payload["edges"].append(
        {
            **payload["edges"][1],
            "edge_id": "edge:route-tool:duplicate",
        }
    )
    payload["controls"].append(
        {
            **payload["controls"][0],
            "control_id": "control:guard:duplicate",
        }
    )
    payload["nodes"][3]["control_ids"].append("control:guard:duplicate")
    profile = align_dynamic_events(
        ImageAgentProfile.model_validate(payload),
        [
            _event(
                "event:ambiguous-route",
                "route",
                "safe-route",
                source_node_id="node:router",
                target_node_id="node:tool",
            ),
            _event(
                "event:ambiguous-guard",
                "guard_registered",
                "Input Guard",
                node_type="guard",
                static_node_id="node:guard",
            ),
        ],
    )

    assert all(edge.verification_status == "supported" for edge in profile.edges if edge.edge_type == "routes_to")
    assert all(control.verification_status == "supported" for control in profile.controls)
    assert {item.code for item in profile.limitations} >= {
        "dynamic_edge_ambiguous",
        "dynamic_control_ambiguous",
    }


def test_dynamic_only_structure_does_not_invent_capabilities_permissions_or_risks() -> None:
    events = [
        _event("event:tool", "tool_registered", "runtime_tool", node_type="tool"),
        _event(
            "event:plan",
            "call_plan",
            "runtime_tool",
            source_node_id="node:agent",
            target_node_id="runtime_tool",
            details={"executed": False},
        ),
    ]

    profile = align_dynamic_events(_profile(), events)
    dynamic_node = next(node for node in profile.nodes if node.name == "runtime_tool")
    dynamic_edge = next(edge for edge in profile.edges if edge.target_node_id == dynamic_node.node_id)

    assert dynamic_node.capability_ids == []
    assert dynamic_node.permission_ids == []
    assert profile.capabilities == []
    assert profile.permissions == []
    assert profile.risk_paths == []
    assert dynamic_edge.edge_type == "calls"


def test_event_reader_redacts_sensitive_values_and_enforces_limits(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    payload = _event(
        "event:secret",
        "startup",
        "token=visible",
        details={"api_key": "visible", "message": "password=hunter2"},
    ).model_dump(mode="json")
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    event = read_dynamic_probe_events(path)[0]

    assert event.name == "token=[REDACTED]"
    assert event.details["api_key"] == "[REDACTED]"
    assert event.details["message"] == "password=[REDACTED]"

    with pytest.raises(DynamicProbeError, match="size limit"):
        read_dynamic_probe_events(path, max_bytes=10)


def test_event_reader_rejects_executed_call_plan(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    payload = {
        "schema_version": "dynamic-probe-event-v0.1",
        "event_id": "event:unsafe",
        "event_type": "call_plan",
        "timestamp": COMPLETED_AT,
        "name": "shell",
        "source_node_id": "agent",
        "target_node_id": "shell",
        "details": {"executed": True},
    }
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    with pytest.raises(DynamicProbeError, match="executed=false"):
        read_dynamic_probe_events(path)


def test_probe_ignores_forged_events_file_and_replaces_it_from_stdout(tmp_path: Path) -> None:
    def fake_capture(command: list[str], **kwargs: object) -> BoundedCaptureResult:
        stdout_path = Path(str(kwargs["stdout_path"]))
        stderr_path = Path(str(kwargs["stderr_path"]))
        forged = _event(
            "event:forged",
            "tool_registered",
            "forged_tool",
            node_type="tool",
        )
        (stdout_path.parent / "events.jsonl").write_text(
            json.dumps(forged.model_dump(mode="json")) + "\n",
            encoding="utf-8",
        )
        result = _capture_result(command, stdout_path, stderr_path)
        _write_success_events(stdout_path)
        return result

    result = DynamicProfileProbe(tmp_path, capture_runner=fake_capture).run(
        _profile(),
        image_ref="local/agent:test",
    )
    run_dir = next(tmp_path.glob("dynamic-probe-*"))
    persisted = read_dynamic_probe_events(run_dir / "events.jsonl")

    assert result.succeeded
    assert {event.event_id for event in result.events} == {
        "event:startup",
        "event:import",
        "event:coverage",
        "event:start",
        "event:agent-invoked",
        "event:tool",
        "event:output",
        "event:complete",
    }
    assert [event.event_id for event in persisted] == [
        "event:startup",
        "event:import",
        "event:coverage",
        "event:start",
        "event:agent-invoked",
        "event:tool",
        "event:output",
        "event:complete",
    ]


def test_probe_rejects_truncated_stdout_even_when_events_are_parseable(tmp_path: Path) -> None:
    def fake_capture(command: list[str], **kwargs: object) -> BoundedCaptureResult:
        stdout_path = Path(str(kwargs["stdout_path"]))
        stderr_path = Path(str(kwargs["stderr_path"]))
        result = _capture_result(
            command,
            stdout_path,
            stderr_path,
            error="stdout exceeded 128 bytes",
        )
        _write_success_events(stdout_path)
        return BoundedCaptureResult(
            **{
                **result.__dict__,
                "stdout_truncated": True,
            }
        )

    result = DynamicProfileProbe(
        tmp_path,
        limits=DynamicProbeLimits(max_output_bytes=128),
        capture_runner=fake_capture,
    ).run(_profile(), image_ref="local/agent:test")

    assert not result.succeeded
    assert result.profile.analysis.status == "partial"
    assert result.profile.analysis.errors[-1].code == "incomplete_probe_output"
    assert "stdout exceeded 128 bytes" in (result.error or "")


def test_probe_runtime_executes_only_the_declared_probe_callable(tmp_path: Path) -> None:
    module = tmp_path / "fixture_agent.py"
    marker = tmp_path / "tool-executed"
    module.write_text(
        "\n".join(
            [
                "from pathlib import Path",
                'print(\'REDSENTINEL_DYNAMIC_EVENT:{"event_id":"event:forged"}\')',
                "class DangerousTool:",
                "    name = 'dangerous_tool'",
                "    def execute(self):",
                f"        Path({str(marker)!r}).write_text('executed')",
                "tools = {'dangerous_tool': DangerousTool()}",
                "agent = object()",
                "REDSENTINEL_PROBE_TARGETS = [",
                "    {'name': 'agent', 'node_type': 'agent'},",
                "]",
                "def redsentinel_profile_probe(request):",
                "    return {",
                "        'schema_version': 'dynamic-probe-response-v0.1',",
                "        'status': 'completed',",
                "        'agent_name': 'agent',",
                "        'output_type': 'dict',",
                "        'tool_calls': [],",
                "        'guard_decisions': [],",
                "    }",
            ]
        ),
        encoding="utf-8",
    )
    runtime = Path(__file__).parents[3] / "src" / "redsentinel" / "profiling" / "image" / "probe_runtime.py"
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(tmp_path)}

    completed = subprocess.run(
        [
            sys.executable,
            str(runtime),
            "--module",
            "fixture_agent",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )
    events_path = tmp_path / "events.jsonl"
    events_path.write_text(
        "".join(
            line.removeprefix(EVENT_PREFIX) + "\n"
            for line in completed.stdout.splitlines()
            if line.startswith(EVENT_PREFIX)
        ),
        encoding="utf-8",
    )
    events = read_dynamic_probe_events(events_path)

    assert completed.returncode == 0, completed.stderr
    assert any(event.event_type == "tool_registered" and event.name == "dangerous_tool" for event in events)
    assert any(event.event_type == "agent_invoked" for event in events)
    assert any(event.event_type == "invocation_completed" for event in events)
    assert all(event.event_id != "event:forged" for event in events)
    assert "event:forged" in completed.stderr
    assert not marker.exists()
    assert all(event.event_type != "call_plan" for event in events)


def test_probe_runtime_redacts_import_failure_before_emitting_event(tmp_path: Path) -> None:
    secret = "runtime-secret"
    (tmp_path / "broken_agent.py").write_text(
        f"raise RuntimeError('token={secret}')\n",
        encoding="utf-8",
    )
    runtime = Path(__file__).parents[3] / "src" / "redsentinel" / "profiling" / "image" / "probe_runtime.py"

    completed = subprocess.run(
        [sys.executable, str(runtime), "--module", "broken_agent"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(tmp_path)},
    )

    assert completed.returncode == 2
    assert secret not in completed.stdout
    assert "token=[REDACTED]" in completed.stdout


@pytest.mark.docker
def test_real_docker_dynamic_probe_is_opt_in(tmp_path: Path) -> None:
    image = os.environ.get("REDSENTINEL_DYNAMIC_PROBE_IMAGE")
    module = os.environ.get("REDSENTINEL_DYNAMIC_PROBE_MODULE")
    if not image or not module:
        pytest.skip("set REDSENTINEL_DYNAMIC_PROBE_IMAGE and REDSENTINEL_DYNAMIC_PROBE_MODULE")

    result = DynamicProfileProbe(tmp_path).run(_profile(), image_ref=image, target_module=module)

    assert result.succeeded, result.error
    assert {event.event_type for event in result.events} >= {"startup", "import_succeeded"}
