from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from redsentinel.application import (
    AgentDirectoryDescriptor,
    AttackProfile,
    ImageAgentProfile,
    ImageAnalysisStatus,
)
from redsentinel.application.attack_profile import build_attack_profile, image_profile_sha256
from redsentinel.application.contracts import AgentProfile, AgentProfileNode
from redsentinel.application.image_profile_contracts import (
    dynamic_required_claim_ids,
    profile_configuration_digest,
)
from redsentinel.attacks.engine.profile_driven import (
    build_attack_profile_driven_attack_plan,
)
from scripts.verify_task13_e2e import _verify_profile_bundle

IMAGE_DIGEST = f"sha256:{'a' * 64}"
CONFIGURATION_DIGEST = f"sha256:{'e' * 64}"
PROFILE_SHA256 = "b" * 64
CONTENT_SHA256 = "c" * 64
COMPLETED_AT = "2026-08-21T10:00:00Z"


def test_profile_configuration_digest_is_stable_and_tracks_profile_inputs() -> None:
    first = AgentDirectoryDescriptor.model_validate(
        {
            "agent_id": "agent_demo",
            "name": "Demo",
            "image": {"type": "docker_archive", "path": "image.tar"},
            "platform": "linux/arm64",
            "runtime": {
                "probe_module": "app.agent",
                "requires_privileged": False,
                "required_host_mounts": ["/cache", "/data"],
            },
            "expected_frameworks": ["langgraph", "langchain"],
        }
    )
    reordered = first.model_copy(
        update={
            "runtime": first.runtime.model_copy(update={"required_host_mounts": ["/data", "/cache"]}),
            "expected_frameworks": ["langchain", "langgraph"],
        }
    )
    assert profile_configuration_digest(first) == profile_configuration_digest(reordered)
    original_digest = profile_configuration_digest(first)
    changes = [
        first.model_copy(update={"platform": "linux/amd64"}),
        first.model_copy(update={"runtime": first.runtime.model_copy(update={"probe_module": "app.corrected_agent"})}),
        first.model_copy(update={"runtime": first.runtime.model_copy(update={"requires_privileged": True})}),
        first.model_copy(update={"runtime": first.runtime.model_copy(update={"required_host_mounts": ["/cache"]})}),
        first.model_copy(update={"expected_frameworks": ["langgraph"]}),
    ]
    assert all(profile_configuration_digest(changed) != original_digest for changed in changes)


def _analysis() -> dict:
    return {
        "analysis_id": "analysis:001",
        "agent_id": "agent_demo",
        "image_digest": IMAGE_DIGEST,
        "configuration_digest": CONFIGURATION_DIGEST,
        "status": "completed",
        "stages": [
            {"stage": stage, "status": "completed", "completed_at": COMPLETED_AT}
            for stage in (
                "inventory",
                "unpack",
                "static_extract",
                "framework_detect",
                "graph_reconstruct",
                "semantic_enrich",
                "dynamic_verify",
                "finalize",
            )
        ],
    }


def _evidence(
    evidence_id: str,
    *,
    method: str = "static",
    extractor: str = "python_ast",
    event: bool = False,
    summary: str | None = None,
    trust_level: str | None = None,
) -> dict:
    locator = (
        {"event_id": f"event:{evidence_id}"}
        if event
        else {
            "image_path": "/app/agent.py",
            "python_module": "agent",
            "symbol": "run",
            "line_start": 10,
            "line_end": 20,
        }
    )
    return {
        "evidence_id": evidence_id,
        "artifact_digest": IMAGE_DIGEST,
        "locator": locator,
        "extractor": extractor,
        "method": method,
        "trust_level": trust_level or ("observed" if method == "dynamic" else "static"),
        "content_sha256": CONTENT_SHA256,
        "summary": summary or f"Evidence for {evidence_id}",
    }


def _claim(*refs: str, status: str = "supported", confidence: float = 0.9) -> dict:
    return {
        "evidence_refs": list(refs),
        "confidence": confidence,
        "verification_status": status,
    }


def _completeness(*, conclusion: str = "complete") -> dict:
    return {
        "static_source_recovery": "complete",
        "framework_coverage": {"covered": 1, "total": 1, "ratio": 1.0},
        "graph_evidence_coverage": {"covered": 4, "total": 4, "ratio": 1.0},
        "dynamic_corroboration_coverage": {"covered": 1, "total": 1, "ratio": 1.0},
        "dynamic_behavior_coverage": {"covered": 1, "total": 1, "ratio": 1.0},
        "unresolved_limitations": 0,
        "blocking_limitations": [],
        "conclusion": conclusion,
    }


def _profile_payload() -> dict:
    static_claim = _claim("ev:static")
    verified_claim = _claim("ev:static", "ev:dynamic", status="verified", confidence=0.98)
    return {
        "schema_version": "agent-profile-v0.2",
        "profile_id": "profile:001",
        "tenant_id": "tenant_001",
        "agent_id": "agent_demo",
        "generated_at": COMPLETED_AT,
        "image": {
            "digest": IMAGE_DIGEST,
            "os": "linux",
            "architecture": "arm64",
            "entrypoint": ["python", "-m", "agent"],
            "working_directory": "/app",
            "environment_variables": ["MODEL_NAME", "API_KEY"],
            "layer_digests": [f"sha256:{'d' * 64}"],
            **verified_claim,
        },
        "analysis": _analysis(),
        "frameworks": [
            {
                "framework_id": "framework:custom",
                "name": "custom",
                **static_claim,
            }
        ],
        "nodes": [
            {
                "node_id": "node:input",
                "node_type": "external_input",
                "name": "User input",
                "framework_ids": ["framework:custom"],
                **static_claim,
            },
            {
                "node_id": "node:shell",
                "node_type": "shell",
                "name": "Command executor",
                "framework_ids": ["framework:custom"],
                "capability_ids": ["capability:shell"],
                "permission_ids": ["permission:shell"],
                "control_ids": ["control:allowlist"],
                "risk_level": "critical",
                **verified_claim,
            },
        ],
        "edges": [
            {
                "edge_id": "edge:input-shell",
                "edge_type": "calls",
                "source_node_id": "node:input",
                "target_node_id": "node:shell",
                **static_claim,
            }
        ],
        "capabilities": [
            {
                "capability_id": "capability:shell",
                "name": "Shell execution",
                "operation": "execute",
                "node_ids": ["node:shell"],
                "risk_level": "critical",
                **verified_claim,
            }
        ],
        "permissions": [
            {
                "permission_id": "permission:shell",
                "permission_type": "shell",
                "operations": ["execute"],
                "scope": "container",
                "node_ids": ["node:shell"],
                "capability_ids": ["capability:shell"],
                "risk_level": "critical",
                **static_claim,
            }
        ],
        "controls": [
            {
                "control_id": "control:allowlist",
                "control_type": "allowlist",
                "name": "Command allowlist",
                "node_ids": ["node:shell"],
                "description": "Limits executable commands.",
                **_claim("ev:static", "ev:guard-decision", status="verified", confidence=0.98),
            }
        ],
        "evidence": [
            _evidence("ev:static"),
            _evidence(
                "ev:dynamic",
                method="dynamic",
                extractor="runtime_probe",
                event=True,
                summary="agent_invoked: Command executor",
            ),
            _evidence(
                "ev:invocation-started",
                method="dynamic",
                extractor="runtime_probe",
                event=True,
                summary="invocation_started: normal-smoke",
            ),
            _evidence(
                "ev:coverage-target",
                method="dynamic",
                extractor="runtime_probe",
                event=True,
                summary="coverage_target: Command allowlist",
            ),
            _evidence(
                "ev:agent-invoked",
                method="dynamic",
                extractor="runtime_probe",
                event=True,
                summary="agent_invoked: Command executor",
            ),
            _evidence(
                "ev:guard-decision",
                method="dynamic",
                extractor="runtime_probe",
                event=True,
                summary="guard_decision: Command allowlist",
            ),
            _evidence(
                "ev:output-observed",
                method="dynamic",
                extractor="runtime_probe",
                event=True,
                summary="output_observed: normal-smoke",
            ),
            _evidence(
                "ev:invocation-completed",
                method="dynamic",
                extractor="runtime_probe",
                event=True,
                summary="invocation_completed: normal-smoke",
            ),
        ],
        "risk_paths": [
            {
                "path_id": "path:input-shell",
                "source_node_id": "node:input",
                "sink_node_id": "node:shell",
                "node_ids": ["node:input", "node:shell"],
                "edge_ids": ["edge:input-shell"],
                "capability_ids": ["capability:shell"],
                "permission_ids": ["permission:shell"],
                "control_ids": ["control:allowlist"],
                "applicable_threats": ["prompt_injection", "command_injection"],
                "control_gaps": ["allowlist coverage is incomplete"],
                "risk_level": "critical",
                **verified_claim,
            }
        ],
        "limitations": [
            {
                "code": "encrypted_content",
                "message": "One encrypted resource was not inspected.",
                "evidence_refs": ["ev:static"],
            }
        ],
    }


def _attack_payload(profile: ImageAgentProfile) -> dict:
    payload = profile.model_dump(mode="json")
    return {
        "schema_version": "attack-profile-v0.1",
        "attack_profile_id": "attack-profile:001",
        "source_profile_id": profile.profile_id,
        "source_profile_sha256": PROFILE_SHA256,
        "tenant_id": profile.tenant_id,
        "agent_id": profile.agent_id,
        "image": payload["image"],
        "generated_at": COMPLETED_AT,
        "frameworks": payload["frameworks"],
        "nodes": payload["nodes"],
        "edges": payload["edges"],
        "capabilities": payload["capabilities"],
        "permissions": payload["permissions"],
        "controls": payload["controls"],
        "evidence": payload["evidence"],
        "risk_paths": payload["risk_paths"],
    }


def test_agent_directory_descriptor_serialization_snapshot() -> None:
    descriptor = AgentDirectoryDescriptor(
        agent_id="openmanus",
        name="OpenManus",
        image={"type": "docker_archive", "path": "image.tar", "digest": IMAGE_DIGEST},
        platform="linux/arm64",
        expected_frameworks=["OpenManus", "MCP"],
        notes="Offline release artifact.",
    )

    assert descriptor.model_dump(mode="json") == {
        "schema_version": "agent-directory-v0.1",
        "agent_id": "openmanus",
        "name": "OpenManus",
        "image": {"type": "docker_archive", "path": "image.tar", "digest": IMAGE_DIGEST},
        "platform": "linux/arm64",
        "runtime": {
            "requires_privileged": False,
            "required_host_mounts": [],
            "probe_module": None,
        },
        "expected_frameworks": ["OpenManus", "MCP"],
        "notes": "Offline release artifact.",
    }


def test_agent_directory_descriptor_rejects_path_traversal() -> None:
    with pytest.raises(ValidationError, match="without traversal"):
        AgentDirectoryDescriptor(
            agent_id="openmanus",
            name="OpenManus",
            image={"type": "docker_archive", "path": "../image.tar"},
        )


def test_agent_directory_descriptor_rejects_unsafe_runtime_metadata() -> None:
    with pytest.raises(ValidationError, match="absolute paths"):
        AgentDirectoryDescriptor(
            agent_id="openmanus",
            name="OpenManus",
            image={"type": "docker_archive", "path": "image.tar"},
            runtime={"required_host_mounts": ["relative/path"]},
        )
    with pytest.raises(ValidationError, match="pattern"):
        AgentDirectoryDescriptor(
            agent_id="openmanus",
            name="OpenManus",
            image={"type": "docker_archive", "path": "image.tar"},
            runtime={"probe_module": "app.agent; unsafe"},
        )


def test_analysis_status_allows_recoverable_dynamic_failure_but_requires_matching_error() -> None:
    payload = _analysis()
    payload["status"] = "partial"
    payload["stages"][6] = {
        "stage": "dynamic_verify",
        "status": "failed",
        "completed_at": COMPLETED_AT,
    }
    payload["errors"] = [
        {
            "error_id": "error:dynamic",
            "stage": "dynamic_verify",
            "code": "unsupported_platform",
            "message": "Dynamic verification is unavailable for this platform.",
            "retryable": False,
        }
    ]

    status = ImageAnalysisStatus.model_validate(payload)
    assert status.stages[6].status == "failed"
    assert status.stages[-1].status == "completed"

    payload["errors"] = []
    with pytest.raises(ValidationError, match="failed stages and analysis errors must match"):
        ImageAnalysisStatus.model_validate(payload)


def test_analysis_status_requires_all_eight_stages_in_canonical_order() -> None:
    payload = _analysis()
    payload["stages"] = payload["stages"][:-1]

    with pytest.raises(ValidationError, match="canonical eight stages"):
        ImageAnalysisStatus.model_validate(payload)


def test_image_and_attack_profiles_round_trip_without_contract_drift() -> None:
    profile = ImageAgentProfile.model_validate(_profile_payload())
    restored = ImageAgentProfile.model_validate_json(profile.model_dump_json())
    attack = AttackProfile.model_validate(_attack_payload(profile))

    assert restored == profile
    assert profile.schema_version == "agent-profile-v0.2"
    assert attack.schema_version == "attack-profile-v0.1"
    assert attack.risk_paths[0].node_ids == ["node:input", "node:shell"]
    assert attack.image.digest == IMAGE_DIGEST


def test_legacy_profile_without_completeness_remains_readable() -> None:
    payload = _profile_payload()
    payload.pop("completeness", None)

    profile = ImageAgentProfile.model_validate(payload)

    assert profile.analysis.status == "completed"
    assert profile.completeness is None


def test_profile_completeness_summary_is_machine_readable_and_consistent() -> None:
    payload = _profile_payload()
    payload["limitations"] = []
    payload["completeness"] = _completeness()

    profile = ImageAgentProfile.model_validate(payload)

    assert profile.completeness is not None
    assert profile.completeness.dynamic_corroboration_coverage.covered == 1
    assert profile.completeness.conclusion == "complete"

    payload["completeness"]["dynamic_corroboration_coverage"] = {
        "covered": 0,
        "total": 1,
        "ratio": 0.0,
    }
    with pytest.raises(ValidationError, match="dynamic corroboration"):
        ImageAgentProfile.model_validate(payload)

    payload["completeness"] = _completeness()
    payload["analysis"]["stages"][6]["status"] = "skipped"
    with pytest.raises(ValidationError, match="successful dynamic verification"):
        ImageAgentProfile.model_validate(payload)


def test_dynamic_coverage_requires_all_behavior_nodes_and_controls() -> None:
    payload = _profile_payload()
    payload["nodes"].extend(
        [
            {
                "node_id": "node:unlisted-tool",
                "node_type": "tool",
                "name": "Unlisted critical tool",
                "risk_level": "critical",
                **_claim("ev:static"),
            },
            {
                "node_id": "node:unlisted-agent",
                "node_type": "agent",
                "name": "Unlisted agent",
                **_claim("ev:static"),
            },
        ]
    )

    profile = ImageAgentProfile.model_validate(
        {**payload, "analysis": {**payload["analysis"], "status": "partial"}, "completeness": None}
    )

    assert dynamic_required_claim_ids(profile) == {
        "node:unlisted-agent",
        "node:unlisted-tool",
        "control:allowlist",
    }


def test_partial_completeness_allows_completed_stages_without_failed_stage() -> None:
    payload = _profile_payload()
    payload["analysis"]["status"] = "partial"
    payload["completeness"] = _completeness(conclusion="partial")
    payload["completeness"]["unresolved_limitations"] = 1
    payload["completeness"]["blocking_limitations"] = ["encrypted_content"]

    profile = ImageAgentProfile.model_validate(payload)

    assert profile.analysis.status == "partial"
    assert profile.completeness is not None
    assert profile.completeness.conclusion == "partial"


@pytest.mark.parametrize(
    ("target", "index"),
    [
        ("nodes", 0),
        ("risk_paths", 0),
    ],
)
def test_profile_rejects_published_nodes_and_paths_without_evidence(target: str, index: int) -> None:
    payload = _profile_payload()
    payload[target][index]["evidence_refs"] = []

    with pytest.raises(ValidationError, match="at least 1 item"):
        ImageAgentProfile.model_validate(payload)


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_profile_rejects_confidence_outside_closed_unit_interval(confidence: float) -> None:
    payload = _profile_payload()
    payload["nodes"][0]["confidence"] = confidence

    with pytest.raises(ValidationError):
        ImageAgentProfile.model_validate(payload)


@pytest.mark.parametrize("collection", ["nodes", "evidence"])
def test_profile_rejects_duplicate_ids(collection: str) -> None:
    payload = _profile_payload()
    payload[collection].append(deepcopy(payload[collection][0]))

    with pytest.raises(ValidationError, match="must be unique"):
        ImageAgentProfile.model_validate(payload)


def test_profile_rejects_verified_claim_without_independent_corroboration() -> None:
    payload = _profile_payload()
    payload["risk_paths"][0]["evidence_refs"] = ["ev:static"]

    with pytest.raises(ValidationError, match="verified status requires"):
        ImageAgentProfile.model_validate(payload)


def test_profile_rejects_risk_path_whose_edge_order_disagrees_with_nodes() -> None:
    payload = _profile_payload()
    payload["edges"][0]["source_node_id"] = "node:shell"
    payload["edges"][0]["target_node_id"] = "node:input"

    with pytest.raises(ValidationError, match="edge order"):
        ImageAgentProfile.model_validate(payload)


def test_attack_profile_rejects_inferred_high_impact_path_even_when_opted_in() -> None:
    profile = ImageAgentProfile.model_validate(_profile_payload())
    payload = _attack_payload(profile)
    payload["include_inferred"] = True
    payload["risk_paths"][0]["verification_status"] = "inferred"

    with pytest.raises(ValidationError, match="cannot trigger high-impact"):
        AttackProfile.model_validate(payload)


def test_legacy_application_agent_profile_v01_remains_compatible() -> None:
    profile = AgentProfile(
        profile_id="legacy_profile",
        agent_id="legacy_agent",
        nodes=[AgentProfileNode(node_id="legacy_node", node_type="tool")],
    )

    assert profile.schema_version == "agent-profile-v0.1"
    assert profile.model_dump(mode="json")["nodes"][0]["node_id"] == "legacy_node"


def _complete_attack_spec_payload(
    profile: ImageAgentProfile,
    attack: AttackProfile,
) -> dict:
    specs = build_attack_profile_driven_attack_plan(attack).targeted_specs
    return {
        "schema_version": "attack-spec-set-v0.1",
        "agent_id": profile.agent_id,
        "image_digest": profile.image.digest,
        "profile_id": profile.profile_id,
        "profile_sha256": image_profile_sha256(profile),
        "attack_profile_id": attack.attack_profile_id,
        "count": len(specs),
        "specs": [item.model_dump(mode="json") for item in specs],
    }


def test_complete_artifact_bundle_round_trips_and_preserves_bindings() -> None:
    profile = ImageAgentProfile.model_validate(_profile_payload())
    attack = build_attack_profile(profile)
    assert attack is not None
    payload = _complete_attack_spec_payload(profile, attack)

    specs = _verify_profile_bundle(profile.agent_id, profile, attack, payload)

    assert len(specs) == 2
    assert {item.risk_type for item in specs} == {
        "prompt_injection",
        "tool_abuse",
    }


@pytest.mark.parametrize(
    ("collection", "field", "value"),
    [
        ("permissions", "scope", "host"),
        ("controls", "description", "Tampered control."),
        ("nodes", "confidence", 0.5),
        ("risk_paths", "verification_status", "supported"),
    ],
)
def test_complete_artifact_bundle_rejects_attack_profile_drift(
    collection: str,
    field: str,
    value: object,
) -> None:
    profile = ImageAgentProfile.model_validate(_profile_payload())
    attack = build_attack_profile(profile)
    assert attack is not None
    attack_payload = attack.model_dump(mode="json")
    attack_payload[collection][0][field] = value
    drifted = AttackProfile.model_validate(attack_payload)

    with pytest.raises(AssertionError):
        _verify_profile_bundle(
            profile.agent_id,
            profile,
            drifted,
            _complete_attack_spec_payload(profile, attack),
        )


def test_complete_artifact_bundle_rejects_attack_spec_binding_drift() -> None:
    profile = ImageAgentProfile.model_validate(_profile_payload())
    attack = build_attack_profile(profile)
    assert attack is not None
    payload = _complete_attack_spec_payload(profile, attack)
    payload["specs"][0]["metadata"]["permission_ids"] = []

    with pytest.raises(AssertionError):
        _verify_profile_bundle(profile.agent_id, profile, attack, payload)
