from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import threading
import time
from pathlib import Path

import pytest

from redsentinel.application.engine.agent_asset_index import AgentAssetIndexService
from redsentinel.application.engine.app import create_app
from redsentinel.application.engine.dynamic_profile_probe import (
    DynamicProbeEvent,
    DynamicProbeResult,
    DynamicProfileProbe,
    align_dynamic_events,
)
from redsentinel.application.engine.image_profile_workflow import (
    ImageProfileWorkflowError,
    ImageProfileWorkflowService,
)
from redsentinel.application.engine.local_image_ref import (
    LocalDockerImageRefResolver,
)
from redsentinel.application.engine.service import ProductEvaluationService
from redsentinel.core.image_profile_graph import AnalysisLimitation


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _write_agent(
    root: Path,
    *,
    agent_id: str,
    source: bytes,
    os_name: str = "linux",
    runtime: dict[str, object] | None = None,
) -> Path:
    directory = root / agent_id
    directory.mkdir(parents=True, exist_ok=True)
    layer = _tar_bytes({"app/agent.py": source})
    layer_digest = hashlib.sha256(layer).hexdigest()
    config = json.dumps(
        {
            "architecture": "arm64",
            "os": os_name,
            "config": {
                "Entrypoint": ["python", "-m", "app.agent"],
                "WorkingDir": "/app",
                "Env": ["API_TOKEN=secret", "MODE=test"],
            },
            "rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer_digest}"]},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    config_name = f"{hashlib.sha256(config).hexdigest()}.json"
    image = _tar_bytes(
        {
            "manifest.json": json.dumps([{"Config": config_name, "RepoTags": [], "Layers": ["layer.tar"]}]).encode(),
            config_name: config,
            "layer.tar": layer,
        }
    )
    (directory / "image.tar").write_bytes(image)
    (directory / "agent.json").write_text(
        json.dumps(
            {
                "schema_version": "agent-directory-v0.1",
                "agent_id": agent_id,
                "name": agent_id,
                "image": {"type": "docker_archive", "path": "image.tar"},
                "runtime": runtime or {},
            }
        ),
        encoding="utf-8",
    )
    return directory


@pytest.mark.parametrize(
    ("os_name", "runtime", "expected_code"),
    [
        (
            "linux",
            {"requires_privileged": True},
            "privileged_runtime_required",
        ),
        (
            "linux",
            {"required_host_mounts": ["/var/run/docker.sock"]},
            "dangerous_mount_required",
        ),
        ("windows", {}, "unsupported_platform"),
    ],
)
def test_workflow_derives_runtime_risk_and_publishes_static_partial_profile(
    tmp_path: Path,
    os_name: str,
    runtime: dict[str, object],
    expected_code: str,
) -> None:
    root = tmp_path / "agents"
    _write_agent(
        root,
        agent_id="unsafe_agent",
        source=b"def run(value):\n    return value\n",
        os_name=os_name,
        runtime=runtime,
    )
    product = ProductEvaluationService(tmp_path / "storage")
    AgentAssetIndexService(product).refresh(
        root,
        tenant_id="tenant",
        username="tenant",
    )
    probe_started = False
    resolver_called = False

    def forbidden_capture(*args: object, **kwargs: object):
        nonlocal probe_started
        probe_started = True
        raise AssertionError("risk gate must reject before Docker starts")

    def forbidden_resolver(_: dict[str, object]) -> str:
        nonlocal resolver_called
        resolver_called = True
        raise AssertionError("risk gate must reject before loading an image")

    workflow = ImageProfileWorkflowService(
        product.storage,
        asset_root_provider=lambda: root,
        image_ref_resolver=forbidden_resolver,
        dynamic_probe_factory=lambda artifact_root: DynamicProfileProbe(
            artifact_root,
            capture_runner=forbidden_capture,
        ),
    )

    created = workflow.create(tenant_id="tenant", agent_id="unsafe_agent")
    status = workflow.run(
        tenant_id="tenant",
        agent_id="unsafe_agent",
        analysis_id=created.analysis.analysis_id,
    )
    profile = workflow.get_latest_profile(
        tenant_id="tenant",
        agent_id="unsafe_agent",
    )

    assert not probe_started
    assert not resolver_called
    assert status.status == "partial"
    assert status.errors[-1].code == expected_code
    assert profile.analysis.status == "partial"
    assert profile.analysis.errors[-1].code == expected_code
    assert profile.completeness is not None
    assert profile.completeness.conclusion == "partial"
    assert profile.completeness.dynamic_corroboration_coverage.covered == 0
    assert profile.nodes


@pytest.mark.docker
def test_two_real_archives_keep_attested_behavior_partial_when_enabled(
    tmp_path: Path,
) -> None:
    root_value = os.environ.get("RED_SENTINEL_REAL_IMAGE_ROOT")
    docker_binary = os.environ.get("RED_SENTINEL_DOCKER_BINARY")
    if not root_value or not docker_binary:
        pytest.skip("set RED_SENTINEL_REAL_IMAGE_ROOT and RED_SENTINEL_DOCKER_BINARY")
    root = Path(root_value).resolve()
    if not Path(docker_binary).is_file():
        pytest.skip("configured Docker binary is unavailable")

    product = ProductEvaluationService(tmp_path / "storage")
    indexed = AgentAssetIndexService(product).refresh(
        root,
        tenant_id="tenant",
        username="tenant",
    )
    assert {item.agent_id for item in indexed} >= {"ecommerce", "openmanus"}
    workflow = ImageProfileWorkflowService(
        product.storage,
        asset_root_provider=lambda: root,
        image_ref_resolver=LocalDockerImageRefResolver(docker_binary),
        dynamic_probe_factory=lambda artifact_root: DynamicProfileProbe(
            artifact_root,
            docker_binary=docker_binary,
        ),
    )

    for agent_id in ("ecommerce", "openmanus"):
        created = workflow.create(tenant_id="tenant", agent_id=agent_id)
        status = workflow.run(
            tenant_id="tenant",
            agent_id=agent_id,
            analysis_id=created.analysis.analysis_id,
        )
        suffix = status.analysis_id.rsplit(":", 1)[-1]
        events = workflow.storage.read_json(
            workflow.storage.image_profile_artifact_path(
                "tenant",
                agent_id,
                suffix,
                "dynamic-events",
            )
        )

        assert status.status == "partial"
        assert status.stages[6].status == "completed"
        assert {event["event_type"] for event in events["events"]} >= {
            "startup",
            "import_succeeded",
        }
        profile = workflow.get_latest_profile(
            tenant_id="tenant",
            agent_id=agent_id,
        )
        assert profile.completeness is not None
        assert profile.completeness.conclusion == "partial"
        assert profile.completeness.dynamic_behavior_coverage.covered == 0
        assert "dynamic_critical_coverage_incomplete" in profile.completeness.blocking_limitations
        evidence_methods = {evidence.evidence_id: evidence.method for evidence in profile.evidence}
        if agent_id == "ecommerce":
            ecommerce_agents = [
                node for node in profile.nodes if node.name in {"call invoke_ecommerce_agent", "invoke_ecommerce_agent"}
            ]
            assert len(ecommerce_agents) == 1
            assert ecommerce_agents[0].name == "call invoke_ecommerce_agent"
            assert ecommerce_agents[0].verification_status == "verified"
            methods = {evidence_methods[evidence_id] for evidence_id in ecommerce_agents[0].evidence_refs}
            assert methods & {"image_config", "package_metadata", "static", "framework"}
            assert "dynamic" in methods


def _workflow(tmp_path: Path, root: Path, tenant_id: str = "tenant") -> ImageProfileWorkflowService:
    product = ProductEvaluationService(tmp_path / "storage")
    indexed = AgentAssetIndexService(product).refresh(root, tenant_id=tenant_id, username=tenant_id)
    assert indexed
    return ImageProfileWorkflowService(product.storage, asset_root_provider=lambda: root)


def test_eight_stage_workflow_publishes_partial_profile_and_raw_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "agents"
    _write_agent(
        root,
        agent_id="shell_agent",
        source=b"import subprocess\n\ndef run(user_input):\n    return subprocess.run(user_input)\n",
    )
    workflow = _workflow(tmp_path, root)

    created = workflow.create(tenant_id="tenant", agent_id="shell_agent")
    completed = workflow.run(
        tenant_id="tenant",
        agent_id="shell_agent",
        analysis_id=created.analysis.analysis_id,
    )
    profile = workflow.get_latest_profile(tenant_id="tenant", agent_id="shell_agent")

    assert completed.status == "partial"
    assert [item.stage for item in completed.stages] == [
        "inventory",
        "unpack",
        "static_extract",
        "framework_detect",
        "graph_reconstruct",
        "semantic_enrich",
        "dynamic_verify",
        "finalize",
    ]
    assert completed.stages[5].status == "skipped"
    assert completed.stages[6].status == "failed"
    assert completed.stages[7].status == "completed"
    assert profile.schema_version == "agent-profile-v0.2"
    assert profile.analysis.status == "partial"
    assert profile.completeness is not None
    assert profile.completeness.conclusion == "partial"
    assert "dynamic_verification_failed" in profile.completeness.blocking_limitations
    assert profile.risk_paths
    assert "API_TOKEN=secret" not in json.dumps(profile.model_dump(mode="json"))
    assert profile.image.environment_variables == ["API_TOKEN", "MODE"]

    suffix = completed.analysis_id.rsplit(":", 1)[-1]
    artifact_dir = workflow.storage.image_profile_dir("tenant", "shell_agent", suffix) / "artifacts"
    assert {
        "static-facts.json",
        "framework-analysis.json",
        "graph-fragments.json",
        "semantic-evidence.json",
        "dynamic-events.json",
        "published-profile.json",
        "evidence-index.json",
        "attack-profile.json",
    } <= {item.name for item in artifact_dir.iterdir()}
    evidence_ids = {item.evidence_id for item in profile.evidence}
    for claim in [
        profile.image,
        *profile.frameworks,
        *profile.nodes,
        *profile.edges,
        *profile.capabilities,
        *profile.permissions,
        *profile.controls,
        *profile.risk_paths,
    ]:
        assert set(claim.evidence_refs) <= evidence_ids


def test_final_profile_keeps_derived_claims_consistent_after_dynamic_only_structure(
    tmp_path: Path,
) -> None:
    root = tmp_path / "agents"
    _write_agent(
        root,
        agent_id="dynamic_graph",
        source=b"import subprocess\n\ndef run(user_input):\n    return subprocess.run(user_input)\n",
        runtime={"probe_module": "agent"},
    )
    workflow = _workflow(tmp_path, root)
    workflow._image_ref_resolver = lambda _: "local/dynamic-graph:test"

    class DynamicOnlyProbe:
        def run(self, profile, **kwargs):
            source_node_id = profile.nodes[0].node_id
            events = (
                DynamicProbeEvent(
                    event_id="event:runtime-tool",
                    event_type="tool_registered",
                    timestamp="2026-08-25T00:00:00Z",
                    name="runtime_tool",
                    node_type="tool",
                ),
                DynamicProbeEvent(
                    event_id="event:runtime-call",
                    event_type="call_plan",
                    timestamp="2026-08-25T00:00:01Z",
                    name="runtime_tool",
                    source_node_id=source_node_id,
                    target_node_id="runtime_tool",
                    details={"executed": False},
                ),
            )
            return DynamicProbeResult(
                profile=align_dynamic_events(profile, events),
                events=events,
            )

    workflow._dynamic_probe_factory = lambda _: DynamicOnlyProbe()
    created = workflow.create(tenant_id="tenant", agent_id="dynamic_graph")
    status = workflow.run(
        tenant_id="tenant",
        agent_id="dynamic_graph",
        analysis_id=created.analysis.analysis_id,
    )
    profile = workflow.get_latest_profile(tenant_id="tenant", agent_id="dynamic_graph")

    assert status.status == "partial"
    assert profile.analysis.status == "partial"
    assert profile.completeness is not None
    assert profile.completeness.conclusion == "partial"
    assert profile.completeness.dynamic_corroboration_coverage.covered == 0
    assert "critical_dynamic_corroboration_incomplete" in profile.completeness.blocking_limitations
    dynamic_node = next(node for node in profile.nodes if node.name == "runtime_tool")
    assert dynamic_node.capability_ids == []
    assert dynamic_node.permission_ids == []
    assert all(dynamic_node.node_id not in item.node_ids for item in profile.capabilities)
    assert all(dynamic_node.node_id not in item.node_ids for item in profile.permissions)
    node_ids = {item.node_id for item in profile.nodes}
    edges = {item.edge_id: item for item in profile.edges}
    for path in profile.risk_paths:
        assert set(path.node_ids) <= node_ids
        for index, edge_id in enumerate(path.edge_ids):
            assert edges[edge_id].source_node_id == path.node_ids[index]
            assert edges[edge_id].target_node_id == path.node_ids[index + 1]


@pytest.mark.parametrize(
    ("limitation_code", "expected_status"),
    [
        (None, "completed"),
        ("dataflow_unresolved", "completed"),
        ("evidence_missing", "partial"),
        ("dynamic_static_conflict", "partial"),
    ],
)
def test_workflow_completes_only_with_static_dynamic_corroboration_and_no_blocker(
    tmp_path: Path,
    limitation_code: str | None,
    expected_status: str,
) -> None:
    root = tmp_path / "agents"
    _write_agent(
        root,
        agent_id="corroborated",
        source=(
            b"from langgraph.graph import StateGraph\n\n"
            b"graph = StateGraph(dict)\n"
            b"graph.add_node('worker', lambda value: value)\n"
        ),
        runtime={"probe_module": "agent"},
    )
    workflow = _workflow(tmp_path, root)
    workflow._image_ref_resolver = lambda _: "local/corroborated:test"

    class CorroboratingProbe:
        def run(self, profile, **kwargs):
            nodes = [
                item
                for item in profile.nodes
                if item.node_type in {"agent", "tool", "mcp", "guard"} or item.risk_level in {"high", "critical"}
            ]
            events = [
                DynamicProbeEvent(
                    event_id=f"event:coverage:{index}",
                    event_type="coverage_target",
                    timestamp="2026-08-26T00:00:00Z",
                    name=node.name,
                    node_type=node.node_type,
                    details={"required": True},
                )
                for index, node in enumerate(nodes)
            ]
            events.extend(
                [
                    DynamicProbeEvent(
                        event_id="event:started",
                        event_type="invocation_started",
                        timestamp="2026-08-26T00:00:00Z",
                        name="normal-smoke",
                    ),
                    *[
                        DynamicProbeEvent(
                            event_id=f"event:static-node:{index}",
                            event_type=(
                                "tool_called"
                                if node.node_type == "tool"
                                else "guard_decision"
                                if node.node_type == "guard"
                                else "agent_invoked"
                            ),
                            timestamp="2026-08-26T00:00:01Z",
                            name=node.name,
                            node_type=node.node_type,
                            static_node_id=node.node_id,
                            source_node_id=(nodes[0].node_id if node.node_type == "tool" else None),
                            target_node_id=(node.node_id if node.node_type == "tool" else None),
                            details={"executed": True},
                            trust_level="observed",
                        )
                        for index, node in enumerate(nodes)
                    ],
                    DynamicProbeEvent(
                        event_id="event:output",
                        event_type="output_observed",
                        timestamp="2026-08-26T00:00:02Z",
                        name="normal-smoke",
                    ),
                    DynamicProbeEvent(
                        event_id="event:completed",
                        event_type="invocation_completed",
                        timestamp="2026-08-26T00:00:03Z",
                        name="normal-smoke",
                        details={"success": True},
                    ),
                ]
            )
            events = tuple(events)
            aligned = align_dynamic_events(profile, events)
            if limitation_code:
                aligned = aligned.model_copy(
                    update={
                        "limitations": [
                            *aligned.limitations,
                            AnalysisLimitation(
                                code=limitation_code,
                                message="Synthetic limitation for completeness classification.",
                            ),
                        ]
                    }
                )
            return DynamicProbeResult(profile=aligned, events=events)

    workflow._dynamic_probe_factory = lambda _: CorroboratingProbe()
    created = workflow.create(tenant_id="tenant", agent_id="corroborated")
    status = workflow.run(
        tenant_id="tenant",
        agent_id="corroborated",
        analysis_id=created.analysis.analysis_id,
    )
    profile = workflow.get_latest_profile(tenant_id="tenant", agent_id="corroborated")

    assert profile.completeness is not None
    assert profile.completeness.dynamic_corroboration_coverage.covered >= 1
    assert status.status == expected_status
    if expected_status == "partial":
        assert status.status == "partial"
        assert profile.completeness.conclusion == "partial"
        assert limitation_code in profile.completeness.blocking_limitations
    else:
        assert profile.completeness.conclusion == "complete"
        assert profile.completeness.blocking_limitations == []
        if limitation_code:
            assert limitation_code in {item.code for item in profile.limitations}


def test_digest_cache_and_digest_change_create_distinct_versions(tmp_path: Path) -> None:
    root = tmp_path / "agents"
    _write_agent(root, agent_id="versioned", source=b"def run(value):\n    return value\n")
    workflow = _workflow(tmp_path, root)
    first = workflow.create(tenant_id="tenant", agent_id="versioned")
    workflow.run(tenant_id="tenant", agent_id="versioned", analysis_id=first.analysis.analysis_id)

    cached = workflow.create(tenant_id="tenant", agent_id="versioned")
    assert cached.cached
    assert cached.analysis.analysis_id == first.analysis.analysis_id

    _write_agent(root, agent_id="versioned", source=b"def run(value):\n    return value.strip()\n")
    product = ProductEvaluationService(tmp_path / "storage")
    AgentAssetIndexService(product).refresh(root, tenant_id="tenant", username="tenant")
    second = workflow.create(tenant_id="tenant", agent_id="versioned")
    assert second.analysis.analysis_id != first.analysis.analysis_id
    assert not second.cached
    historical = workflow.get_status(
        tenant_id="tenant",
        agent_id="versioned",
        analysis_id=first.analysis.analysis_id,
    )
    assert historical.analysis_id == first.analysis.analysis_id
    assert len(list((tmp_path / "storage" / "tenant" / "image_profiles" / "versioned").glob("*/status.json"))) == 2


def test_checkpoint_is_adopted_after_status_write_interruption(tmp_path: Path) -> None:
    root = tmp_path / "agents"
    _write_agent(root, agent_id="recoverable", source=b"def run(value):\n    return value\n")
    workflow = _workflow(tmp_path, root)
    created = workflow.create(tenant_id="tenant", agent_id="recoverable")
    status = created.analysis
    suffix = status.analysis_id.rsplit(":", 1)[-1]
    inventory = workflow._inventory("tenant", "recoverable", status)
    checkpoint_ref = workflow._write_checkpoint(
        "tenant",
        "recoverable",
        suffix,
        "inventory",
        status.analysis_id,
        status.image_digest,
        status.configuration_digest,
        inventory,
        skipped=False,
    )
    assert checkpoint_ref

    original = workflow._inventory

    def fail_if_repeated(*args, **kwargs):
        raise AssertionError("committed inventory checkpoint must not be repeated")

    workflow._inventory = fail_if_repeated  # type: ignore[method-assign]
    result = workflow.run(tenant_id="tenant", agent_id="recoverable", analysis_id=status.analysis_id)
    workflow._inventory = original  # type: ignore[method-assign]

    assert result.status == "partial"
    assert result.stages[0].status == "completed"


def test_recovery_enumeration_normalizes_persisted_tenant_tasks(tmp_path: Path) -> None:
    root = tmp_path / "agents"
    _write_agent(root, agent_id="recoverable", source=b"def run(value):\n    return value\n")
    workflow_a = _workflow(tmp_path, root, "tenant_a")
    workflow_b = _workflow(tmp_path, root, "tenant_b")
    queued = workflow_a.create(tenant_id="tenant_a", agent_id="recoverable")
    running = workflow_b.create(tenant_id="tenant_b", agent_id="recoverable")
    suffix = running.analysis.analysis_id.rsplit(":", 1)[-1]
    workflow_b._write_status(
        "tenant_b",
        "recoverable",
        suffix,
        workflow_b._mark_running(running.analysis, "inventory"),
    )

    tasks = workflow_a.list_recovery_tasks()

    assert {(task.tenant_id, task.agent_id, task.analysis_id) for task in tasks} == {
        ("tenant_a", "recoverable", queued.analysis.analysis_id),
        ("tenant_b", "recoverable", running.analysis.analysis_id),
    }
    normalized = workflow_b.get_status(
        tenant_id="tenant_b",
        agent_id="recoverable",
    )
    assert normalized.status == "queued"
    assert normalized.stages[0].status == "pending"


def test_testclient_startup_resumes_checkpoint_and_exposes_live_agent_status(
    tmp_path: Path,
    monkeypatch,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    root = tmp_path / "agents"
    storage = tmp_path / "storage"
    tenant_id = "restart_owner"
    _write_agent(root, agent_id="restart_agent", source=b"def run(value):\n    return value\n")
    workflow = _workflow(tmp_path, root, tenant_id)
    created = workflow.create(tenant_id=tenant_id, agent_id="restart_agent")
    suffix = created.analysis.analysis_id.rsplit(":", 1)[-1]
    inventory = workflow._inventory(tenant_id, "restart_agent", created.analysis)
    workflow._write_checkpoint(
        tenant_id,
        "restart_agent",
        suffix,
        "inventory",
        created.analysis.analysis_id,
        created.analysis.image_digest,
        created.analysis.configuration_digest,
        inventory,
        skipped=False,
    )
    workflow._write_status(
        tenant_id,
        "restart_agent",
        suffix,
        workflow._mark_running(created.analysis, "inventory"),
    )

    unpack_started = threading.Event()
    continue_run = threading.Event()
    original_execute_stage = ImageProfileWorkflowService._execute_stage

    def controlled_execute_stage(self, stage, **kwargs):
        if stage == "inventory":
            raise AssertionError("committed inventory checkpoint must not be repeated")
        if stage == "unpack":
            unpack_started.set()
            assert continue_run.wait(timeout=5)
        return original_execute_stage(self, stage, **kwargs)

    monkeypatch.setattr(ImageProfileWorkflowService, "_execute_stage", controlled_execute_stage)
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))

    with TestClient(create_app(storage_root=storage)) as client:
        assert unpack_started.wait(timeout=5)
        response = client.post(
            "/v1/auth/register",
            json={
                "username": tenant_id,
                "email": f"{tenant_id}@example.test",
                "password": "correct-horse-battery-staple",
            },
        )
        client.headers["Authorization"] = f"Bearer {response.json()['access_token']}"

        visible = client.get("/v1/agents").json()
        assert len(visible) == 1
        assert visible[0]["agent_id"] == "restart_agent"
        assert visible[0]["status"] == "profiling"
        assert visible[0]["data_boundary"]["profile_status"] == "running"
        assert visible[0]["data_boundary"]["profile_stage"] == "unpack"

        continue_run.set()
        for _ in range(200):
            status = client.get(f"/v1/agents/restart_agent/profiles/{created.analysis.analysis_id}/status").json()
            if status["status"] in {"completed", "partial", "failed"}:
                break
            time.sleep(0.02)

        assert status["status"] == "partial"
        recovered = client.get("/v1/agents").json()[0]
        assert recovered["status"] == "ready"
        assert recovered["data_boundary"]["profile_status"] == "partial"


def test_unpack_checkpoint_canonicalizes_rootfs_inside_current_unpack_root(tmp_path: Path) -> None:
    root = tmp_path / "agents"
    _write_agent(root, agent_id="canonical", source=b"def run(value):\n    return value\n")
    workflow = _workflow(tmp_path, root)
    created = workflow.create(tenant_id="tenant", agent_id="canonical")
    suffix = created.analysis.analysis_id.rsplit(":", 1)[-1]
    inventory = workflow._inventory("tenant", "canonical", created.analysis)
    unpacked = workflow._unpack("tenant", "canonical", suffix, inventory)
    rootfs = Path(unpacked["rootfs_path"])
    unpacked["rootfs_path"] = str(rootfs / ".." / rootfs.name)
    workflow._write_checkpoint(
        "tenant",
        "canonical",
        suffix,
        "unpack",
        created.analysis.analysis_id,
        created.analysis.image_digest,
        created.analysis.configuration_digest,
        unpacked,
        skipped=False,
    )

    checkpoint = workflow._read_checkpoint(
        "tenant",
        "canonical",
        suffix,
        "unpack",
        created.analysis,
    )

    assert checkpoint is not None
    assert checkpoint["output"]["rootfs_path"] == str(rootfs.resolve())


@pytest.mark.parametrize("tamper_kind", ["unpack_root", "foreign_path", "symlink_escape"])
def test_tampered_unpack_checkpoint_is_rejected_before_static_traversal(
    tmp_path: Path,
    monkeypatch,
    tamper_kind: str,
) -> None:
    root = tmp_path / "agents"
    _write_agent(root, agent_id="tampered", source=b"def run(value):\n    return value\n")
    workflow = _workflow(tmp_path, root)
    created = workflow.create(tenant_id="tenant", agent_id="tampered")
    suffix = created.analysis.analysis_id.rsplit(":", 1)[-1]
    unpack_root = workflow.storage.image_profile_unpack_root("tenant", "tampered", suffix)
    unpack_root.mkdir(parents=True)
    foreign_rootfs = tmp_path / "foreign" / "rootfs"
    foreign_rootfs.mkdir(parents=True)
    if tamper_kind == "unpack_root":
        rootfs_path = unpack_root
    elif tamper_kind == "foreign_path":
        rootfs_path = foreign_rootfs
    else:
        link = unpack_root / "rootfs-link"
        link.symlink_to(foreign_rootfs, target_is_directory=True)
        rootfs_path = link
    workflow._write_checkpoint(
        "tenant",
        "tampered",
        suffix,
        "unpack",
        created.analysis.analysis_id,
        created.analysis.image_digest,
        created.analysis.configuration_digest,
        {"rootfs_path": str(rootfs_path)},
        skipped=False,
    )
    traversed = False

    def fail_if_traversed(*args, **kwargs):
        nonlocal traversed
        traversed = True
        raise AssertionError("tampered rootfs must not reach static extraction")

    monkeypatch.setattr(
        "redsentinel.application.engine.image_profile_workflow.extract_static_facts",
        fail_if_traversed,
    )

    with pytest.raises(
        ImageProfileWorkflowError,
        match="unpack checkpoint rootfs path",
    ) as exc_info:
        workflow.run(
            tenant_id="tenant",
            agent_id="tampered",
            analysis_id=created.analysis.analysis_id,
        )

    assert exc_info.value.code == "image_profile_checkpoint_tampered"
    assert not traversed


def test_unpack_replaces_read_only_output_left_by_an_interrupted_run(tmp_path: Path) -> None:
    root = tmp_path / "agents"
    _write_agent(root, agent_id="interrupted", source=b"def run(value):\n    return value\n")
    workflow = _workflow(tmp_path, root)
    created = workflow.create(tenant_id="tenant", agent_id="interrupted")
    suffix = created.analysis.analysis_id.rsplit(":", 1)[-1]
    output = workflow.storage.image_profile_unpack_root("tenant", "interrupted", suffix)
    stale = output / "stale" / "proc"
    stale.mkdir(parents=True)
    stale.chmod(0o500)
    stale.parent.chmod(0o500)

    inventory = workflow._inventory("tenant", "interrupted", created.analysis)
    unpacked = workflow._unpack("tenant", "interrupted", suffix, inventory)

    assert Path(unpacked["rootfs_path"]).is_dir()
    assert not (output / "stale").exists()


def test_persistent_lease_prevents_concurrent_runner(tmp_path: Path) -> None:
    root = tmp_path / "agents"
    _write_agent(root, agent_id="leased", source=b"def run(value):\n    return value\n")
    workflow = _workflow(tmp_path, root)
    created = workflow.create(tenant_id="tenant", agent_id="leased")
    suffix = created.analysis.analysis_id.rsplit(":", 1)[-1]

    with workflow.storage.image_profile_lease("tenant", "leased", suffix) as acquired:
        assert acquired
        concurrent = workflow.run(
            tenant_id="tenant",
            agent_id="leased",
            analysis_id=created.analysis.analysis_id,
        )
        assert concurrent.status == "queued"

    lease = json.loads(
        workflow.storage.image_profile_lease_path("tenant", "leased", suffix).read_text(encoding="utf-8")
    )
    assert lease["released_at"]


def test_tenant_boundary_and_failure_isolation(tmp_path: Path) -> None:
    root = tmp_path / "agents"
    _write_agent(root, agent_id="shared", source=b"def run(value):\n    return value\n")
    workflow_a = _workflow(tmp_path, root, "tenant_a")
    workflow_b = _workflow(tmp_path, root, "tenant_b")
    created = workflow_a.create(tenant_id="tenant_a", agent_id="shared")
    workflow_a.run(tenant_id="tenant_a", agent_id="shared", analysis_id=created.analysis.analysis_id)

    with pytest.raises(ImageProfileWorkflowError, match="not found"):
        workflow_b.get_latest_profile(tenant_id="tenant_b", agent_id="shared")

    broken = root / "broken"
    broken.mkdir()
    (broken / "image.tar").write_bytes(b"not a tar")
    (broken / "agent.json").write_text(
        json.dumps(
            {
                "schema_version": "agent-directory-v0.1",
                "agent_id": "broken",
                "name": "broken",
                "image": {"type": "docker_archive", "path": "image.tar"},
            }
        ),
        encoding="utf-8",
    )
    product = ProductEvaluationService(tmp_path / "storage")
    AgentAssetIndexService(product).refresh(root, tenant_id="tenant_a", username="tenant_a")
    broken_workflow = ImageProfileWorkflowService(product.storage, asset_root_provider=lambda: root)
    broken_created = broken_workflow.create(tenant_id="tenant_a", agent_id="broken")
    broken_status = broken_workflow.run(
        tenant_id="tenant_a",
        agent_id="broken",
        analysis_id=broken_created.analysis.analysis_id,
    )
    assert broken_status.status == "failed"
    assert broken_status.stages[1].status == "failed"
    assert workflow_a.get_latest_profile(tenant_id="tenant_a", agent_id="shared").agent_id == "shared"


def test_sensitive_stage_error_is_redacted_from_status_and_published_profile(tmp_path: Path) -> None:
    secret = "task14-secret-value"
    root = tmp_path / "agents"
    _write_agent(root, agent_id="redacted", source=b"def run(value):\n    return value\n")
    workflow = _workflow(tmp_path, root)
    workflow._image_ref_resolver = lambda _: "local/redacted:test"

    class FailingProbe:
        def run(self, *args, **kwargs):
            raise RuntimeError(f"password={secret} token: {secret} api_key='{secret}' Authorization: Bearer {secret}")

    workflow._dynamic_probe_factory = lambda _: FailingProbe()
    created = workflow.create(tenant_id="tenant", agent_id="redacted")
    status = workflow.run(
        tenant_id="tenant",
        agent_id="redacted",
        analysis_id=created.analysis.analysis_id,
    )
    profile = workflow.get_latest_profile(tenant_id="tenant", agent_id="redacted")
    suffix = status.analysis_id.rsplit(":", 1)[-1]
    persisted_status = workflow.storage.image_profile_status_path("tenant", "redacted", suffix).read_text(
        encoding="utf-8"
    )
    persisted_profile = workflow.storage.image_profile_artifact_path(
        "tenant", "redacted", suffix, "published-profile"
    ).read_text(encoding="utf-8")
    visible = json.dumps(
        {
            "status": status.model_dump(mode="json"),
            "profile": profile.model_dump(mode="json"),
            "persisted_status": persisted_status,
            "persisted_profile": persisted_profile,
        }
    )

    assert secret not in visible
    assert "[REDACTED]" in visible
    assert "RuntimeError" in visible
    assert status.errors[-1].code == "dynamic_verify_failed"

    legacy_status = json.loads(persisted_status)
    legacy_status["errors"][-1]["message"] = f"RuntimeError: password={secret}"
    status_path = workflow.storage.image_profile_status_path("tenant", "redacted", suffix)
    status_path.write_text(json.dumps(legacy_status), encoding="utf-8")
    legacy_profile = json.loads(persisted_profile)
    legacy_profile["analysis"]["errors"][-1]["message"] = f"RuntimeError: token={secret}"
    profile_path = workflow.storage.image_profile_artifact_path("tenant", "redacted", suffix, "published-profile")
    profile_path.write_text(json.dumps(legacy_profile), encoding="utf-8")

    recovered_status = workflow.get_status(
        tenant_id="tenant",
        agent_id="redacted",
        analysis_id=status.analysis_id,
    )
    recovered_profile = workflow.get_latest_profile(
        tenant_id="tenant",
        agent_id="redacted",
    )

    assert secret not in json.dumps(recovered_status.model_dump(mode="json"))
    assert secret not in json.dumps(recovered_profile.model_dump(mode="json"))
    assert secret not in status_path.read_text(encoding="utf-8")
    assert secret not in profile_path.read_text(encoding="utf-8")


def _api_client(storage: Path, username: str):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    client = TestClient(create_app(storage_root=storage))
    response = client.post(
        "/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.test",
            "password": "correct-horse-battery-staple",
        },
    )
    client.headers["Authorization"] = f"Bearer {response.json()['access_token']}"
    return client


def test_profile_api_202_status_latest_legacy_and_errors(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "agents"
    _write_agent(root, agent_id="api_agent", source=b"def run(value):\n    return value\n")
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    client = _api_client(tmp_path / "storage", "api_tenant")

    created = client.post("/v1/agents/api_agent/profiles")
    assert created.status_code == 202
    assert created.json()["analysis"]["status"] in {"queued", "running"}
    analysis_id = created.json()["analysis"]["analysis_id"]

    status = None
    for _ in range(100):
        response = client.get(f"/v1/agents/api_agent/profiles/{analysis_id}/status")
        assert response.status_code == 200
        status = response.json()
        if status["status"] in {"completed", "partial", "failed"}:
            break
        time.sleep(0.02)
    assert status is not None and status["status"] == "partial"

    latest = client.get("/v1/agents/api_agent/profiles/latest")
    legacy = client.get("/v1/agents/api_agent/profile")
    assert latest.status_code == 200, latest.text
    assert latest.json()["schema_version"] == "agent-profile-v0.2"
    assert legacy.json() == latest.json()

    missing = client.get("/v1/agents/api_agent/profiles/analysis:missing/status")
    assert missing.status_code == 404
    assert missing.json()["detail"]["error_code"] == "profile_analysis_not_found"

    retry = client.post(f"/v1/agents/api_agent/profiles/{analysis_id}/retry")
    assert retry.status_code == 202


def test_profile_api_redacts_sensitive_workflow_error(tmp_path: Path, monkeypatch) -> None:
    secret = "task14-api-secret"

    def fail_status(self, **kwargs):
        raise ImageProfileWorkflowError(
            "profile_backend_failed",
            f"RuntimeError: password={secret}; Authorization: Bearer {secret}",
            status_code=503,
        )

    monkeypatch.setattr(ImageProfileWorkflowService, "get_status", fail_status)
    client = _api_client(tmp_path / "storage", "api_error_tenant")

    response = client.get("/v1/agents/agent/profiles/analysis:failed/status")

    assert response.status_code == 503
    payload = response.json()["detail"]
    assert payload["error_code"] == "profile_backend_failed"
    assert "RuntimeError" in payload["message"]
    assert secret not in json.dumps(payload)
    assert "[REDACTED]" in payload["message"]
