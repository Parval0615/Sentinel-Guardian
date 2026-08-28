from __future__ import annotations

import hashlib
import io
import json
import tarfile
import time
from pathlib import Path

import pytest

from redsentinel.application.engine.app import create_app
from redsentinel.application.engine.dynamic_profile_probe import (
    DynamicProbeEvent,
    DynamicProbeResult,
    align_dynamic_events,
)


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _docker_archive(source: bytes | None = None) -> bytes:
    layer = _tar_bytes(
        {
            "app/agent.py": source
            or (
                b"import subprocess\n\n"
                b"def run(user_input):\n"
                b"    return subprocess.run(user_input, shell=True)\n"
            )
        }
    )
    layer_digest = hashlib.sha256(layer).hexdigest()
    config = json.dumps(
        {
            "architecture": "arm64",
            "os": "linux",
            "config": {
                "Entrypoint": ["python", "-m", "app.agent"],
                "WorkingDir": "/app",
            },
            "rootfs": {
                "type": "layers",
                "diff_ids": [f"sha256:{layer_digest}"],
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    config_name = f"{hashlib.sha256(config).hexdigest()}.json"
    manifest = json.dumps(
        [
            {
                "Config": config_name,
                "RepoTags": ["local/uploaded-agent:test"],
                "Layers": ["layer.tar"],
            }
        ],
        separators=(",", ":"),
    ).encode()
    return _tar_bytes(
        {
            "manifest.json": manifest,
            config_name: config,
            "layer.tar": layer,
        }
    )


def _client(storage_root: Path, username: str):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    client = TestClient(create_app(storage_root=storage_root))
    response = client.post(
        "/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.test",
            "password": "correct-horse-battery-staple",
        },
    )
    assert response.status_code == 200
    client.headers["Authorization"] = f"Bearer {response.json()['access_token']}"
    return client


def _wait_for_profile(client, agent_id: str, analysis_id: str) -> dict:
    status = None
    for _ in range(500):
        response = client.get(
            f"/v1/agents/{agent_id}/profiles/{analysis_id}/status"
        )
        assert response.status_code == 200
        status = response.json()
        if status["status"] in {"completed", "partial", "failed"}:
            return status
        time.sleep(0.02)
    raise AssertionError(f"Profile did not finish: {status}")


def test_upload_registers_agent_and_automatically_publishes_real_profile(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "storage"
    client = _client(storage, "upload_owner")
    archive = _docker_archive()

    response = client.post(
        "/v1/agents/import-image",
        params={
            "agent_id": "uploaded_agent",
            "name": "Uploaded Agent",
            "domain": "security",
            "expected_frameworks": "custom-agent",
        },
        content=archive,
        headers={"Content-Type": "application/x-tar"},
    )

    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload["agent"]["status"] == "profiling"
    assert payload["agent"]["data_boundary"]["asset_source"] == "managed_upload"
    analysis_id = payload["profile"]["analysis"]["analysis_id"]

    status = _wait_for_profile(client, "uploaded_agent", analysis_id)

    assert status["status"] in {"completed", "partial"}
    assert [item["stage"] for item in status["stages"]] == [
        "inventory",
        "unpack",
        "static_extract",
        "framework_detect",
        "graph_reconstruct",
        "semantic_enrich",
        "dynamic_verify",
        "finalize",
    ]
    latest = client.get("/v1/agents/uploaded_agent/profiles/latest")
    agent = client.get("/v1/agents/uploaded_agent")
    assert latest.status_code == 200
    assert latest.json()["schema_version"] == "agent-profile-v0.2"
    assert latest.json()["image"]["digest"] == payload["agent"]["data_boundary"]["image_digest"]
    configuration_digest = payload["profile"]["analysis"]["configuration_digest"]
    assert status["configuration_digest"] == configuration_digest
    assert latest.json()["analysis"]["configuration_digest"] == configuration_digest
    assert agent.json()["data_boundary"]["profile_configuration_digest"] == configuration_digest
    latest_record = json.loads(
        (
            storage
            / "upload_owner"
            / "image_profiles"
            / "uploaded_agent"
            / "latest.json"
        ).read_text(encoding="utf-8")
    )
    assert latest_record["configuration_digest"] == configuration_digest
    checkpoint_root = (
        storage
        / "upload_owner"
        / "image_profiles"
        / "uploaded_agent"
        / latest_record["digest_suffix"]
        / "checkpoints"
    )
    assert {
        json.loads(path.read_text(encoding="utf-8"))["configuration_digest"]
        for path in checkpoint_root.glob("*.json")
    } == {configuration_digest}
    assert agent.json()["status"] == "ready"
    assert agent.json()["data_boundary"]["profile_id"] == latest.json()["profile_id"]
    assert agent.json()["data_boundary"]["profile_sha256"] == latest.headers["etag"].strip('"')

    asset_ref = payload["agent"]["data_boundary"]["asset_directory_ref"]
    asset_dir = storage / "upload_owner" / "managed_agent_assets" / asset_ref
    assert (asset_dir / "image.tar").read_bytes() == archive
    assert (asset_dir / "agent.json").is_file()
    assert not list((storage / "upload_owner" / "managed_agent_assets" / ".incoming").glob("*"))
    client.close()


def test_reupload_same_image_with_corrected_probe_module_rebuilds_profile(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "storage"
    client = _client(storage, "reconfigure_owner")
    workflow = client.app.state.service.image_profiles
    workflow._image_ref_resolver = lambda _: "local/uploaded-agent:test"

    class ConfigurationAwareProbe:
        def run(self, profile, *, target_module=None, **kwargs):
            if target_module != "app.agent":
                raise RuntimeError("configured probe module could not be imported")
            node = next(item for item in profile.nodes if item.node_type == "agent")
            events = (
                DynamicProbeEvent(
                    event_id="event:coverage",
                    event_type="coverage_target",
                    timestamp="2026-08-26T00:00:00Z",
                    name=node.name,
                    node_type="agent",
                    details={"required": True},
                ),
                DynamicProbeEvent(
                    event_id="event:started",
                    event_type="invocation_started",
                    timestamp="2026-08-26T00:00:00Z",
                    name="normal-smoke",
                ),
                DynamicProbeEvent(
                    event_id="event:corrected-probe",
                    event_type="agent_invoked",
                    timestamp="2026-08-26T00:00:01Z",
                    name=node.name,
                    node_type="agent",
                    static_node_id=node.node_id,
                    details={"executed": True},
                        trust_level="observed",
                ),
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
            )
            return DynamicProbeResult(
                profile=align_dynamic_events(profile, events),
                events=events,
            )

    workflow._dynamic_probe_factory = lambda _: ConfigurationAwareProbe()
    archive = _docker_archive(
        b"from langgraph.graph import StateGraph\n\n"
        b"graph = StateGraph(dict)\n"
        b"graph.add_node('worker', lambda value: value)\n"
    )
    first_response = client.post(
        "/v1/agents/import-image",
        params={
            "agent_id": "reconfigured_agent",
            "name": "Reconfigured Agent",
            "probe_module": "app.broken",
            "expected_frameworks": "langgraph",
        },
        content=archive,
        headers={"Content-Type": "application/x-tar"},
    )
    assert first_response.status_code == 202
    first = first_response.json()
    first_status = _wait_for_profile(
        client,
        "reconfigured_agent",
        first["profile"]["analysis"]["analysis_id"],
    )
    assert first_status["status"] == "partial"

    second_response = client.post(
        "/v1/agents/import-image",
        params={
            "agent_id": "reconfigured_agent",
            "name": "Reconfigured Agent",
            "probe_module": "app.agent",
            "expected_frameworks": "langgraph",
        },
        content=archive,
        headers={"Content-Type": "application/x-tar"},
    )
    assert second_response.status_code == 202
    second = second_response.json()
    second_status = _wait_for_profile(
        client,
        "reconfigured_agent",
        second["profile"]["analysis"]["analysis_id"],
    )

    assert second_status["status"] == "partial"
    dynamic_stage = next(
        item for item in second_status["stages"] if item["stage"] == "dynamic_verify"
    )
    assert dynamic_stage["status"] == "completed"
    second_profile = client.get(
        "/v1/agents/reconfigured_agent/profiles/latest"
    ).json()
    assert (
        "critical_dynamic_corroboration_incomplete"
        in second_profile["completeness"]["blocking_limitations"]
    )
    assert second["agent"]["data_boundary"]["image_digest"] == (
        first["agent"]["data_boundary"]["image_digest"]
    )
    assert second["profile"]["analysis"]["configuration_digest"] != (
        first["profile"]["analysis"]["configuration_digest"]
    )
    assert second["profile"]["analysis"]["analysis_id"] != (
        first["profile"]["analysis"]["analysis_id"]
    )
    descriptor_path = (
        storage
        / "reconfigure_owner"
        / "managed_agent_assets"
        / second["agent"]["data_boundary"]["asset_directory_ref"]
        / "agent.json"
    )
    assert json.loads(descriptor_path.read_text(encoding="utf-8"))["runtime"][
        "probe_module"
    ] == "app.agent"

    cached_response = client.post(
        "/v1/agents/import-image",
        params={
            "agent_id": "reconfigured_agent",
            "name": "Reconfigured Agent",
            "probe_module": "app.agent",
            "expected_frameworks": "langgraph",
        },
        content=archive,
        headers={"Content-Type": "application/x-tar"},
    )
    assert cached_response.status_code == 202
    cached = cached_response.json()["profile"]
    assert cached["cached"] is True
    assert cached["analysis"]["analysis_id"] == second["profile"]["analysis"]["analysis_id"]

    restored_response = client.post(
        "/v1/agents/import-image",
        params={
            "agent_id": "reconfigured_agent",
            "name": "Reconfigured Agent",
            "probe_module": "app.broken",
            "expected_frameworks": "langgraph",
        },
        content=archive,
        headers={"Content-Type": "application/x-tar"},
    )
    assert restored_response.status_code == 202
    restored = restored_response.json()["profile"]
    assert restored["cached"] is True
    assert restored["analysis"]["analysis_id"] == first["profile"]["analysis"]["analysis_id"]
    latest = client.get("/v1/agents/reconfigured_agent/profiles/latest")
    assert latest.status_code == 200
    assert (
        latest.json()["analysis"]["configuration_digest"]
        == first["profile"]["analysis"]["configuration_digest"]
    )
    client.close()



    storage = tmp_path / "storage"
    client = _client(storage, "busy_owner")
    registration = client.post(
        "/v1/agents",
        json={
            "agent_id": "busy_agent",
            "name": "Busy Agent",
            "status": "ready",
        },
    )
    assert registration.status_code == 200
    audit_path = storage / "busy_owner" / "audits" / "audit-active" / "audit.json"
    audit_path.parent.mkdir(parents=True)
    audit_path.write_text(
        json.dumps(
            {
                "schema_version": "audit-run-v0.1",
                "audit_id": "audit-active",
                "tenant_id": "busy_owner",
                "agent_id": "busy_agent",
                "state": "planning",
                "task_ref": "task.json",
                "source_material_ref": "source.json",
                "source_snapshot_sha256": "a" * 64,
            }
        ),
        encoding="utf-8",
    )

    response = client.delete("/v1/agents/busy_agent")

    assert response.status_code == 409
    assert response.json()["detail"]["error_code"] == "agent_has_active_audits"
    assert client.get("/v1/agents/busy_agent").status_code == 200
    client.close()


def test_upload_rejects_invalid_archive_without_registering_agent(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path / "storage", "invalid_upload_owner")

    response = client.post(
        "/v1/agents/import-image",
        params={"agent_id": "broken_agent", "name": "Broken Agent"},
        content=b"not a Docker archive",
        headers={"Content-Type": "application/x-tar"},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["error_code"] == "docker_archive_invalid"
    assert client.get("/v1/agents/broken_agent").status_code == 404
    client.close()


def test_managed_upload_is_visible_with_configured_asset_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    configured_root = tmp_path / "configured-agents"
    configured_root.mkdir()
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(configured_root))
    client = _client(tmp_path / "storage", "mixed_owner")

    response = client.post(
        "/v1/agents/import-image",
        params={"agent_id": "managed_agent", "name": "Managed Agent"},
        content=_docker_archive(),
        headers={"Content-Type": "application/x-tar"},
    )

    assert response.status_code == 202
    _wait_for_profile(
        client,
        "managed_agent",
        response.json()["profile"]["analysis"]["analysis_id"],
    )
    assert [item["agent_id"] for item in client.get("/v1/agents").json()] == [
        "managed_agent"
    ]
    client.close()


def test_agent_list_hides_unfinished_profiles_and_is_tenant_private(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "storage"
    owner = _client(storage, "asset_owner")
    other = _client(storage, "asset_other")
    registration = {
        "agent_id": "pending_agent",
        "name": "Pending Agent",
        "integration_type": "docker",
        "status": "profiling",
    }

    assert owner.post("/v1/agents", json=registration).status_code == 200
    assert owner.get("/v1/agents").json() == []
    assert other.get("/v1/agents").json() == []

    registration["status"] = "ready"
    assert owner.post("/v1/agents", json=registration).status_code == 200
    assert [item["agent_id"] for item in owner.get("/v1/agents").json()] == [
        "pending_agent"
    ]
    assert other.get("/v1/agents").json() == []
    owner.close()
    other.close()


def test_delete_agent_removes_managed_image_profile_and_index(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "storage"
    client = _client(storage, "delete_owner")
    response = client.post(
        "/v1/agents/import-image",
        params={"agent_id": "delete_agent", "name": "Delete Agent"},
        content=_docker_archive(),
        headers={"Content-Type": "application/x-tar"},
    )
    payload = response.json()
    _wait_for_profile(
        client,
        "delete_agent",
        payload["profile"]["analysis"]["analysis_id"],
    )
    version_suffix = payload["profile"]["analysis"]["analysis_id"].rsplit(":", 1)[-1]
    image_suffix = payload["agent"]["data_boundary"]["image_digest"].removeprefix("sha256:")[:16]
    assert version_suffix != image_suffix
    with client.app.state.service.storage.image_profile_lease(
        "delete_owner",
        "delete_agent",
        version_suffix,
    ) as acquired:
        assert acquired
        blocked = client.delete("/v1/agents/delete_agent")
        assert blocked.status_code == 409
        assert blocked.json()["detail"]["error_code"] == "agent_profile_active"

    deleted = None
    for _ in range(50):
        deleted = client.delete("/v1/agents/delete_agent")
        if deleted.status_code != 409:
            break
        time.sleep(0.02)

    assert deleted is not None
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert client.get("/v1/agents/delete_agent").status_code == 404
    assert client.get("/v1/agents").json() == []
    assert not (
        storage / "delete_owner" / "managed_agent_assets" / "delete_agent"
    ).exists()
    assert not (storage / "delete_owner" / "image_profiles" / "delete_agent").exists()
    assert not (
        storage
        / "delete_owner"
        / "agent_asset_index"
        / "current"
        / "delete_agent.json"
    ).exists()
    client.close()
