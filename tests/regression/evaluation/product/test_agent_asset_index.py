import json
from pathlib import Path

import pytest

from redsentinel.application.engine.app import create_app
from redsentinel.apps import desktop_launcher


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
    client.headers["Authorization"] = (
        f"Bearer {response.json()['access_token']}"
    )
    return client


def _docker_asset(
    root: Path,
    directory_name: str,
    *,
    agent_id: str,
    image_bytes: bytes = b"docker image archive",
    expected_frameworks: list[str] | None = None,
) -> Path:
    directory = root / directory_name
    directory.mkdir(parents=True)
    (directory / "agent.json").write_text(
        json.dumps(
            {
                "schema_version": "agent-directory-v0.1",
                "agent_id": agent_id,
                "name": f"Agent {directory_name}",
                "expected_frameworks": expected_frameworks or [],
                "image": {
                    "type": "docker_archive",
                    "path": "image.tar",
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (directory / "image.tar").write_bytes(image_bytes)
    return directory


def test_openmanus_image_uses_real_runtime_adapter(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    _docker_asset(
        root,
        "openmanus",
        agent_id="openmanus_agent",
        expected_frameworks=["OpenManus"],
    )
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    client = _client(tmp_path / "storage", "openmanus_owner")

    agent = client.get("/v1/agents/openmanus_agent")

    assert agent.status_code == 200
    assert agent.json()["adapter_type"] == "openmanus"
    assert agent.json()["integration_type"] == "docker"


def _oci_asset(root: Path, directory_name: str, *, agent_id: str) -> Path:
    directory = root / directory_name
    layout = directory / "image"
    (layout / "blobs" / "sha256").mkdir(parents=True)
    (layout / "oci-layout").write_text(
        '{"imageLayoutVersion":"1.0.0"}',
        encoding="utf-8",
    )
    (layout / "index.json").write_text('{"manifests":[]}', encoding="utf-8")
    (layout / "blobs" / "sha256" / "content").write_bytes(b"oci-content-v1")
    (directory / "agent.json").write_text(
        json.dumps(
            {
                "schema_version": "agent-directory-v0.1",
                "agent_id": agent_id,
                "name": "OCI Agent",
                "image": {"type": "oci_layout", "path": "image"},
            }
        ),
        encoding="utf-8",
    )
    return directory


def test_desktop_agent_root_is_app_sibling_agents(monkeypatch) -> None:
    executable = Path("/Applications/Distribution/Sentinel Guardian.app/Contents/MacOS/sentinel")
    monkeypatch.setattr(desktop_launcher.sys, "executable", str(executable))

    assert desktop_launcher._agent_root() == (
        Path("/Applications/Distribution/agents")
    )


def test_deleted_configured_asset_is_not_restored_by_refresh(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    _docker_asset(root, "deletable", agent_id="deletable_agent")
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    storage = tmp_path / "storage"
    client = _client(storage, "delete_owner")

    assert client.get("/v1/agents/deletable_agent").status_code == 200
    current_index = (
        storage
        / "delete_owner"
        / "agent_asset_index"
        / "current"
        / "deletable_agent.json"
    )
    legacy_record = json.loads(current_index.read_text(encoding="utf-8"))
    legacy_record.pop("profile_version_digest")
    current_index.write_text(json.dumps(legacy_record), encoding="utf-8")

    deleted = client.delete("/v1/agents/deletable_agent")

    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert client.get("/v1/agents").json() == []
    assert client.get("/v1/agents/deletable_agent").status_code == 404
    assert (
        storage
        / "delete_owner"
        / "agent_asset_index"
        / "suppressed"
        / "deletable_agent.json"
    ).is_file()
    client.close()


def test_empty_configured_root_is_authoritative(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("RED_SENTINEL_AGENT_ROOT", raising=False)
    client = _client(tmp_path / "storage", "empty_owner")
    created = client.post(
        "/v1/agents",
        json={"agent_id": "direct_agent", "name": "Direct Agent"},
    )
    assert created.status_code == 200

    root = tmp_path / "agents"
    root.mkdir()
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))

    assert client.get("/v1/agents").json() == []
    assert client.get("/v1/agents/index-errors").json() == []


def test_chinese_directory_and_bad_directory_are_isolated(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    _docker_asset(root, "电商", agent_id="ecommerce_agent")
    damaged = root / "损坏"
    damaged.mkdir()
    (damaged / "agent.json").write_text("{not-json", encoding="utf-8")
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    client = _client(tmp_path / "storage", "index_owner")

    errors = client.get("/v1/agents/index-errors")
    response = client.get("/v1/agents")

    assert response.status_code == 200
    assert [
        (item["agent_id"], item["status"], item["data_boundary"]["profile_status"])
        for item in response.json()
    ] == [("ecommerce_agent", "profiling", "profile_pending")]
    assert client.get("/v1/agents/ecommerce_agent").status_code == 200
    assert errors.status_code == 200
    assert [(item["directory_name"], item["code"]) for item in errors.json()] == [
        ("损坏", "descriptor_invalid")
    ]
    assert str(tmp_path) not in errors.text


def test_only_direct_children_with_ascii_ids_and_safe_paths_are_indexed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    _docker_asset(root, "合法目录", agent_id="valid_agent")
    _docker_asset(root / "分组", "nested", agent_id="nested_agent")
    invalid_id = _docker_asset(root, "中文标识", agent_id="temporary")
    descriptor = json.loads(
        (invalid_id / "agent.json").read_text(encoding="utf-8")
    )
    descriptor["agent_id"] = "中文_agent"
    (invalid_id / "agent.json").write_text(
        json.dumps(descriptor, ensure_ascii=False),
        encoding="utf-8",
    )
    escaped = _docker_asset(root, "路径穿越", agent_id="escaped_path_agent")
    descriptor = json.loads(
        (escaped / "agent.json").read_text(encoding="utf-8")
    )
    descriptor["image"]["path"] = "../outside.tar"
    (escaped / "agent.json").write_text(
        json.dumps(descriptor, ensure_ascii=False),
        encoding="utf-8",
    )
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    client = _client(tmp_path / "storage", "constraint_owner")

    errors = client.get("/v1/agents/index-errors")
    agents = client.get("/v1/agents")

    assert [item["agent_id"] for item in agents.json()] == ["valid_agent"]
    assert client.get("/v1/agents/valid_agent").status_code == 200
    assert {
        (item["directory_name"], item["code"])
        for item in errors.json()
    } == {
        ("中文标识", "agent_id_invalid"),
        ("分组", "descriptor_missing"),
        ("路径穿越", "descriptor_invalid"),
    }


def test_symlinked_agent_directory_outside_root_is_rejected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    root.mkdir()
    outside = tmp_path / "outside-agent"
    _docker_asset(tmp_path, "outside-agent", agent_id="outside_agent")
    (root / "linked-agent").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    client = _client(tmp_path / "storage", "symlink_owner")

    assert client.get("/v1/agents").json() == []
    errors = client.get("/v1/agents/index-errors").json()
    assert [(item["directory_name"], item["code"]) for item in errors] == [
        ("linked-agent", "directory_symlink_rejected")
    ]


def test_image_must_resolve_within_agent_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    directory = root / "escaped"
    directory.mkdir(parents=True)
    outside = tmp_path / "outside.tar"
    outside.write_bytes(b"sensitive image")
    (directory / "image.tar").symlink_to(outside)
    (directory / "agent.json").write_text(
        json.dumps(
            {
                "schema_version": "agent-directory-v0.1",
                "agent_id": "escaped_agent",
                "name": "Escaped Agent",
                "image": {
                    "type": "docker_archive",
                    "path": "image.tar",
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    client = _client(tmp_path / "storage", "escape_owner")

    assert client.get("/v1/agents").json() == []
    errors = client.get("/v1/agents/index-errors").json()
    assert errors[0]["code"] == "image_outside_directory"
    assert str(outside) not in json.dumps(errors)


def test_same_digest_is_idempotent_and_change_creates_index_version(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    directory = _docker_asset(root, "版本化", agent_id="versioned_agent")
    storage = tmp_path / "storage"
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    client = _client(storage, "version_owner")

    assert client.get("/v1/agents/index-errors").status_code == 200
    first = client.get("/v1/agents/versioned_agent").json()
    current_path = (
        storage
        / "version_owner"
        / "agent_asset_index"
        / "current"
        / "versioned_agent.json"
    )
    first_record = current_path.read_text(encoding="utf-8")
    assert client.get("/v1/agents/index-errors").status_code == 200
    second = client.get("/v1/agents/versioned_agent").json()

    assert second == first
    assert current_path.read_text(encoding="utf-8") == first_record
    assert len(
        list(
            (
                storage
                / "version_owner"
                / "agent_asset_index"
                / "versions"
                / "versioned_agent"
            ).glob("*.json")
        )
    ) == 1

    (directory / "image.tar").write_bytes(b"docker image archive v2")
    assert client.get("/v1/agents/index-errors").status_code == 200
    changed = client.get("/v1/agents/versioned_agent").json()
    versions = list(
        (
            storage
            / "version_owner"
            / "agent_asset_index"
            / "versions"
            / "versioned_agent"
        ).glob("*.json")
    )

    assert changed["data_boundary"]["image_digest"] != (
        first["data_boundary"]["image_digest"]
    )
    assert changed["data_boundary"]["material_version_id"] != (
        first["data_boundary"]["material_version_id"]
    )
    assert changed["data_boundary"]["profile_version_id"] != (
        first["data_boundary"]["profile_version_id"]
    )
    assert len(versions) == 2


def test_profile_configuration_change_keeps_material_and_creates_profile_version(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    directory = _docker_asset(root, "配置版本", agent_id="configured_agent")
    descriptor_path = directory / "agent.json"
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    descriptor["runtime"] = {"probe_module": "app.broken"}
    descriptor_path.write_text(json.dumps(descriptor), encoding="utf-8")
    storage = tmp_path / "storage"
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    client = _client(storage, "configuration_owner")

    assert client.get("/v1/agents/index-errors").status_code == 200
    first = client.get("/v1/agents/configured_agent").json()["data_boundary"]
    descriptor["runtime"]["probe_module"] = "app.agent"
    descriptor_path.write_text(json.dumps(descriptor), encoding="utf-8")
    assert client.get("/v1/agents/index-errors").status_code == 200
    second = client.get("/v1/agents/configured_agent").json()["data_boundary"]

    assert second["image_digest"] == first["image_digest"]
    assert second["material_version_id"] == first["material_version_id"]
    assert second["profile_configuration_digest"] != first["profile_configuration_digest"]
    assert second["profile_version_id"] != first["profile_version_id"]
    assert len(
        list(
            (
                storage
                / "configuration_owner"
                / "agent_asset_index"
                / "versions"
                / "configured_agent"
            ).glob("*.json")
        )
    ) == 2
    client.close()


def test_corrupt_index_record_is_isolated_to_its_agent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    _docker_asset(root, "损坏索引", agent_id="broken_index_agent")
    _docker_asset(root, "正常索引", agent_id="healthy_index_agent")
    storage = tmp_path / "storage"
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    client = _client(storage, "index_recovery_owner")
    assert client.get("/v1/agents/index-errors").status_code == 200
    assert client.get("/v1/agents/broken_index_agent").status_code == 200
    assert client.get("/v1/agents/healthy_index_agent").status_code == 200

    current = (
        storage
        / "index_recovery_owner"
        / "agent_asset_index"
        / "current"
        / "broken_index_agent.json"
    )
    current.write_text("{invalid", encoding="utf-8")

    errors = client.get("/v1/agents/index-errors")

    assert {
        item["agent_id"] for item in client.get("/v1/agents").json()
    } == {"broken_index_agent", "healthy_index_agent"}
    assert client.get("/v1/agents/healthy_index_agent").status_code == 200
    assert [(item["directory_name"], item["code"]) for item in errors.json()] == [
        ("损坏索引", "asset_index_failed")
    ]


def test_oci_digest_tracks_layout_content(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    directory = _oci_asset(root, "oci", agent_id="oci_agent")
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    client = _client(tmp_path / "storage", "oci_owner")

    assert client.get("/v1/agents/index-errors").status_code == 200
    first = client.get("/v1/agents/oci_agent").json()
    (directory / "image" / "blobs" / "sha256" / "content").write_bytes(
        b"oci-content-v2"
    )
    assert client.get("/v1/agents/index-errors").status_code == 200
    second = client.get("/v1/agents/oci_agent").json()

    assert first["data_boundary"]["image_type"] == "oci_layout"
    assert (
        first["data_boundary"]["image_digest"]
        != second["data_boundary"]["image_digest"]
    )


def test_index_records_and_errors_are_tenant_isolated(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "agents"
    _docker_asset(root, "共享目录", agent_id="shared_agent")
    bad = root / "bad"
    bad.mkdir()
    monkeypatch.setenv("RED_SENTINEL_AGENT_ROOT", str(root))
    storage = tmp_path / "storage"

    tenant_a = _client(storage, "tenant_a")
    tenant_b = _client(storage, "tenant_b")
    assert tenant_a.get("/v1/agents/index-errors").status_code == 200
    assert tenant_b.get("/v1/agents/index-errors").status_code == 200
    assert tenant_a.get("/v1/agents/shared_agent").json()["tenant_id"] == "tenant_a"
    assert tenant_b.get("/v1/agents/shared_agent").json()["tenant_id"] == "tenant_b"

    for tenant_id in ("tenant_a", "tenant_b"):
        tenant_root = storage / tenant_id / "agent_asset_index"
        assert (tenant_root / "current" / "shared_agent.json").is_file()
        errors = json.loads(
            (tenant_root / "errors.json").read_text(encoding="utf-8")
        )
        assert errors["errors"][0]["code"] == "descriptor_missing"
