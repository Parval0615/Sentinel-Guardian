from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from redsentinel.application.engine.local_image_ref import (
    LocalDockerImageRefResolver,
    LocalImageResolutionError,
)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _archive(tmp_path: Path) -> tuple[Path, str, str]:
    repo_tag = "local/safe-agent:test"
    config = _json_bytes(
        {
            "architecture": "arm64",
            "os": "linux",
            "config": {"Entrypoint": ["python", "-m", "safe_agent"]},
            "rootfs": {"type": "layers", "diff_ids": []},
        }
    )
    config_digest = hashlib.sha256(config).hexdigest()
    image_manifest = _json_bytes(
        {
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{config_digest}",
                "size": len(config),
            },
            "layers": [],
        }
    )
    image_id = f"sha256:{hashlib.sha256(image_manifest).hexdigest()}"
    manifest = _json_bytes(
        [
            {
                "Config": f"blobs/sha256/{config_digest}",
                "RepoTags": [repo_tag],
                "Layers": [],
            }
        ]
    )
    index = _json_bytes(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "digest": image_id,
                    "annotations": {
                        "io.containerd.image.name": f"docker.io/{repo_tag}",
                    },
                }
            ],
        }
    )
    path = tmp_path / "image.tar"
    with tarfile.open(path, "w") as archive:
        for name, content in (
            ("manifest.json", manifest),
            ("index.json", index),
            (f"blobs/sha256/{config_digest}", config),
            (f"blobs/sha256/{image_id[7:]}", image_manifest),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return path, repo_tag, image_id


def _inventory(path: Path) -> dict[str, object]:
    digest = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    return {
        "record": {"image_digest": digest},
        "descriptor": {
            "schema_version": "agent-directory-v0.1",
            "agent_id": "safe_agent",
            "name": "Safe Agent",
            "image": {
                "type": "docker_archive",
                "path": "image.tar",
                "digest": digest,
            },
            "platform": "linux/arm64",
        },
        "image_path": str(path),
    }


def _inspect(image_id: str) -> str:
    return json.dumps(
        [
            {
                "Id": image_id,
                "Os": "linux",
                "Architecture": "arm64",
            }
        ]
    )


def test_resolver_uses_verified_immutable_id_without_loading_existing_image(
    tmp_path: Path,
) -> None:
    path, repo_tag, image_id = _archive(tmp_path)
    commands: list[list[str]] = []

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, _inspect(image_id), "")

    resolved = LocalDockerImageRefResolver("/safe/docker", runner=runner)(
        _inventory(path)
    )

    assert resolved == image_id
    assert commands == [["/safe/docker", "image", "inspect", repo_tag]]


def test_resolver_loads_missing_archive_then_rechecks_identity(tmp_path: Path) -> None:
    path, repo_tag, image_id = _archive(tmp_path)
    responses = iter(
        [
            subprocess.CompletedProcess([], 1, "", "not found"),
            subprocess.CompletedProcess([], 0, f"Loaded image: {repo_tag}\n", ""),
            subprocess.CompletedProcess([], 0, _inspect(image_id), ""),
        ]
    )
    commands: list[list[str]] = []

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        response = next(responses)
        return subprocess.CompletedProcess(
            command,
            response.returncode,
            response.stdout,
            response.stderr,
        )

    resolved = LocalDockerImageRefResolver("/safe/docker", runner=runner)(
        _inventory(path)
    )

    assert resolved == image_id
    assert commands == [
        ["/safe/docker", "image", "inspect", repo_tag],
        ["/safe/docker", "load", "--input", str(path)],
        ["/safe/docker", "image", "inspect", repo_tag],
    ]


def test_resolver_rejects_retargeted_local_tag_before_probe(tmp_path: Path) -> None:
    path, _, _ = _archive(tmp_path)

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            0,
            _inspect(f"sha256:{'f' * 64}"),
            "",
        )

    with pytest.raises(LocalImageResolutionError, match="does not match"):
        LocalDockerImageRefResolver("/safe/docker", runner=runner)(_inventory(path))


def test_resolver_rejects_archive_changed_after_indexing(tmp_path: Path) -> None:
    path, _, _ = _archive(tmp_path)
    inventory = _inventory(path)
    path.write_bytes(path.read_bytes() + b"changed")

    with pytest.raises(LocalImageResolutionError, match="changed"):
        LocalDockerImageRefResolver("/safe/docker")(inventory)
