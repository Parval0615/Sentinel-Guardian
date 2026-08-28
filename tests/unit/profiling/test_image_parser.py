from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest

from redsentinel.profiling import (
    ImageArtifactError,
    ImageExtractionLimits,
    parse_image_artifact,
)


pytestmark = pytest.mark.unit


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _tar_bytes(entries: list[tuple[str, bytes | str | None, str]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, payload, kind in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o755 if kind == "directory" else 0o644
            if kind == "file":
                assert isinstance(payload, bytes)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            elif kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                assert isinstance(payload, str)
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                archive.addfile(info)
            elif kind == "hardlink":
                assert isinstance(payload, str)
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                archive.addfile(info)
            else:
                raise AssertionError(f"unsupported fixture kind: {kind}")
    return output.getvalue()


def _config_bytes(layers: list[bytes] | None = None) -> bytes:
    return _json_bytes(
        {
            "architecture": "arm64",
            "config": {
                "Cmd": ["serve"],
                "Entrypoint": ["python", "-m", "agent"],
                "Env": ["API_TOKEN=top-secret", "EMPTY=", "PATH=/usr/bin", "API_TOKEN=rotated"],
                "WorkingDir": "/workspace",
            },
            "created": "2026-08-21T00:00:00Z",
            "os": "linux",
            "rootfs": {
                "diff_ids": [f"sha256:{hashlib.sha256(layer).hexdigest()}" for layer in layers or []],
                "type": "layers",
            },
            "variant": "v8",
        }
    )


def _docker_archive(
    path: Path,
    layers: list[bytes],
    config: bytes | None = None,
    *,
    compress_layers: bool = False,
) -> str:
    config = config or _config_bytes(layers)
    config_digest = hashlib.sha256(config).hexdigest()
    stored_layers = [gzip.compress(layer, mtime=0) for layer in layers] if compress_layers else layers
    layer_names = (
        [f"blobs/sha256/{hashlib.sha256(layer).hexdigest()}" for layer in stored_layers]
        if compress_layers
        else [f"layer-{index}/layer.tar" for index in range(len(layers))]
    )
    manifest = _json_bytes([{"Config": f"{config_digest}.json", "Layers": layer_names, "RepoTags": ["test:latest"]}])
    with tarfile.open(path, "w") as archive:
        for name, content in [
            ("manifest.json", manifest),
            (f"{config_digest}.json", config),
            *zip(layer_names, stored_layers, strict=True),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return f"sha256:{config_digest}"


def _write_blob(layout: Path, content: bytes) -> dict[str, object]:
    digest = hashlib.sha256(content).hexdigest()
    path = layout / "blobs" / "sha256" / digest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {"digest": f"sha256:{digest}", "size": len(content)}


def _oci_layout(path: Path, layers: list[bytes], config: bytes | None = None) -> str:
    path.mkdir()
    (path / "oci-layout").write_bytes(_json_bytes({"imageLayoutVersion": "1.0.0"}))
    config_descriptor = _write_blob(path, config or _config_bytes(layers))
    config_descriptor["mediaType"] = "application/vnd.oci.image.config.v1+json"
    layer_descriptors = []
    for layer in layers:
        descriptor = _write_blob(path, layer)
        descriptor["mediaType"] = "application/vnd.oci.image.layer.v1.tar"
        layer_descriptors.append(descriptor)
    manifest = _json_bytes(
        {
            "config": config_descriptor,
            "layers": layer_descriptors,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }
    )
    manifest_descriptor = _write_blob(path, manifest)
    manifest_descriptor.update(
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
        }
    )
    (path / "index.json").write_bytes(
        _json_bytes(
            {
                "manifests": [manifest_descriptor],
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2,
            }
        )
    )
    return str(manifest_descriptor["digest"])


@pytest.mark.parametrize("artifact_kind", ["docker_archive", "oci_layout"])
def test_parses_image_metadata_and_builds_read_only_rootfs(tmp_path: Path, artifact_kind: str) -> None:
    layer = _tar_bytes(
        [
            ("workspace", None, "directory"),
            ("workspace/agent.py", b"print('ok')\n", "file"),
            ("workspace/current.py", "agent.py", "symlink"),
            ("workspace/copy.py", "workspace/agent.py", "hardlink"),
        ]
    )
    artifact = tmp_path / ("image.tar" if artifact_kind == "docker_archive" else "oci")
    expected_digest = (
        _docker_archive(artifact, [layer])
        if artifact_kind == "docker_archive"
        else _oci_layout(artifact, [layer])
    )

    result = parse_image_artifact(artifact, tmp_path / "output", image_type=artifact_kind)

    assert result.image_digest == expected_digest
    assert result.config.entrypoint == ("python", "-m", "agent")
    assert result.config.cmd == ("serve",)
    assert result.config.working_dir == "/workspace"
    assert result.config.platform == "linux/arm64/v8"
    assert result.config.created == "2026-08-21T00:00:00Z"
    assert result.config.env_keys == ("API_TOKEN", "EMPTY", "PATH")
    assert "top-secret" not in repr(result)
    assert (result.rootfs_path / "workspace" / "agent.py").read_bytes() == b"print('ok')\n"
    assert (result.rootfs_path / "workspace" / "current.py").readlink().as_posix() == "agent.py"
    assert (result.rootfs_path / "workspace" / "copy.py").read_bytes() == b"print('ok')\n"
    assert stat.S_IMODE(result.rootfs_path.stat().st_mode) & 0o222 == 0
    assert all(
        path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o222 == 0
        for path in result.rootfs_path.rglob("*")
    )
    assert [record.path for record in result.files] == [
        "workspace",
        "workspace/agent.py",
        "workspace/copy.py",
        "workspace/current.py",
    ]
    assert len(result.layers) == 1
    assert result.layers[0].digest == f"sha256:{hashlib.sha256(layer).hexdigest()}"


def test_parses_gzip_compressed_docker_blob_and_validates_diff_id(tmp_path: Path) -> None:
    layer = _tar_bytes([("workspace/agent.py", b"print('ok')\n", "file")])
    artifact = tmp_path / "image.tar"
    _docker_archive(artifact, [layer], compress_layers=True)

    result = parse_image_artifact(artifact, tmp_path / "output")

    assert result.layers[0].digest == f"sha256:{hashlib.sha256(layer).hexdigest()}"
    assert (result.rootfs_path / "workspace" / "agent.py").read_bytes() == b"print('ok')\n"


def test_applies_normal_and_opaque_whiteouts_before_same_layer_files(tmp_path: Path) -> None:
    lower = _tar_bytes(
        [
            ("app", None, "directory"),
            ("app/delete.txt", b"delete", "file"),
            ("app/keep.txt", b"keep", "file"),
            ("cache", None, "directory"),
            ("cache/old-a", b"a", "file"),
            ("cache/old-b", b"b", "file"),
        ]
    )
    upper = _tar_bytes(
        [
            ("cache/new", b"new", "file"),
            ("app/.wh.delete.txt", b"", "file"),
            ("cache/.wh..wh..opq", b"", "file"),
        ]
    )
    artifact = tmp_path / "image.tar"
    _docker_archive(artifact, [lower, upper])

    result = parse_image_artifact(artifact, tmp_path / "output")

    assert not (result.rootfs_path / "app" / "delete.txt").exists()
    assert (result.rootfs_path / "app" / "keep.txt").read_text() == "keep"
    assert sorted(path.name for path in (result.rootfs_path / "cache").iterdir()) == ["new"]
    assert result.layers[1].whiteouts == ("app/delete.txt",)
    assert result.layers[1].opaque_directories == ("cache",)
    assert {record.path for record in result.files} == {"app", "app/keep.txt", "cache", "cache/new"}


def test_replacing_one_hardlink_does_not_mutate_its_lower_layer_peer(tmp_path: Path) -> None:
    lower = _tar_bytes(
        [
            ("original", b"lower", "file"),
            ("peer", "original", "hardlink"),
        ]
    )
    upper = _tar_bytes([("original", b"upper", "file")])
    artifact = tmp_path / "image.tar"
    _docker_archive(artifact, [lower, upper])

    result = parse_image_artifact(artifact, tmp_path / "output")

    assert (result.rootfs_path / "original").read_bytes() == b"upper"
    assert (result.rootfs_path / "peer").read_bytes() == b"lower"


def test_selects_platform_through_nested_oci_index(tmp_path: Path) -> None:
    layer = _tar_bytes([("agent.py", b"print('ok')\n", "file")])
    layout = tmp_path / "oci"
    expected_digest = _oci_layout(layout, [layer])
    index_path = layout / "index.json"
    index = json.loads(index_path.read_bytes())
    nested_index = _json_bytes(
        {
            "manifests": index["manifests"],
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "schemaVersion": 2,
        }
    )
    nested_descriptor = _write_blob(layout, nested_index)
    nested_descriptor["mediaType"] = "application/vnd.oci.image.index.v1+json"
    index_path.write_bytes(
        _json_bytes(
            {
                "manifests": [nested_descriptor],
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2,
            }
        )
    )

    result = parse_image_artifact(layout, tmp_path / "output", platform="linux/arm64/v8")

    assert result.image_digest == expected_digest
    assert (result.rootfs_path / "agent.py").read_bytes() == b"print('ok')\n"


@pytest.mark.parametrize(
    ("name", "payload", "kind"),
    [
        ("../outside", b"x", "file"),
        ("/absolute", b"x", "file"),
        ("C:/drive", b"x", "file"),
        ("escape", "../../outside", "symlink"),
        ("escape", "../outside", "hardlink"),
    ],
)
def test_rejects_unsafe_layer_paths_and_links(
    tmp_path: Path,
    name: str,
    payload: bytes | str,
    kind: str,
) -> None:
    artifact = tmp_path / "image.tar"
    _docker_archive(artifact, [_tar_bytes([(name, payload, kind)])])
    output = tmp_path / "output"

    with pytest.raises(ImageArtifactError):
        parse_image_artifact(artifact, output)

    assert not (tmp_path / "outside").exists()
    assert not list(output.glob(".image-unpack-*"))


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
@pytest.mark.parametrize("target", ["../../outside", "C:/outside"])
def test_rejects_unsafe_symlink_and_hardlink_targets(tmp_path: Path, kind: str, target: str) -> None:
    artifact = tmp_path / "image.tar"
    _docker_archive(artifact, [_tar_bytes([("link", target, kind)])])
    output = tmp_path / "output"

    with pytest.raises(ImageArtifactError):
        parse_image_artifact(artifact, output)

    assert list(output.iterdir()) == []


@pytest.mark.skipif(os.sep == "\\", reason="Backslash is a path separator on Windows")
def test_allows_posix_filename_with_literal_backslash(tmp_path: Path) -> None:
    artifact = tmp_path / "image.tar"
    _docker_archive(artifact, [_tar_bytes([("systemd\\x2dunit", b"ok", "file")])])

    result = parse_image_artifact(artifact, tmp_path / "output")

    assert (result.rootfs_path / "systemd\\x2dunit").read_bytes() == b"ok"


def test_rewrites_absolute_symlink_to_stay_inside_rootfs(tmp_path: Path) -> None:
    layer = _tar_bytes(
        [
            ("usr/bin/tool", b"ok", "file"),
            ("etc/alternatives/tool", "/usr/bin/tool", "symlink"),
        ]
    )
    artifact = tmp_path / "image.tar"
    _docker_archive(artifact, [layer])

    result = parse_image_artifact(artifact, tmp_path / "output")
    link = result.rootfs_path / "etc" / "alternatives" / "tool"

    assert link.readlink().as_posix() == "../../usr/bin/tool"
    assert link.read_bytes() == b"ok"


def test_rejects_write_through_symlink(tmp_path: Path) -> None:
    layer = _tar_bytes([("link", "target", "symlink"), ("link/child", b"x", "file")])
    artifact = tmp_path / "image.tar"
    _docker_archive(artifact, [layer])

    with pytest.raises(ImageArtifactError, match="symlink"):
        parse_image_artifact(artifact, tmp_path / "output")


def test_rejects_unsafe_outer_docker_archive_member(tmp_path: Path) -> None:
    artifact = tmp_path / "image.tar"
    with tarfile.open(artifact, "w") as archive:
        info = tarfile.TarInfo("../outside")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))

    with pytest.raises(ImageArtifactError, match="traversal"):
        parse_image_artifact(artifact, tmp_path / "output")

    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize(
    ("layers", "limits", "match"),
    [
        (
            [_tar_bytes([("one", b"1", "file")]), _tar_bytes([("two", b"2", "file")])],
            ImageExtractionLimits(max_layers=1),
            "layer count",
        ),
        (
            [_tar_bytes([("one", b"1", "file"), ("two", b"2", "file")])],
            ImageExtractionLimits(max_files=1),
            "file count",
        ),
        (
            [_tar_bytes([("large", b"12", "file")])],
            ImageExtractionLimits(max_single_file_size=1),
            "single-file",
        ),
        (
            [_tar_bytes([("one", b"12", "file"), ("two", b"34", "file")])],
            ImageExtractionLimits(max_total_extracted_size=3),
            "total extracted",
        ),
        (
            [_tar_bytes([("one/two/three", b"x", "file")])],
            ImageExtractionLimits(max_path_depth=2),
            "depth",
        ),
    ],
)
def test_enforces_resource_limits(
    tmp_path: Path,
    layers: list[bytes],
    limits: ImageExtractionLimits,
    match: str,
) -> None:
    artifact = tmp_path / "image.tar"
    _docker_archive(artifact, layers)
    output = tmp_path / "output"

    with pytest.raises(ImageArtifactError, match=match):
        parse_image_artifact(artifact, output, limits=limits)

    assert list(output.iterdir()) == []


def test_rejects_docker_layer_that_does_not_match_config_diff_id(tmp_path: Path) -> None:
    layer = _tar_bytes([("safe", b"x", "file")])
    config = _config_bytes([_tar_bytes([("different", b"y", "file")])])
    artifact = tmp_path / "image.tar"
    _docker_archive(artifact, [layer], config=config)
    output = tmp_path / "output"

    with pytest.raises(ImageArtifactError, match="layer digest mismatch"):
        parse_image_artifact(artifact, output)

    assert list(output.iterdir()) == []


def test_rejects_tampered_oci_blob_before_writing_rootfs(tmp_path: Path) -> None:
    layout = tmp_path / "oci"
    _oci_layout(layout, [_tar_bytes([("safe", b"x", "file")])])
    layer_blob = max((layout / "blobs" / "sha256").iterdir(), key=lambda path: path.stat().st_size)
    layer_blob.write_bytes(layer_blob.read_bytes() + b"tampered")
    output = tmp_path / "output"

    with pytest.raises(ImageArtifactError, match="size mismatch|digest mismatch"):
        parse_image_artifact(layout, output)

    assert not list(output.glob(".image-unpack-*"))
