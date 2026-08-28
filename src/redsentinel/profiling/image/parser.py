from __future__ import annotations

import gzip
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import tarfile
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from redsentinel.profiling.image.models import (
    FileRecord,
    ImageArtifactError,
    ImageArtifactType,
    ImageExtractionLimits,
    LayerRecord,
    ParsedImageArtifact,
    SanitizedImageConfig,
)


_DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_OCI_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_OCI_INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}


@dataclass
class _Budget:
    limits: ImageExtractionLimits
    files: int = 0
    extracted_size: int = 0

    def account_member(self, size: int) -> None:
        self.files += 1
        if self.files > self.limits.max_files:
            raise ImageArtifactError("image exceeds the maximum file count")
        if size > self.limits.max_single_file_size:
            raise ImageArtifactError("image member exceeds the maximum single-file size")
        self.extracted_size += size
        if self.extracted_size > self.limits.max_total_extracted_size:
            raise ImageArtifactError("image exceeds the maximum total extracted size")


@dataclass(frozen=True)
class _LayerSource:
    digest: str
    size: int
    opener: Any


def _sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _load_json_bytes(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImageArtifactError(f"{label} is not valid UTF-8 JSON") from exc


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ImageArtifactError(f"{label} must be a JSON object")
    return value


def _require_sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise ImageArtifactError(f"{label} must be a JSON array")
    return value


def _safe_relative_path(name: str, max_depth: int, *, allow_dot: bool = False) -> PurePosixPath:
    if (
        not isinstance(name, str)
        or "\x00" in name
        or (os.sep == "\\" and "\\" in name)
        or _DRIVE_RE.match(name)
    ):
        raise ImageArtifactError(f"unsafe archive path: {name!r}")
    if name.startswith("/"):
        raise ImageArtifactError(f"absolute archive path is forbidden: {name!r}")
    raw = name[:-1] if name.endswith("/") else name
    if raw.startswith("./"):
        raw = raw[2:]
    path = PurePosixPath(raw)
    if (not allow_dot and str(path) in {"", "."}) or ".." in path.parts:
        raise ImageArtifactError(f"archive path traversal is forbidden: {name!r}")
    if len(path.parts) > max_depth:
        raise ImageArtifactError(f"archive path exceeds maximum depth: {name!r}")
    if str(path) != raw:
        raise ImageArtifactError(f"archive path is not normalized: {name!r}")
    return path


def _inside(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _assert_no_symlink_parents(root: Path, relative: PurePosixPath) -> Path:
    target = root.joinpath(*relative.parts)
    if not _inside(root, target):
        raise ImageArtifactError("resolved image path escapes the root filesystem")
    current = root
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink():
            raise ImageArtifactError(f"archive path traverses a symlink: {relative}")
        if current.exists() and not current.is_dir():
            raise ImageArtifactError(f"archive path parent is not a directory: {relative}")
    return target


def _ensure_parent(root: Path, relative: PurePosixPath) -> Path:
    target = _assert_no_symlink_parents(root, relative)
    current = root
    for part in relative.parts[:-1]:
        current /= part
        if not current.exists():
            current.mkdir(mode=0o700)
    return target


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def _replace_for_type(path: Path, *, directory: bool) -> None:
    if path.is_symlink() or (path.exists() and (not directory or not path.is_dir())):
        _remove_path(path)


def _safe_link_target(
    root: Path,
    member_path: PurePosixPath,
    link_name: str,
    limits: ImageExtractionLimits,
    *,
    hardlink: bool,
) -> tuple[str, Path]:
    if (
        not link_name
        or "\x00" in link_name
        or (os.sep == "\\" and "\\" in link_name)
        or _DRIVE_RE.match(link_name)
    ):
        raise ImageArtifactError(f"unsafe link target: {link_name!r}")
    absolute = link_name.startswith("/")
    link_path = PurePosixPath(link_name.lstrip("/") if absolute else link_name)
    base = PurePosixPath() if hardlink or absolute else member_path.parent
    stack: list[str] = []
    for part in (base / link_path).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                raise ImageArtifactError(f"link target escapes the root filesystem: {link_name!r}")
            stack.pop()
        else:
            stack.append(part)
    if len(stack) > limits.max_path_depth:
        raise ImageArtifactError(f"link target exceeds maximum depth: {link_name!r}")
    resolved = root.joinpath(*stack)
    if not _inside(root, resolved):
        raise ImageArtifactError(f"link target escapes the root filesystem: {link_name!r}")
    materialized_name = link_name
    if absolute and not hardlink:
        source_parent = f"/{member_path.parent}" if str(member_path.parent) != "." else "/"
        materialized_name = posixpath.relpath(f"/{'/'.join(stack)}", source_parent)
    return materialized_name, resolved


def _read_bounded(stream: BinaryIO, size: int, limit: int, label: str) -> bytes:
    if size < 0 or size > limit:
        raise ImageArtifactError(f"{label} exceeds its size limit")
    data = stream.read(size + 1)
    if len(data) != size:
        raise ImageArtifactError(f"{label} is truncated")
    return data


def _config_strings(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ImageArtifactError(f"image config {label} must be an array of strings")
    return tuple(value)


def _sanitize_config(raw: bytes) -> SanitizedImageConfig:
    document = _require_mapping(_load_json_bytes(raw, "image config"), "image config")
    config_value = document.get("config", {})
    config = _require_mapping(config_value, "image config.config") if config_value is not None else {}
    os_name = document.get("os", "unknown")
    architecture = document.get("architecture", "unknown")
    variant = document.get("variant")
    if not isinstance(os_name, str) or not isinstance(architecture, str):
        raise ImageArtifactError("image config platform fields must be strings")
    if variant is not None and not isinstance(variant, str):
        raise ImageArtifactError("image config variant must be a string")
    platform = f"{os_name}/{architecture}"
    if variant:
        platform = f"{platform}/{variant}"
    working_dir = config.get("WorkingDir") or "/"
    created = document.get("created")
    env = config.get("Env") or []
    if not isinstance(working_dir, str) or not isinstance(env, list) or not all(isinstance(item, str) for item in env):
        raise ImageArtifactError("image config contains invalid WorkingDir or Env")
    if created is not None and not isinstance(created, str):
        raise ImageArtifactError("image config created must be a string")
    env_keys = tuple(dict.fromkeys(item.partition("=")[0] for item in env if item.partition("=")[0]))
    return SanitizedImageConfig(
        entrypoint=_config_strings(config.get("Entrypoint"), "Entrypoint"),
        cmd=_config_strings(config.get("Cmd"), "Cmd"),
        working_dir=working_dir,
        platform=platform,
        created=created,
        env_keys=env_keys,
    )


def _validated_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ImageArtifactError(f"{label} must be a sha256 digest")
    return value


def _open_oci_blob(layout: Path, descriptor: Mapping[str, Any], limits: ImageExtractionLimits) -> tuple[Path, bytes]:
    digest = _validated_digest(descriptor.get("digest"), "OCI descriptor digest")
    expected_size = descriptor.get("size")
    if not isinstance(expected_size, int) or expected_size < 0:
        raise ImageArtifactError("OCI descriptor size must be a non-negative integer")
    if expected_size > limits.max_layer_archive_size:
        raise ImageArtifactError("OCI blob exceeds the maximum archive size")
    blob = layout / "blobs" / "sha256" / digest[7:]
    if blob.is_symlink() or not blob.is_file():
        raise ImageArtifactError(f"OCI blob is missing or not a regular file: {digest}")
    resolved = blob.resolve()
    if not _inside(layout.resolve(), resolved):
        raise ImageArtifactError("OCI blob escapes the image layout")
    if blob.stat().st_size != expected_size:
        raise ImageArtifactError(f"OCI blob size mismatch: {digest}")
    if _sha256_file(blob) != digest:
        raise ImageArtifactError(f"OCI blob digest mismatch: {digest}")
    if expected_size > limits.max_metadata_size:
        return blob, b""
    return blob, blob.read_bytes()


def _descriptor_platform_matches(descriptor: Mapping[str, Any], platform: str) -> bool:
    candidate = descriptor.get("platform")
    if not isinstance(candidate, dict):
        return False
    value = f"{candidate.get('os', '')}/{candidate.get('architecture', '')}"
    if candidate.get("variant"):
        value += f"/{candidate['variant']}"
    return value == platform


def _select_oci_manifest(
    layout: Path,
    descriptors: Sequence[Any],
    limits: ImageExtractionLimits,
    platform: str | None,
    depth: int = 0,
) -> tuple[Mapping[str, Any], str]:
    if depth > 4:
        raise ImageArtifactError("OCI index nesting is too deep")
    mappings = [_require_mapping(item, "OCI manifest descriptor") for item in descriptors]
    if platform:
        platform_matches = [item for item in mappings if _descriptor_platform_matches(item, platform)]
        if platform_matches:
            mappings = platform_matches
        else:
            mappings = [item for item in mappings if item.get("mediaType") in _OCI_INDEX_TYPES]
    if len(mappings) != 1:
        raise ImageArtifactError("OCI layout must resolve to exactly one image manifest")
    descriptor = mappings[0]
    media_type = descriptor.get("mediaType")
    blob, data = _open_oci_blob(layout, descriptor, limits)
    if blob.stat().st_size > limits.max_metadata_size:
        raise ImageArtifactError("OCI manifest exceeds the metadata size limit")
    document = _require_mapping(_load_json_bytes(data, "OCI manifest"), "OCI manifest")
    if media_type in _OCI_INDEX_TYPES or "manifests" in document:
        return _select_oci_manifest(
            layout,
            _require_sequence(document.get("manifests"), "nested OCI manifests"),
            limits,
            platform,
            depth + 1,
        )
    if media_type not in _OCI_MANIFEST_TYPES and document.get("schemaVersion") != 2:
        raise ImageArtifactError("unsupported OCI manifest media type")
    return document, _validated_digest(descriptor.get("digest"), "OCI manifest digest")


def _read_oci(
    layout: Path,
    limits: ImageExtractionLimits,
    platform: str | None,
) -> tuple[str, bytes, list[_LayerSource]]:
    if layout.is_symlink() or not layout.is_dir():
        raise ImageArtifactError("OCI image layout must be a real directory")
    layout_file = layout / "oci-layout"
    index_file = layout / "index.json"
    for path in (layout_file, index_file):
        if path.is_symlink() or not path.is_file():
            raise ImageArtifactError(f"OCI layout is missing {path.name}")
        if path.stat().st_size > limits.max_metadata_size:
            raise ImageArtifactError(f"{path.name} exceeds the metadata size limit")
    layout_doc = _require_mapping(_load_json_bytes(layout_file.read_bytes(), "oci-layout"), "oci-layout")
    if layout_doc.get("imageLayoutVersion") != "1.0.0":
        raise ImageArtifactError("unsupported OCI image layout version")
    index_doc = _require_mapping(_load_json_bytes(index_file.read_bytes(), "OCI index"), "OCI index")
    manifest, manifest_digest = _select_oci_manifest(
        layout,
        _require_sequence(index_doc.get("manifests"), "OCI index manifests"),
        limits,
        platform,
    )
    config_desc = _require_mapping(manifest.get("config"), "OCI config descriptor")
    config_path, config_bytes = _open_oci_blob(layout, config_desc, limits)
    if config_path.stat().st_size > limits.max_metadata_size:
        raise ImageArtifactError("OCI config exceeds the metadata size limit")
    layer_descs = _require_sequence(manifest.get("layers"), "OCI layers")
    if len(layer_descs) > limits.max_layers:
        raise ImageArtifactError("image exceeds the maximum layer count")
    layers: list[_LayerSource] = []
    for raw_descriptor in layer_descs:
        descriptor = _require_mapping(raw_descriptor, "OCI layer descriptor")
        path, _ = _open_oci_blob(layout, descriptor, limits)
        digest = _validated_digest(descriptor.get("digest"), "OCI layer digest")
        layers.append(_LayerSource(digest=digest, size=path.stat().st_size, opener=path.open))
    return manifest_digest, config_bytes, layers


def _docker_member_index(archive: tarfile.TarFile, limits: ImageExtractionLimits) -> dict[str, tarfile.TarInfo]:
    result: dict[str, tarfile.TarInfo] = {}
    for member in archive:
        path = _safe_relative_path(member.name, limits.max_path_depth, allow_dot=True)
        if str(path) == ".":
            continue
        name = str(path)
        if name in result:
            raise ImageArtifactError(f"duplicate Docker archive member: {name}")
        if not (member.isfile() or member.isdir()):
            raise ImageArtifactError(f"unsupported Docker archive member type: {name}")
        if member.size > limits.max_layer_archive_size:
            raise ImageArtifactError(f"Docker archive member exceeds size limit: {name}")
        result[name] = member
    return result


def _docker_member_bytes(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    name: str,
    limit: int,
) -> bytes:
    path = str(_safe_relative_path(name, 64))
    member = members.get(path)
    if member is None or not member.isfile():
        raise ImageArtifactError(f"Docker archive member is missing: {path}")
    stream = archive.extractfile(member)
    if stream is None:
        raise ImageArtifactError(f"cannot read Docker archive member: {path}")
    with stream:
        return _read_bounded(stream, member.size, limit, path)


def _copy_docker_layer(
    archive_path: Path,
    member_name: str,
    expected_size: int,
    destination: Path,
    limit: int,
) -> None:
    if expected_size > limit:
        raise ImageArtifactError("Docker layer exceeds the maximum archive size")
    with tarfile.open(archive_path, "r:*") as archive:
        member = archive.getmember(member_name)
        stream = archive.extractfile(member)
        if stream is None:
            raise ImageArtifactError(f"cannot read Docker layer: {member_name}")
        written = 0
        with stream, destination.open("wb") as output:
            while chunk := stream.read(1024 * 1024):
                written += len(chunk)
                if written > limit:
                    raise ImageArtifactError("Docker layer exceeds the maximum archive size")
                output.write(chunk)
        if written != expected_size:
            raise ImageArtifactError(f"Docker layer is truncated: {member_name}")


def _docker_layer_diff_id(path: Path, limit: int) -> str:
    with path.open("rb") as raw:
        magic = raw.read(4)
        raw.seek(0)
        if magic.startswith(b"\x1f\x8b"):
            stream: BinaryIO = gzip.GzipFile(fileobj=raw)
        elif magic == b"\x28\xb5\x2f\xfd":
            raise ImageArtifactError("zstd-compressed Docker layers are not supported")
        else:
            stream = raw
        digest = hashlib.sha256()
        size = 0
        try:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise ImageArtifactError("Docker layer exceeds the maximum archive size")
                digest.update(chunk)
        except (EOFError, OSError) as exc:
            raise ImageArtifactError("Docker layer compression is invalid") from exc
        finally:
            if stream is not raw:
                stream.close()
    return f"sha256:{digest.hexdigest()}"


def _read_docker(
    archive_path: Path,
    limits: ImageExtractionLimits,
    staging: Path,
) -> tuple[str, bytes, list[_LayerSource]]:
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ImageArtifactError("Docker archive must be a real file")
    try:
        archive = tarfile.open(archive_path, "r:*")
    except (tarfile.TarError, OSError) as exc:
        raise ImageArtifactError("Docker archive is not a readable tar file") from exc
    with archive:
        members = _docker_member_index(archive, limits)
        manifest_raw = _docker_member_bytes(archive, members, "manifest.json", limits.max_metadata_size)
        manifest = _require_sequence(_load_json_bytes(manifest_raw, "Docker manifest"), "Docker manifest")
        if len(manifest) != 1:
            raise ImageArtifactError("Docker archive must contain exactly one image")
        image = _require_mapping(manifest[0], "Docker manifest entry")
        config_name = image.get("Config")
        if not isinstance(config_name, str):
            raise ImageArtifactError("Docker manifest Config must be a path")
        config_bytes = _docker_member_bytes(archive, members, config_name, limits.max_metadata_size)
        image_digest = _sha256_bytes(config_bytes)
        config_filename = PurePosixPath(config_name).name
        if re.fullmatch(r"[0-9a-f]{64}\.json", config_filename) and config_filename[:-5] != image_digest[7:]:
            raise ImageArtifactError("Docker config filename does not match its content digest")
        layer_names = _require_sequence(image.get("Layers"), "Docker manifest Layers")
        if len(layer_names) > limits.max_layers:
            raise ImageArtifactError("image exceeds the maximum layer count")
        config_document = _require_mapping(_load_json_bytes(config_bytes, "Docker config"), "Docker config")
        rootfs = config_document.get("rootfs")
        expected_diff_ids: Sequence[Any] | None = None
        if rootfs is not None:
            rootfs_mapping = _require_mapping(rootfs, "Docker config rootfs")
            expected_diff_ids = _require_sequence(rootfs_mapping.get("diff_ids"), "Docker config rootfs.diff_ids")
            if len(expected_diff_ids) != len(layer_names):
                raise ImageArtifactError("Docker config diff_ids count does not match layer count")
        layers: list[_LayerSource] = []
        layer_dir = staging / "layer-archives"
        layer_dir.mkdir()
        for index, raw_name in enumerate(layer_names):
            if not isinstance(raw_name, str):
                raise ImageArtifactError("Docker layer name must be a path")
            name = str(_safe_relative_path(raw_name, limits.max_path_depth))
            member = members.get(name)
            if member is None or not member.isfile():
                raise ImageArtifactError(f"Docker layer is missing: {name}")
            layer_path = layer_dir / f"{index}.tar"
            _copy_docker_layer(archive_path, member.name, member.size, layer_path, limits.max_layer_archive_size)
            archive_digest = _sha256_file(layer_path)
            blob_match = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", name)
            if blob_match and archive_digest[7:] != blob_match.group(1):
                raise ImageArtifactError(f"Docker layer blob digest mismatch: {name}")
            digest = _docker_layer_diff_id(layer_path, limits.max_layer_archive_size)
            if expected_diff_ids is not None:
                expected_digest = _validated_digest(expected_diff_ids[index], "Docker layer diff_id")
                if digest != expected_digest:
                    raise ImageArtifactError(f"Docker layer digest mismatch: {name}")
            layers.append(_LayerSource(digest=digest, size=member.size, opener=layer_path.open))
    return image_digest, config_bytes, layers


def _member_kind(member: tarfile.TarInfo) -> str:
    if member.isfile():
        return "file"
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    raise ImageArtifactError(f"unsupported layer member type: {member.name}")


def _scan_layer(
    archive: tarfile.TarFile,
    limits: ImageExtractionLimits,
    budget: _Budget,
) -> list[tuple[tarfile.TarInfo, PurePosixPath]]:
    members: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
    seen: set[str] = set()
    for member in archive:
        path = _safe_relative_path(member.name, limits.max_path_depth, allow_dot=True)
        if str(path) == ".":
            continue
        normalized = str(path)
        if normalized in seen:
            raise ImageArtifactError(f"duplicate layer member: {normalized}")
        seen.add(normalized)
        kind = _member_kind(member)
        budget.account_member(member.size if kind == "file" else 0)
        members.append((member, path))
    return members


def _whiteout_target(path: PurePosixPath) -> tuple[str, PurePosixPath] | None:
    name = path.name
    if name == ".wh..wh..opq":
        return "opaque", path.parent
    if name.startswith(".wh."):
        target_name = name[4:]
        if not target_name:
            raise ImageArtifactError("invalid empty whiteout target")
        return "remove", path.parent / target_name
    return None


def _apply_whiteouts(
    root: Path,
    members: Sequence[tuple[tarfile.TarInfo, PurePosixPath]],
) -> tuple[list[str], list[str]]:
    whiteouts: list[str] = []
    opaque: list[str] = []
    for _, path in members:
        action = _whiteout_target(path)
        if action is None:
            continue
        kind, target_relative = action
        target = _assert_no_symlink_parents(root, target_relative)
        if kind == "opaque":
            if target.is_symlink():
                raise ImageArtifactError(f"opaque whiteout targets a symlink: {target_relative}")
            if target.exists() and not target.is_dir():
                raise ImageArtifactError(f"opaque whiteout target is not a directory: {target_relative}")
            if target.is_dir():
                for child in target.iterdir():
                    _remove_path(child)
            opaque.append(str(target_relative))
        else:
            _remove_path(target)
            whiteouts.append(str(target_relative))
    return whiteouts, opaque


def _copy_regular_file(source: BinaryIO, destination: Path, expected: int) -> str:
    digest = hashlib.sha256()
    written = 0
    with destination.open("wb") as output:
        while chunk := source.read(min(1024 * 1024, expected - written)):
            output.write(chunk)
            digest.update(chunk)
            written += len(chunk)
            if written == expected:
                break
    if written != expected:
        raise ImageArtifactError(f"layer member is truncated: {destination.name}")
    return digest.hexdigest()


def _apply_layer(
    layer: _LayerSource,
    root: Path,
    budget: _Budget,
    limits: ImageExtractionLimits,
) -> tuple[LayerRecord, dict[str, FileRecord]]:
    try:
        with layer.opener("rb") as stream, tarfile.open(fileobj=stream, mode="r:*") as archive:
            members = _scan_layer(archive, limits, budget)
            whiteouts, opaque = _apply_whiteouts(root, members)
            changed: dict[str, FileRecord] = {}
            for member, relative in members:
                if _whiteout_target(relative) is not None:
                    continue
                target = _ensure_parent(root, relative)
                kind = _member_kind(member)
                mode = stat.S_IMODE(member.mode) & 0o777
                if kind == "directory":
                    _replace_for_type(target, directory=True)
                    target.mkdir(mode=mode or 0o755, exist_ok=True)
                    os.chmod(target, mode or 0o755, follow_symlinks=False)
                    record = FileRecord(str(relative), "directory", 0, layer.digest)
                elif kind == "file":
                    _replace_for_type(target, directory=False)
                    source = archive.extractfile(member)
                    if source is None:
                        raise ImageArtifactError(f"cannot read layer member: {relative}")
                    with source:
                        digest = _copy_regular_file(source, target, member.size)
                    os.chmod(target, mode or 0o644, follow_symlinks=False)
                    record = FileRecord(str(relative), "file", member.size, layer.digest, sha256=digest)
                elif kind == "symlink":
                    _replace_for_type(target, directory=False)
                    link_name, _ = _safe_link_target(root, relative, member.linkname, limits, hardlink=False)
                    os.symlink(link_name, target)
                    record = FileRecord(str(relative), "symlink", 0, layer.digest, link_target=link_name)
                else:
                    _replace_for_type(target, directory=False)
                    link_name, link_target = _safe_link_target(
                        root, relative, member.linkname, limits, hardlink=True
                    )
                    if any(parent.is_symlink() for parent in link_target.parents if _inside(root, parent)):
                        raise ImageArtifactError(f"hardlink target traverses a symlink: {link_name!r}")
                    if link_target.is_symlink() or not link_target.is_file():
                        raise ImageArtifactError(f"hardlink target is not an existing regular file: {link_name!r}")
                    os.link(link_target, target, follow_symlinks=False)
                    record = FileRecord(
                        str(relative),
                        "hardlink",
                        link_target.stat().st_size,
                        layer.digest,
                        sha256=_sha256_file(link_target)[7:],
                        link_target=link_name,
                    )
                changed[str(relative)] = record
    except ImageArtifactError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise ImageArtifactError(f"cannot safely apply image layer {layer.digest}") from exc
    return (
        LayerRecord(
            digest=layer.digest,
            size=layer.size,
            file_count=len(changed),
            whiteouts=tuple(whiteouts),
            opaque_directories=tuple(opaque),
        ),
        changed,
    )


def _final_file_records(root: Path, records: Mapping[str, FileRecord]) -> tuple[FileRecord, ...]:
    result: list[FileRecord] = []
    for relative, record in sorted(records.items()):
        path = root.joinpath(*PurePosixPath(relative).parts)
        if path.exists() or path.is_symlink():
            result.append(record)
    return tuple(result)


def _make_read_only(root: Path) -> None:
    paths = sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True)
    for path in paths:
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        path.chmod(mode & ~0o222)
    root.chmod(stat.S_IMODE(root.stat().st_mode) & ~0o222)


def _remove_staging(staging: Path) -> None:
    def make_writable_and_retry(function: Any, path: str, _: Any) -> None:
        os.chmod(path, stat.S_IRWXU)
        function(path)

    shutil.rmtree(staging, ignore_errors=False, onerror=make_writable_and_retry)


def parse_image_artifact(
    artifact_path: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    *,
    image_type: ImageArtifactType | None = None,
    limits: ImageExtractionLimits | None = None,
    platform: str | None = None,
) -> ParsedImageArtifact:
    """Parse an image artifact without a daemon and materialize a read-only rootfs."""

    artifact = Path(artifact_path)
    selected_type: ImageArtifactType
    if image_type is None:
        selected_type = "oci_layout" if artifact.is_dir() else "docker_archive"
    elif image_type in {"docker_archive", "oci_layout"}:
        selected_type = image_type
    else:
        raise ImageArtifactError(f"unsupported image artifact type: {image_type!r}")
    effective_limits = limits or ImageExtractionLimits()

    output = Path(output_root)
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or not output.is_dir():
        raise ImageArtifactError("output root must be a real directory")
    output = output.resolve()
    staging = output / f".image-unpack-{uuid.uuid4().hex}"
    staging.mkdir(mode=0o700)
    try:
        rootfs = staging / "rootfs"
        rootfs.mkdir(mode=0o700)
        if selected_type == "docker_archive":
            image_digest, config_bytes, layer_sources = _read_docker(artifact, effective_limits, staging)
        else:
            image_digest, config_bytes, layer_sources = _read_oci(artifact, effective_limits, platform)
        config = _sanitize_config(config_bytes)
        if platform is not None and config.platform != platform:
            raise ImageArtifactError(
                f"selected image platform {config.platform!r} does not match requested platform {platform!r}"
            )

        budget = _Budget(effective_limits)
        layer_records: list[LayerRecord] = []
        current_records: dict[str, FileRecord] = {}
        for layer in layer_sources:
            layer_record, changed = _apply_layer(layer, rootfs, budget, effective_limits)
            layer_records.append(layer_record)
            for removed in layer_record.whiteouts:
                current_records.pop(removed, None)
                prefix = f"{removed}/"
                current_records = {
                    path: record for path, record in current_records.items() if not path.startswith(prefix)
                }
            for opaque_dir in layer_record.opaque_directories:
                if opaque_dir == ".":
                    current_records = {}
                else:
                    prefix = f"{opaque_dir}/"
                    current_records = {
                        path: record for path, record in current_records.items() if not path.startswith(prefix)
                    }
            current_records.update(changed)

        shutil.rmtree(staging / "layer-archives", ignore_errors=True)
        destination = output / image_digest.replace(":", "-")
        if destination.exists() or destination.is_symlink():
            raise ImageArtifactError(f"image output already exists: {destination.name}")
        records = _final_file_records(rootfs, current_records)
        _make_read_only(rootfs)
        staging.rename(destination)
        return ParsedImageArtifact(
            image_type=selected_type,
            image_digest=image_digest,
            config=config,
            layers=tuple(layer_records),
            files=records,
            rootfs_path=destination / "rootfs",
            _owned_paths=(destination,),
        )
    except Exception:
        if staging.exists():
            try:
                _remove_staging(staging)
            except OSError:
                pass
        raise
