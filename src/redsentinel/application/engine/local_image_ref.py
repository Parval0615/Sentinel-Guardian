from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tarfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from redsentinel.application.image_profile_contracts import AgentDirectoryDescriptor


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,254}$")
_HASH_CHUNK_SIZE = 1024 * 1024


class LocalImageResolutionError(ValueError):
    """Raised when an indexed archive cannot be bound to a local Docker image."""


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class ArchiveImageIdentity:
    repo_tag: str
    image_id: str
    platform: str


@dataclass
class LocalDockerImageRefResolver:
    docker_binary: str
    runner: CommandRunner = subprocess.run
    timeout_seconds: float = 120.0
    max_output_chars: int = 16 * 1024

    def __call__(self, inventory: dict[str, Any]) -> str | None:
        descriptor = AgentDirectoryDescriptor.model_validate(inventory.get("descriptor"))
        if descriptor.image.type != "docker_archive":
            return None
        image_path = Path(str(inventory.get("image_path", "")))
        expected_archive_digest = str(inventory.get("record", {}).get("image_digest", ""))
        if (
            not image_path.is_file()
            or not _DIGEST.fullmatch(expected_archive_digest)
            or _sha256_file(image_path) != expected_archive_digest
        ):
            raise LocalImageResolutionError(
                "indexed Docker archive changed before dynamic verification"
            )

        identity = read_archive_identity(image_path, descriptor.platform)
        inspected = self._inspect(identity.repo_tag)
        if inspected is None:
            self._load(image_path, identity)
            inspected = self._inspect(identity.repo_tag)
        if inspected is None:
            raise LocalImageResolutionError(
                "Docker did not expose the archive RepoTag after loading"
            )
        image_id, platform = _validated_inspect_identity(inspected)
        if image_id != identity.image_id:
            raise LocalImageResolutionError(
                "local Docker RepoTag does not match the indexed archive image identity"
            )
        if platform != identity.platform:
            raise LocalImageResolutionError(
                "local Docker image platform does not match the indexed archive"
            )
        return image_id

    def _inspect(self, image_ref: str) -> dict[str, Any] | None:
        result = self._run(
            [self.docker_binary, "image", "inspect", image_ref],
            check=False,
        )
        if result.returncode != 0:
            return None
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise LocalImageResolutionError("Docker image inspect returned invalid JSON") from exc
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise LocalImageResolutionError("Docker image inspect returned an invalid image record")
        return payload[0]

    def _load(self, image_path: Path, identity: ArchiveImageIdentity) -> None:
        result = self._run(
            [self.docker_binary, "load", "--input", str(image_path)],
            check=False,
        )
        if result.returncode != 0:
            raise LocalImageResolutionError("Docker could not load the indexed image archive")
        output = f"{result.stdout}\n{result.stderr}"
        accepted = (
            f"Loaded image: {identity.repo_tag}" in output
            or f"Loaded image ID: {identity.image_id}" in output
        )
        if not accepted:
            raise LocalImageResolutionError(
                "Docker load output did not identify the archive image"
            )

    def _run(
        self,
        command: Sequence[str],
        *,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = self.runner(
                list(command),
                check=check,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LocalImageResolutionError(
                f"Docker command failed before dynamic verification: {type(exc).__name__}"
            ) from exc
        if len(result.stdout) > self.max_output_chars or len(result.stderr) > self.max_output_chars:
            raise LocalImageResolutionError("Docker command output exceeded the safety limit")
        return result


def read_archive_identity(
    image_path: Path,
    declared_platform: str | None = None,
) -> ArchiveImageIdentity:
    try:
        with tarfile.open(image_path, "r:*") as archive:
            manifest = _read_json_member(archive, "manifest.json")
            if not isinstance(manifest, list) or len(manifest) != 1:
                raise LocalImageResolutionError(
                    "Docker archive must contain exactly one manifest"
                )
            record = manifest[0]
            if not isinstance(record, Mapping):
                raise LocalImageResolutionError("Docker archive manifest is invalid")
            repo_tags = record.get("RepoTags")
            if (
                not isinstance(repo_tags, list)
                or len(repo_tags) != 1
                or not isinstance(repo_tags[0], str)
                or not _valid_image_ref(repo_tags[0])
            ):
                raise LocalImageResolutionError(
                    "Docker archive must contain exactly one safe RepoTag"
                )
            config_name = _safe_member_name(record.get("Config"), "image config")
            config = _read_json_member(archive, config_name)
            if not isinstance(config, Mapping):
                raise LocalImageResolutionError("Docker archive config is invalid")
            platform = _config_platform(config)
            image_id = _archive_image_id(archive, repo_tags[0], config_name)
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        raise LocalImageResolutionError("Docker archive metadata is unreadable") from exc
    if declared_platform is not None and platform != declared_platform:
        raise LocalImageResolutionError(
            "Docker archive platform does not match its descriptor"
        )
    return ArchiveImageIdentity(repo_tag=repo_tags[0], image_id=image_id, platform=platform)


def _archive_image_id(archive: tarfile.TarFile, repo_tag: str, config_name: str) -> str:
    try:
        index = _read_json_member(archive, "index.json")
    except KeyError:
        config_digest = _member_digest(config_name)
        if config_digest is None:
            raise LocalImageResolutionError("Docker archive config identity is invalid")
        return config_digest
    if not isinstance(index, Mapping) or not isinstance(index.get("manifests"), list):
        raise LocalImageResolutionError("Docker archive index is invalid")
    first_component = repo_tag.split("/", 1)[0]
    canonical_tag = (
        repo_tag
        if "." in first_component or ":" in first_component or first_component == "localhost"
        else f"docker.io/{repo_tag}"
    )
    matches = []
    for item in index["manifests"]:
        if not isinstance(item, Mapping):
            continue
        annotations = item.get("annotations")
        if not isinstance(annotations, Mapping):
            continue
        name = annotations.get("io.containerd.image.name")
        if name in {repo_tag, canonical_tag}:
            matches.append(item.get("digest"))
    if len(matches) != 1 or not isinstance(matches[0], str) or not _DIGEST.fullmatch(matches[0]):
        raise LocalImageResolutionError(
            "Docker archive index does not bind its RepoTag to one image identity"
        )
    digest = matches[0]
    blob_name = f"blobs/sha256/{digest[7:]}"
    member = archive.getmember(blob_name)
    stream = archive.extractfile(member)
    if stream is None or f"sha256:{hashlib.sha256(stream.read()).hexdigest()}" != digest:
        raise LocalImageResolutionError("Docker archive image identity blob is invalid")
    return digest


def _read_json_member(archive: tarfile.TarFile, name: str) -> Any:
    member = archive.getmember(name)
    if not member.isfile() or member.size > 16 * 1024 * 1024:
        raise LocalImageResolutionError(f"Docker archive {name} is not a bounded file")
    stream = archive.extractfile(member)
    if stream is None:
        raise LocalImageResolutionError(f"Docker archive {name} is unreadable")
    return json.load(stream)


def _safe_member_name(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise LocalImageResolutionError(f"Docker archive {label} path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise LocalImageResolutionError(f"Docker archive {label} path is unsafe")
    return value


def _member_digest(name: str) -> str | None:
    path = PurePosixPath(name)
    candidate = path.name.removesuffix(".json")
    if len(candidate) == 64 and all(char in "0123456789abcdef" for char in candidate):
        return f"sha256:{candidate}"
    return None


def _config_platform(config: Mapping[str, Any]) -> str:
    os_name = config.get("os")
    architecture = config.get("architecture")
    variant = config.get("variant")
    if not isinstance(os_name, str) or not isinstance(architecture, str):
        raise LocalImageResolutionError("Docker archive platform metadata is invalid")
    platform = f"{os_name.lower()}/{_normalize_architecture(architecture)}"
    if isinstance(variant, str) and variant:
        platform = f"{platform}/{variant.lower()}"
    return platform


def _validated_inspect_identity(payload: Mapping[str, Any]) -> tuple[str, str]:
    image_id = payload.get("Id")
    os_name = payload.get("Os")
    architecture = payload.get("Architecture")
    variant = payload.get("Variant")
    if (
        not isinstance(image_id, str)
        or not _DIGEST.fullmatch(image_id)
        or not isinstance(os_name, str)
        or not isinstance(architecture, str)
    ):
        raise LocalImageResolutionError("Docker image inspect identity is invalid")
    platform = f"{os_name.lower()}/{_normalize_architecture(architecture)}"
    if isinstance(variant, str) and variant:
        platform = f"{platform}/{variant.lower()}"
    return image_id, platform


def _valid_image_ref(value: str) -> bool:
    return bool(
        _IMAGE_REF.fullmatch(value)
        and not value.startswith("-")
        and not any(char.isspace() for char in value)
    )


def _normalize_architecture(value: str) -> str:
    return {"aarch64": "arm64", "x86_64": "amd64"}.get(value.lower(), value.lower())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK_SIZE):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


__all__ = [
    "ArchiveImageIdentity",
    "LocalDockerImageRefResolver",
    "LocalImageResolutionError",
    "read_archive_identity",
]
