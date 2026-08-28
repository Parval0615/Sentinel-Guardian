from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from redsentinel.application.contracts import AgentRegistration
from redsentinel.application.image_profile_contracts import (
    AgentDirectoryDescriptor,
    profile_configuration_digest,
    profile_version_digest,
)


_ASCII_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_HASH_CHUNK_SIZE = 1024 * 1024


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentAssetIndexRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "agent-asset-index-v0.1"
    tenant_id: str
    agent_id: str
    directory_name: str
    image_type: str
    image_digest: str
    configuration_digest: str
    profile_version_digest: str
    material_version_id: str
    profile_version_id: str
    asset_source: Literal["configured_root", "managed_upload"] = "configured_root"
    asset_directory_ref: str | None = None
    status: str = "profile_pending"
    indexed_at: str = Field(default_factory=_utc_now_iso)


class AgentAssetIndexError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "agent-asset-index-error-v0.1"
    error_id: str
    directory_name: str
    code: str
    message: str
    retryable: bool = True


class AgentAssetIndexService:
    """Indexes the configured asset root without starting image analysis."""

    def __init__(self, product_service: Any) -> None:
        self._product_service = product_service
        self._storage = product_service.storage
        self._lock = threading.RLock()

    def refresh(
        self,
        root: Path,
        *,
        tenant_id: str,
        username: str,
    ) -> list[AgentRegistration]:
        with self._lock:
            candidates: list[
                tuple[Path, AgentDirectoryDescriptor, str]
            ] = []
            errors: list[AgentAssetIndexError] = []
            if not root.is_dir():
                errors.append(
                    self._error(
                        "",
                        "agent_root_unavailable",
                        "The configured Agent asset directory is unavailable.",
                    )
                )
                self._write_errors(tenant_id, errors)
                return []

            root_resolved = root.resolve()
            for entry in sorted(root.iterdir(), key=lambda path: path.name):
                if not entry.is_dir():
                    continue
                if entry.is_symlink():
                    errors.append(
                        self._error(
                            entry.name,
                            "directory_symlink_rejected",
                            "The Agent directory must be a direct physical child of the asset root.",
                        )
                    )
                    continue
                try:
                    if not entry.resolve().is_relative_to(root_resolved):
                        raise AgentAssetIndexErrorException(
                            "directory_outside_root",
                            "The Agent directory must remain inside the asset root.",
                        )
                    descriptor, digest = self._read_asset(entry)
                    candidates.append((entry, descriptor, digest))
                except AgentAssetIndexErrorException as exc:
                    errors.append(self._error(entry.name, exc.code, exc.public_message))
                except OSError:
                    errors.append(
                        self._error(
                            entry.name,
                            "directory_unavailable",
                            "The Agent directory could not be read.",
                        )
                    )

            duplicates = self._duplicate_agent_ids(candidates)
            indexed: list[AgentRegistration] = []
            for directory, descriptor, digest in candidates:
                if descriptor.agent_id in duplicates:
                    errors.append(
                        self._error(
                            directory.name,
                            "duplicate_agent_id",
                            "Another Agent directory declares the same agent_id.",
                        )
                    )
                    continue
                if self._storage.agent_asset_suppression_path(
                    tenant_id, descriptor.agent_id
                ).is_file():
                    continue
                try:
                    indexed.append(
                        self._index_asset(
                            directory,
                            descriptor,
                            digest,
                            tenant_id=tenant_id,
                            username=username,
                        )
                    )
                except (OSError, ValueError, json.JSONDecodeError, ValidationError):
                    errors.append(
                        self._error(
                            directory.name,
                            "asset_index_failed",
                            "The Agent asset could not be indexed.",
                        )
                    )

            self._write_errors(tenant_id, errors)
            return sorted(indexed, key=lambda item: item.agent_id)

    def list_errors(self, tenant_id: str) -> list[AgentAssetIndexError]:
        path = self._storage.agent_asset_index_errors_path(tenant_id)
        if not path.is_file():
            return []
        payload = self._storage.read_json(path)
        return [
            AgentAssetIndexError.model_validate(item)
            for item in payload.get("errors", [])
        ]


    def index_directory(
        self,
        directory: Path,
        *,
        tenant_id: str,
        username: str,
        asset_source: Literal["configured_root", "managed_upload"],
        asset_directory_ref: str | None = None,
        domain: str = "general",
    ) -> AgentRegistration:
        with self._lock:
            descriptor, digest = self._read_asset(directory)
            if asset_source == "managed_upload":
                self._storage.agent_asset_suppression_path(
                    tenant_id, descriptor.agent_id
                ).unlink(missing_ok=True)
            return self._index_asset(
                directory,
                descriptor,
                digest,
                tenant_id=tenant_id,
                username=username,
                asset_source=asset_source,
                asset_directory_ref=asset_directory_ref,
                domain=domain,
            )

    def suppress_configured_asset(self, tenant_id: str, agent_id: str) -> None:
        with self._lock:
            self._storage.write_json(
                self._storage.agent_asset_suppression_path(tenant_id, agent_id),
                {
                    "schema_version": "agent-asset-suppression-v0.1",
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                    "suppressed_at": _utc_now_iso(),
                },
            )

    def _read_asset(
        self,
        directory: Path,
    ) -> tuple[AgentDirectoryDescriptor, str]:
        descriptor_path = directory / "agent.json"
        if not descriptor_path.is_file():
            raise AgentAssetIndexErrorException(
                "descriptor_missing",
                "The Agent directory does not contain agent.json.",
            )
        try:
            payload = json.loads(descriptor_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentAssetIndexErrorException(
                "descriptor_invalid",
                "The Agent descriptor is invalid.",
            ) from exc
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("agent_id"), str)
            or not _ASCII_AGENT_ID.fullmatch(payload["agent_id"])
        ):
            raise AgentAssetIndexErrorException(
                "agent_id_invalid",
                "The Agent descriptor has an invalid agent_id.",
            )
        try:
            descriptor = AgentDirectoryDescriptor.model_validate(payload)
        except ValidationError as exc:
            raise AgentAssetIndexErrorException(
                "descriptor_invalid",
                "The Agent descriptor is invalid.",
            ) from exc

        directory_root = directory.resolve()
        try:
            image_path = (directory / descriptor.image.path).resolve(strict=True)
        except OSError as exc:
            raise AgentAssetIndexErrorException(
                "image_unavailable",
                "The declared image artifact is unavailable.",
            ) from exc
        if not image_path.is_relative_to(directory_root):
            raise AgentAssetIndexErrorException(
                "image_outside_directory",
                "The declared image artifact must remain inside its Agent directory.",
            )

        try:
            if descriptor.image.type == "docker_archive":
                if not image_path.is_file():
                    raise AgentAssetIndexErrorException(
                        "image_type_mismatch",
                        "A Docker archive image must be a regular file.",
                    )
                digest = _digest_file(image_path)
            else:
                digest = _digest_oci_layout(image_path)
        except AgentAssetIndexErrorException:
            raise
        except OSError as exc:
            raise AgentAssetIndexErrorException(
                "image_unreadable",
                "The declared image artifact could not be read.",
            ) from exc

        expected_digest = descriptor.image.digest
        if expected_digest is not None and expected_digest != digest:
            raise AgentAssetIndexErrorException(
                "image_digest_mismatch",
                "The declared image digest does not match the artifact content.",
            )
        return descriptor, digest

    def _index_asset(
        self,
        directory: Path,
        descriptor: AgentDirectoryDescriptor,
        digest: str,
        *,
        tenant_id: str,
        username: str,
        asset_source: Literal["configured_root", "managed_upload"] = "configured_root",
        asset_directory_ref: str | None = None,
        domain: str = "general",
    ) -> AgentRegistration:
        configuration_digest = profile_configuration_digest(descriptor)
        adapter_type = (
            "openmanus"
            if any(
                "openmanus" in framework.casefold()
                for framework in descriptor.expected_frameworks
            )
            else "external_sdk"
        )
        current_path = self._storage.agent_asset_index_path(
            tenant_id,
            descriptor.agent_id,
        )
        if current_path.is_file():
            current = AgentAssetIndexRecord.model_validate(
                self._storage.read_json(current_path)
            )
            agent_path = self._storage.agent_path(tenant_id, descriptor.agent_id)
            if (
                current.image_digest == digest
                and current.configuration_digest == configuration_digest
                and agent_path.is_file()
            ):
                cached = AgentRegistration.model_validate(
                    self._storage.read_json(agent_path)
                )
                if cached.adapter_type == adapter_type:
                    return cached

        digest_suffix = digest.removeprefix("sha256:")[:16]
        version_digest = profile_version_digest(digest, configuration_digest)
        version_suffix = version_digest.removeprefix("sha256:")[:16]
        record = AgentAssetIndexRecord(
            tenant_id=tenant_id,
            agent_id=descriptor.agent_id,
            directory_name=directory.name,
            image_type=descriptor.image.type,
            image_digest=digest,
            configuration_digest=configuration_digest,
            profile_version_digest=version_digest,
            material_version_id=(
                f"image-material-{descriptor.agent_id}-{digest_suffix}"
            ),
            profile_version_id=(
                f"image-profile-{descriptor.agent_id}-{version_suffix}"
            ),
            asset_source=asset_source,
            asset_directory_ref=asset_directory_ref,
        )
        registration = AgentRegistration(
            tenant_id=tenant_id,
            username=username,
            agent_id=descriptor.agent_id,
            name=descriptor.name,
            domain=domain,
            integration_type="docker",
            framework=", ".join(descriptor.expected_frameworks) or "unknown",
            adapter_type=adapter_type,
            status="profiling",
            remarks=descriptor.notes,
            data_boundary={
                "asset_source": asset_source,
                "asset_directory_ref": asset_directory_ref,
                "image_type": descriptor.image.type,
                "image_digest": digest,
                "profile_configuration_digest": configuration_digest,
                "material_version_id": record.material_version_id,
                "profile_version_id": record.profile_version_id,
                "profile_status": record.status,
                "platform": descriptor.platform,
            },
        )
        self._product_service.register_agent(registration)
        payload = record.model_dump(mode="json")
        self._storage.write_json(current_path, payload)
        history_path = self._storage.agent_asset_index_version_path(
            tenant_id,
            descriptor.agent_id,
            version_suffix,
        )
        if not history_path.exists():
            self._storage.write_json(history_path, payload)
        return registration

    def _write_errors(
        self,
        tenant_id: str,
        errors: list[AgentAssetIndexError],
    ) -> None:
        self._storage.write_json(
            self._storage.agent_asset_index_errors_path(tenant_id),
            {
                "schema_version": "agent-asset-index-errors-v0.1",
                "errors": [
                    item.model_dump(mode="json")
                    for item in sorted(
                        errors,
                        key=lambda item: (item.directory_name, item.code),
                    )
                ],
            },
        )

    @staticmethod
    def _duplicate_agent_ids(
        candidates: list[tuple[Path, AgentDirectoryDescriptor, str]],
    ) -> set[str]:
        counts: dict[str, int] = {}
        for _, descriptor, _ in candidates:
            counts[descriptor.agent_id] = counts.get(descriptor.agent_id, 0) + 1
        return {agent_id for agent_id, count in counts.items() if count > 1}

    @staticmethod
    def _error(
        directory_name: str,
        code: str,
        message: str,
    ) -> AgentAssetIndexError:
        identity = hashlib.sha256(
            f"{directory_name}\0{code}".encode("utf-8")
        ).hexdigest()[:16]
        return AgentAssetIndexError(
            error_id=f"asset-index-{identity}",
            directory_name=directory_name,
            code=code,
            message=message,
        )


class AgentAssetIndexErrorException(Exception):
    def __init__(self, code: str, public_message: str) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK_SIZE):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _digest_oci_layout(path: Path) -> str:
    if not path.is_dir():
        raise AgentAssetIndexErrorException(
            "image_type_mismatch",
            "An OCI layout image must be a directory.",
        )
    if not (path / "oci-layout").is_file() or not (path / "index.json").is_file():
        raise AgentAssetIndexErrorException(
            "oci_layout_invalid",
            "The OCI image layout is incomplete.",
        )

    files = sorted(
        candidate
        for candidate in path.rglob("*")
        if candidate.is_file()
    )
    if not files:
        raise AgentAssetIndexErrorException(
            "oci_layout_invalid",
            "The OCI image layout does not contain readable content.",
        )
    digest = hashlib.sha256()
    root = path.resolve()
    for candidate in files:
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise AgentAssetIndexErrorException(
                "image_outside_directory",
                "The OCI image layout contains a file outside its directory.",
            )
        relative = candidate.relative_to(path).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(candidate.stat().st_size.to_bytes(8, "big"))
        with candidate.open("rb") as handle:
            while chunk := handle.read(_HASH_CHUNK_SIZE):
                digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"
