from __future__ import annotations

import hashlib
import os
import re
import shutil
import uuid
from collections.abc import AsyncIterable

from pydantic import BaseModel, ConfigDict

from redsentinel.application.contracts import AgentRegistration
from redsentinel.application.engine.agent_asset_index import AgentAssetIndexService
from redsentinel.application.engine.image_profile_workflow import (
    ImageProfileCreateResult,
    ImageProfileWorkflowService,
)
from redsentinel.application.engine.local_image_ref import (
    LocalImageResolutionError,
    read_archive_identity,
)
from redsentinel.application.engine.storage import ProductStorage, safe_component
from redsentinel.application.image_profile_contracts import (
    AgentDirectoryDescriptor,
    DynamicRuntimeRequirements,
    ImageReference,
)


_DEFAULT_MAX_UPLOAD_BYTES = 20 * 1024 * 1024 * 1024


class AgentImageUploadError(ValueError):
    def __init__(self, code: str, message: str, *, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class AgentImageImportResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "agent-image-import-response-v0.1"
    agent: AgentRegistration
    profile: ImageProfileCreateResult


class AgentImageUploadService:
    """Persists a tenant-owned Docker archive and starts its profile contract."""

    def __init__(
        self,
        storage: ProductStorage,
        asset_index: AgentAssetIndexService,
        image_profiles: ImageProfileWorkflowService,
        *,
        max_upload_bytes: int | None = None,
    ) -> None:
        self.storage = storage
        self.asset_index = asset_index
        self.image_profiles = image_profiles
        self.max_upload_bytes = (
            max_upload_bytes
            if max_upload_bytes is not None
            else _max_upload_bytes_from_environment()
        )

    async def import_archive(
        self,
        *,
        tenant_id: str,
        username: str,
        agent_id: str | None,
        name: str | None,
        domain: str,
        probe_module: str | None,
        expected_frameworks: list[str],
        chunks: AsyncIterable[bytes],
        content_length: int | None,
    ) -> AgentImageImportResult:
        safe_component(tenant_id, "tenant_id")
        domain = domain.strip()
        if not domain:
            raise AgentImageUploadError("agent_domain_required", "Agent domain is required.")
        if content_length is not None and content_length > self.max_upload_bytes:
            raise AgentImageUploadError(
                "image_too_large",
                "The Docker archive exceeds the configured upload limit.",
                status_code=413,
            )

        managed_root = self.storage.managed_agent_assets_dir(tenant_id)
        incoming = managed_root / ".incoming" / uuid.uuid4().hex
        incoming.mkdir(parents=True, exist_ok=False)
        image_path = incoming / "image.tar"
        digest = hashlib.sha256()
        received = 0
        try:
            with image_path.open("xb") as stream:
                async for chunk in chunks:
                    if not chunk:
                        continue
                    received += len(chunk)
                    if received > self.max_upload_bytes:
                        raise AgentImageUploadError(
                            "image_too_large",
                            "The Docker archive exceeds the configured upload limit.",
                            status_code=413,
                        )
                    stream.write(chunk)
                    digest.update(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            if received == 0:
                raise AgentImageUploadError(
                    "image_empty",
                    "The Docker archive is empty.",
                )

            image_digest = f"sha256:{digest.hexdigest()}"
            try:
                identity = read_archive_identity(image_path)
            except LocalImageResolutionError as exc:
                raise AgentImageUploadError(
                    "docker_archive_invalid",
                    str(exc),
                ) from exc
            resolved_agent_id = agent_id.strip() if agent_id else _agent_id_from_repo_tag(
                identity.repo_tag,
            )
            resolved_name = name.strip() if name else _agent_name_from_repo_tag(identity.repo_tag)
            safe_component(resolved_agent_id, "agent_id")
            if not resolved_name:
                raise AgentImageUploadError("agent_name_required", "Agent name is required.")

            descriptor = AgentDirectoryDescriptor(
                agent_id=resolved_agent_id,
                name=resolved_name,
                image=ImageReference(
                    type="docker_archive",
                    path="image.tar",
                    digest=image_digest,
                ),
                platform=identity.platform,
                runtime=DynamicRuntimeRequirements(probe_module=probe_module),
                expected_frameworks=_normalized_frameworks(expected_frameworks),
                notes=f"Imported Docker image {identity.repo_tag}.",
            )
            self.storage.write_json(
                incoming / "agent.json",
                descriptor.model_dump(mode="json"),
            )

            suffix = image_digest.removeprefix("sha256:")[:16]
            final_directory = self.storage.managed_agent_asset_dir(
                tenant_id,
                resolved_agent_id,
                suffix,
            )
            final_directory.parent.mkdir(parents=True, exist_ok=True)
            if final_directory.exists():
                self.storage.write_json(
                    final_directory / "agent.json",
                    descriptor.model_dump(mode="json"),
                )
                shutil.rmtree(incoming)
            else:
                os.replace(incoming, final_directory)

            relative_ref = final_directory.relative_to(managed_root).as_posix()
            agent = self.asset_index.index_directory(
                final_directory,
                tenant_id=tenant_id,
                username=username,
                asset_source="managed_upload",
                asset_directory_ref=relative_ref,
                domain=domain,
            )
            profile = self.image_profiles.create(
                tenant_id=tenant_id,
                agent_id=resolved_agent_id,
            )
            return AgentImageImportResult(agent=agent, profile=profile)
        finally:
            if incoming.exists():
                shutil.rmtree(incoming)


def _normalized_frameworks(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        item = value.strip()
        if item and item not in normalized:
            normalized.append(item)
    return normalized


def _repository_from_repo_tag(repo_tag: str) -> str:
    final_slash = repo_tag.rfind("/")
    final_colon = repo_tag.rfind(":")
    return repo_tag[:final_colon] if final_colon > final_slash else repo_tag


def _agent_id_from_repo_tag(repo_tag: str) -> str:
    repository = _repository_from_repo_tag(repo_tag).lower()
    candidate = re.sub(r"[^a-z0-9_.-]+", "-", repository.replace("/", "-"))
    candidate = candidate.strip(".-")[:80]
    if not candidate:
        raise AgentImageUploadError(
            "agent_identity_unavailable",
            "The Docker archive RepoTag cannot be converted to an Agent ID.",
        )
    return candidate


def _agent_name_from_repo_tag(repo_tag: str) -> str:
    repository = _repository_from_repo_tag(repo_tag)
    leaf = repository.rsplit("/", 1)[-1]
    return re.sub(r"[-_]+", " ", leaf).strip() or "Imported Agent"


def _max_upload_bytes_from_environment() -> int:
    configured = os.environ.get("RED_SENTINEL_MAX_IMAGE_UPLOAD_BYTES", "").strip()
    if not configured:
        return _DEFAULT_MAX_UPLOAD_BYTES
    try:
        value = int(configured)
    except ValueError as exc:
        raise ValueError("RED_SENTINEL_MAX_IMAGE_UPLOAD_BYTES must be an integer.") from exc
    if value <= 0:
        raise ValueError("RED_SENTINEL_MAX_IMAGE_UPLOAD_BYTES must be positive.")
    return value


__all__ = [
    "AgentImageImportResult",
    "AgentImageUploadError",
    "AgentImageUploadService",
]
