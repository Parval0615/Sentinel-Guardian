from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


_IGNORED_PARTS = {".git", "__pycache__", ".pytest_cache", ".ruff_cache"}


@dataclass(frozen=True)
class SourceSnapshot:
    source_path: str
    build_manifest_path: str
    source_sha256: str
    build_manifest_sha256: str
    snapshot_sha256: str
    source_file_count: int
    adapter_type: str


def create_source_snapshot(
    source_path: str,
    build_manifest_path: str,
) -> SourceSnapshot:
    source_root = Path(source_path).expanduser().resolve()
    manifest = Path(build_manifest_path).expanduser().resolve()
    if not source_root.is_dir():
        raise ValueError("source_path must reference an existing source directory.")
    if not manifest.is_file():
        raise ValueError("build_manifest_path must reference an existing file.")
    if not manifest.is_relative_to(source_root):
        raise ValueError("build_manifest_path must be inside source_path.")
    manifest_payload = _build_manifest(manifest)

    source_sha256, source_file_count = _hash_source_tree(source_root)
    build_manifest_sha256 = _hash_file(manifest)
    snapshot_sha256 = hashlib.sha256(
        f"{source_sha256}:{build_manifest_sha256}".encode("utf-8")
    ).hexdigest()
    return SourceSnapshot(
        source_path=str(source_root),
        build_manifest_path=str(manifest),
        source_sha256=source_sha256,
        build_manifest_sha256=build_manifest_sha256,
        snapshot_sha256=snapshot_sha256,
        source_file_count=source_file_count,
        adapter_type=manifest_payload["adapter_type"],
    )


def verify_source_snapshot(
    *,
    source_path: str,
    build_manifest_path: str,
    expected_snapshot_sha256: str,
) -> SourceSnapshot:
    snapshot = create_source_snapshot(source_path, build_manifest_path)
    if snapshot.snapshot_sha256 != expected_snapshot_sha256:
        raise ValueError("Agent source snapshot SHA-256 mismatch.")
    return snapshot


def _hash_source_tree(source_root: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    file_count = 0
    for path in sorted(source_root.rglob("*")):
        if not path.is_file() or any(part in _IGNORED_PARTS for part in path.parts):
            continue
        if path.is_symlink():
            raise ValueError("Agent source snapshot does not allow symbolic links.")
        relative = path.relative_to(source_root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(65536), b""):
                digest.update(chunk)
        digest.update(b"\0")
        file_count += 1
    if file_count == 0:
        raise ValueError("source_path must contain at least one source file.")
    return digest.hexdigest(), file_count


def _build_manifest(path: Path) -> dict[str, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("build_manifest_path must contain valid JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Agent sandbox build manifest must be a JSON object.")
    if payload.get("schema_version") != "agent-sandbox-build-v0.1":
        raise ValueError(
            "Agent sandbox build manifest requires "
            "schema_version=agent-sandbox-build-v0.1."
        )
    adapter_type = payload.get("adapter_type")
    if adapter_type not in {"ecommerce_demo", "external_sdk", "openmanus"}:
        raise ValueError(
            "Agent sandbox build manifest adapter_type must be "
            "ecommerce_demo, external_sdk, or openmanus."
        )
    return {"adapter_type": adapter_type}


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "SourceSnapshot",
    "create_source_snapshot",
    "verify_source_snapshot",
]
