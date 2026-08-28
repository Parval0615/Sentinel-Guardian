from __future__ import annotations

import json

import pytest

from redsentinel.application.engine.source_ingress import (
    create_source_snapshot,
    verify_source_snapshot,
)


def _source_tree(tmp_path):
    source_root = tmp_path / "agent-source"
    source_root.mkdir()
    (source_root / "agent.py").write_text(
        "def run(task):\n    return task\n",
        encoding="utf-8",
    )
    manifest = source_root / "sandbox-build.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "agent-sandbox-build-v0.1",
                "adapter_type": "external_sdk",
            }
        ),
        encoding="utf-8",
    )
    return source_root, manifest


def test_source_snapshot_is_deterministic_and_detects_mutation(tmp_path) -> None:
    source_root, manifest = _source_tree(tmp_path)
    snapshot = create_source_snapshot(str(source_root), str(manifest))

    assert snapshot.source_file_count == 2
    assert len(snapshot.snapshot_sha256) == 64
    assert (
        verify_source_snapshot(
            source_path=str(source_root),
            build_manifest_path=str(manifest),
            expected_snapshot_sha256=snapshot.snapshot_sha256,
        )
        == snapshot
    )

    (source_root / "agent.py").write_text(
        "def run(task):\n    return {'changed': task}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="snapshot SHA-256 mismatch"):
        verify_source_snapshot(
            source_path=str(source_root),
            build_manifest_path=str(manifest),
            expected_snapshot_sha256=snapshot.snapshot_sha256,
        )


def test_source_snapshot_rejects_remote_or_prebuilt_manifest_shapes(tmp_path) -> None:
    source_root, manifest = _source_tree(tmp_path)
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "agent-sandbox-build-v0.1",
                "adapter_type": "http_endpoint",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="adapter_type"):
        create_source_snapshot(str(source_root), str(manifest))
