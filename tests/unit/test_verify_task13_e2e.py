import hashlib
import json
from pathlib import Path

import pytest

from scripts.generate_task15_artifacts import _artifact_names, _desktop_http_smoke
from scripts.verify_task13_e2e import _ensure_artifacts, _required_artifacts


def _write_required_artifacts(root: Path) -> None:
    for path in _required_artifacts(root):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")


def test_missing_docker_artifacts_are_not_replaced_with_offline_output(
    tmp_path: Path,
) -> None:
    artifacts_root = tmp_path / "artifacts"

    with pytest.raises(RuntimeError, match="Docker-backed artifacts are missing"):
        _ensure_artifacts(tmp_path / "repo", artifacts_root)


def test_docker_artifact_set_is_accepted(tmp_path: Path) -> None:
    artifacts_root = tmp_path / "artifacts"
    _write_required_artifacts(artifacts_root)

    _ensure_artifacts(tmp_path, artifacts_root)


def test_offline_and_docker_artifact_names_are_distinct(tmp_path: Path) -> None:
    partial_root, partial_prefix = _artifact_names(tmp_path, "partial")
    docker_root, docker_prefix = _artifact_names(tmp_path, "docker")

    assert partial_root == tmp_path / "task15-partial"
    assert partial_prefix == "task13-partial"
    assert docker_root == tmp_path / "task15"
    assert docker_prefix == "task13"


def test_desktop_smoke_discovers_profile_pending_agents(tmp_path: Path) -> None:
    agents_root = tmp_path / "agents"
    for directory, agent_id in (("电商", "ecommerce"), ("openmanus", "openmanus")):
        root = agents_root / directory
        root.mkdir(parents=True)
        image = b"deterministic archive fixture"
        (root / "image.tar").write_bytes(image)
        (root / "agent.json").write_text(
            json.dumps(
                {
                    "schema_version": "agent-directory-v0.1",
                    "agent_id": agent_id,
                    "name": agent_id,
                    "image": {
                        "type": "docker_archive",
                        "path": "image.tar",
                        "digest": f"sha256:{hashlib.sha256(image).hexdigest()}",
                    },
                }
            ),
            encoding="utf-8",
        )

    result = _desktop_http_smoke(agents_root, tmp_path / "storage")

    assert result["health"] == 200
    assert result["agent_ids"] == ["ecommerce", "openmanus"]
