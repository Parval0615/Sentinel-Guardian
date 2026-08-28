from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from redsentinel.profiling import (
    FileRecord,
    ParsedImageArtifact,
    SanitizedImageConfig,
    StaticExtractionLimits,
    StaticFactIndex,
    extract_static_facts,
)


IMAGE_DIGEST = f"sha256:{'a' * 64}"
LAYER_DIGEST = f"sha256:{'b' * 64}"


def _write(root: Path, relative: str, content: str | bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _parsed_image(root: Path, *, command: tuple[str, ...] = ()) -> ParsedImageArtifact:
    records = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        content = path.read_bytes()
        records.append(
            FileRecord(
                path=path.relative_to(root).as_posix(),
                file_type="file",
                size=len(content),
                layer_digest=LAYER_DIGEST,
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
    return ParsedImageArtifact(
        image_type="docker_archive",
        image_digest=IMAGE_DIGEST,
        config=SanitizedImageConfig(
            entrypoint=("python", "-m", "agent"),
            cmd=command,
            working_dir="/workspace",
            env_keys=("OPENAI_API_KEY", "MODEL_NAME"),
        ),
        layers=(),
        files=tuple(records),
        rootfs_path=root,
    )


def _all_facts(index: StaticFactIndex) -> list[object]:
    return [
        *index.modules,
        *index.symbols,
        *index.imports,
        *index.calls,
        *index.decorators,
        *index.class_bases,
        *index.dependencies,
        *index.entrypoints,
        *index.configuration,
        *index.capabilities,
        *index.limitations,
    ]


def test_extracts_source_dependencies_metadata_and_all_entrypoint_forms(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    _write(root, "workspace/agent/__init__.py", "")
    _write(root, "workspace/agent/__main__.py", "from .app import main\nmain()\n")
    _write(root, "workspace/requirements.txt", "requests==2.32.0\n-r private.txt\n")
    _write(
        root,
        "workspace/pyproject.toml",
        """
[project]
name = "agent"
dependencies = ["pydantic>=2", "httpx[http2]~=0.27"]
[project.scripts]
agent-cli = "agent.app:main"
[tool.poetry.dependencies]
python = "^3.10"
redis = "^5"
[tool.poetry.scripts]
agent-worker = "agent.worker:run"
""",
    )
    _write(
        root,
        "workspace/setup.py",
        """
from setuptools import setup
setup(
    install_requires=["sqlalchemy>=2"],
    entry_points={"console_scripts": ["legacy-agent=agent.app:main"]},
)
""",
    )
    _write(
        root,
        "workspace/setup.cfg",
        """
[options]
install_requires =
    PyYAML>=6
[options.entry_points]
console_scripts =
    cfg-agent = agent.app:main
""",
    )
    _write(
        root,
        "workspace/poetry.lock",
        """
[[package]]
name = "tenacity"
version = "8.2.3"
""",
    )
    _write(root, "workspace/requirements.lock", "orjson==3.10.0 --hash=sha256:deadbeef\n")
    _write(root, "workspace/requirements.lock", "orjson==3.10.0 --hash=sha256:deadbeef\n")
    _write(root, "workspace/requirements.lock", "orjson==3.10.0 --hash=sha256:deadbeef\n")
    _write(root, "workspace/requirements.lock", "orjson==3.10.0 --hash=sha256:deadbeef\n")
    _write(
        root,
        "usr/lib/python3.10/site-packages/demo-1.2.dist-info/METADATA",
        "Metadata-Version: 2.1\nName: demo\nVersion: 1.2\nRequires-Dist: anyio (>=3)\n",
    )
    _write(
        root,
        "usr/lib/python3.10/site-packages/demo-1.2.dist-info/entry_points.txt",
        "[console_scripts]\ndemo = demo.cli:main\n",
    )
    _write(root, "usr/lib/python3.10/site-packages/demo/__init__.py", "__version__ = '1.2'\n")
    _write(root, "usr/local/lib/python3.12/stdlib.py", "def runtime_helper():\n    return 1\n")
    _write(root, "opt/support/monitor.py", "def support_helper():\n    return 1\n")

    index = extract_static_facts(_parsed_image(root))

    assert index.schema_version == "static-fact-index-v0.1"
    assert index.source_recovery == "complete"
    assert {(item.module, item.source_kind) for item in index.modules} >= {
        ("agent", "project"),
        ("agent.__main__", "project"),
        ("demo", "site_package"),
        ("usr.local.lib.python3.12.stdlib", "runtime"),
        ("support.monitor", "runtime"),
    }
    assert not any(item.qualified_name in {"runtime_helper", "support_helper"} for item in index.symbols)
    assert {item.code for item in index.limitations} >= {
        "dependency_source_omitted",
        "runtime_source_omitted",
    }
    dependencies = {(item.name.lower(), item.version, item.source) for item in index.dependencies}
    assert ("requests", "==2.32.0", "requirements") in dependencies
    assert ("pydantic", ">=2", "pyproject") in dependencies
    assert ("httpx", "~=0.27", "pyproject") in dependencies
    assert ("redis", "^5", "pyproject") in dependencies
    assert ("sqlalchemy", ">=2", "setup") in dependencies
    assert ("pyyaml", ">=6", "setup") in dependencies
    assert ("tenacity", "8.2.3", "lock") in dependencies
    assert ("orjson", "==3.10.0", "lock") in dependencies
    assert ("orjson", "==3.10.0", "lock") in dependencies
    assert ("orjson", "==3.10.0", "lock") in dependencies
    assert ("orjson", "==3.10.0", "lock") in dependencies
    assert ("demo", "1.2", "dist_info") in dependencies
    assert ("anyio", "(>=3)", "dist_info") in dependencies
    entrypoints = {(item.kind, item.name, item.module, item.symbol) for item in index.entrypoints}
    assert ("image", "image-command", "agent", None) in entrypoints
    assert ("module", "agent", "agent", None) in entrypoints
    assert ("project_script", "agent-cli", "agent.app", "main") in entrypoints
    assert ("project_script", "legacy-agent", "agent.app", "main") in entrypoints
    assert ("project_script", "cfg-agent", "agent.app", "main") in entrypoints
    assert ("console_script", "demo", "demo.cli", "main") in entrypoints


def test_builds_ast_index_and_capability_clues_without_graph_or_risk_paths(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    _write(
        root,
        "workspace/agent.py",
        """
import os
import sqlite3
import subprocess
import requests
from mcp.server.fastmcp import FastMCP
from openai import OpenAI
from pathlib import Path
from playwright.sync_api import sync_playwright

API_TOKEN = "must-never-appear"
SERVICE_URL = "https://user:password@example.test/private?token=secret"

class Agent(BaseAgent):
    @tool("search")
    def run(self, query: str):
        token = os.getenv("SERVICE_PASSWORD", "also-secret")
        OpenAI()
        sqlite3.connect("private.db")
        FastMCP("private-name")
        requests.post("https://private.example/api", data=query)
        subprocess.run(["sh", "-c", query])
        Path("private.txt").write_text(query)
        sync_playwright()
        return token
""",
    )

    index = extract_static_facts(root)

    assert index.source_recovery == "complete"
    assert {(item.qualified_name, item.symbol_kind) for item in index.symbols} == {
        ("Agent", "class"),
        ("Agent.run", "function"),
    }
    assert any(item.imported_module == "mcp.server.fastmcp" and item.imported_name == "FastMCP" for item in index.imports)
    assert any(item.caller == "Agent.run" and item.callee == "subprocess.run" for item in index.calls)
    assert any(item.symbol == "Agent.run" and item.decorator == "tool" for item in index.decorators)
    assert any(item.class_name == "Agent" and item.base == "BaseAgent" for item in index.class_bases)
    assert {item.capability for item in index.capabilities} == {
        "model",
        "database",
        "mcp",
        "external_api",
        "shell",
        "file",
        "browser",
    }
    configs = {(item.category, item.key, item.value_type, item.is_sensitive) for item in index.configuration}
    assert ("constant", "API_TOKEN", "str", True) in configs
    assert ("constant", "SERVICE_URL", "str", False) in configs
    assert ("environment", "SERVICE_PASSWORD", "presence", True) in configs
    assert not hasattr(index, "risk_paths")
    assert not hasattr(index, "frameworks")


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({"app.py": "def run():\n    return 1\n"}, "complete"),
        ({"app.py": "def broken(:\n"}, "partial"),
        ({"demo-1.dist-info/METADATA": "Name: demo\nVersion: 1\n"}, "metadata_only"),
        ({"__pycache__/app.cpython-310.pyc": b"bytecode"}, "bytecode_only"),
        ({"native.cpython-310-x86_64-linux-gnu.so": b"binary"}, "bytecode_only"),
        ({"README": "no Python artifacts"}, "none"),
    ],
)
def test_source_recovery_matrix(
    tmp_path: Path,
    files: dict[str, str | bytes],
    expected: str,
) -> None:
    root = tmp_path / "rootfs"
    root.mkdir()
    for relative, content in files.items():
        _write(root, relative, content)

    index = extract_static_facts(root)

    assert index.source_recovery == expected
    if expected == "partial":
        assert any(item.code == "syntax_error" for item in index.limitations)
        assert any(item.code == "source_partial" for item in index.limitations)
    if expected in {"metadata_only", "bytecode_only", "none"}:
        assert any(item.code == "source_missing" for item in index.limitations)


def test_mixed_source_and_unmatched_bytecode_is_partial(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    _write(root, "workspace/app.py", "def main():\n    return 0\n")
    _write(root, "workspace/__pycache__/plugin.cpython-310.pyc", b"bytecode")

    index = extract_static_facts(root)

    assert index.source_recovery == "partial"
    assert {(item.module, item.source_kind) for item in index.modules} == {
        ("app", "project"),
        ("plugin", "bytecode"),
    }


def test_dependency_and_runtime_binaries_do_not_reduce_project_source_recovery(
    tmp_path: Path,
) -> None:
    root = tmp_path / "rootfs"
    _write(root, "workspace/app.py", "def main():\n    return 0\n")
    _write(
        root,
        "usr/local/lib/python3.12/site-packages/demo/__pycache__/only.cpython-312.pyc",
        b"bytecode",
    )
    _write(
        root,
        "usr/lib/aarch64-linux-gnu/dri/driver.so",
        b"x" * 64,
    )

    index = extract_static_facts(
        _parsed_image(root),
        limits=StaticExtractionLimits(max_file_size=32),
    )

    assert index.source_recovery == "complete"
    assert any(item.image_path.endswith("driver.so") for item in index.modules)
    assert not any(item.code == "file_too_large" for item in index.limitations)


def test_every_fact_has_bound_profile_evidence_and_layer_provenance(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    _write(root, "workspace/agent.py", "import subprocess\n\ndef run():\n    subprocess.run(['true'])\n")

    index = extract_static_facts(_parsed_image(root))

    facts = _all_facts(index)
    assert facts
    assert all(fact.evidence.artifact_digest == IMAGE_DIGEST for fact in facts)
    file_facts = [fact for fact in facts if fact.evidence.method != "image_config"]
    config_facts = [fact for fact in facts if fact.evidence.method == "image_config"]
    assert all(fact.evidence.layer_digest == LAYER_DIGEST for fact in file_facts)
    assert all(fact.evidence.locator.image_path == "/workspace/agent.py" for fact in file_facts)
    assert all(fact.evidence.layer_digest is None for fact in config_facts)
    assert all(fact.evidence.locator.config_key for fact in config_facts)
    assert all(len(fact.evidence.content_sha256) == 64 for fact in facts)
    assert len({fact.fact_id for fact in facts}) == len(facts)


def test_environment_constants_and_sensitive_command_arguments_are_redacted(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    _write(
        root,
        "workspace/agent.py",
        """
import os
API_KEY = "source-api-secret"
NORMAL_LIMIT = 42
password = os.environ["DATABASE_PASSWORD"]
""",
    )
    image = _parsed_image(root, command=("--api-key=command-secret", "--password", "next-secret"))

    index = extract_static_facts(image)
    payload = json.dumps(index.model_dump(mode="json"), sort_keys=True)

    assert "source-api-secret" not in payload
    assert "command-secret" not in payload
    assert "next-secret" not in payload
    assert "top-secret" not in payload
    assert "[REDACTED]" in payload
    assert set(item.key for item in index.configuration) >= {
        "API_KEY",
        "NORMAL_LIMIT",
        "DATABASE_PASSWORD",
        "OPENAI_API_KEY",
        "MODEL_NAME",
    }
    image_entrypoint = next(item for item in index.entrypoints if item.kind == "image")
    assert image_entrypoint.command[-3:] == ("--api-key=[REDACTED]", "--password", "[REDACTED]")


def test_rootfs_digest_is_deterministic_and_explicit_digest_is_validated(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    _write(root, "app.py", "def run():\n    return 1\n")

    first = extract_static_facts(root)
    second = extract_static_facts(root)

    assert first.artifact_digest == second.artifact_digest
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    with pytest.raises(ValueError, match="sha256"):
        extract_static_facts(root, artifact_digest="invalid")


def test_static_fact_index_rejects_cross_artifact_evidence(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    _write(root, "app.py", "def run():\n    return 1\n")
    index = extract_static_facts(root)
    payload = index.model_dump(mode="json")
    payload["artifact_digest"] = IMAGE_DIGEST

    with pytest.raises(ValidationError, match="bind"):
        StaticFactIndex.model_validate(payload)


def test_limits_skip_large_source_and_reject_excess_inventory(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    _write(root, "large.py", "x = 1\n")

    skipped = extract_static_facts(root, limits=StaticExtractionLimits(max_file_size=2))

    assert skipped.source_recovery == "partial"
    assert any(item.code == "file_too_large" for item in skipped.limitations)
    _write(root, "other.py", "x = 2\n")
    with pytest.raises(ValueError, match="file count"):
        extract_static_facts(root, limits=StaticExtractionLimits(max_files=1))


def test_symlinks_are_not_followed_for_raw_rootfs(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    outside = tmp_path / "outside.py"
    root.mkdir()
    outside.write_text("API_KEY = 'outside-secret'\n", encoding="utf-8")
    (root / "linked.py").symlink_to(outside)

    index = extract_static_facts(root)

    assert index.source_recovery == "none"
    assert "outside-secret" not in json.dumps(index.model_dump(mode="json"))
