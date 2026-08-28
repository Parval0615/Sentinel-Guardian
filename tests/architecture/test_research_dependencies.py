from __future__ import annotations

import ast
from pathlib import Path

from redsentinel.core.architecture import (
    ALLOWED_INTERNAL_DEPENDENCIES,
    is_allowed_internal_dependency,
    package_layer,
)


def test_dependency_policy_has_expected_core_boundary() -> None:
    assert ALLOWED_INTERNAL_DEPENDENCIES["core"] == frozenset()
    assert is_allowed_internal_dependency("redsentinel.attacks.generator", "redsentinel.core.models")
    assert not is_allowed_internal_dependency("redsentinel.core.models", "redsentinel.attacks.generator")
    assert not is_allowed_internal_dependency("redsentinel.evaluation.oracle", "redsentinel.adapters.openmanus")
    assert package_layer("redsentinel.core.models") == "core"
    assert package_layer("external.module") is None


def test_current_research_package_respects_internal_dependency_policy() -> None:
    source_root = Path("src/redsentinel")
    violations: list[str] = []

    for path in source_root.rglob("*.py"):
        importer = _module_name(path, source_root.parent)
        for imported in _redsentinel_imports(path):
            if not is_allowed_internal_dependency(importer, imported):
                violations.append(f"{importer} -> {imported}")

    assert violations == []


def test_core_does_not_import_legacy_or_application_packages() -> None:
    forbidden_prefixes = (
        "agent_integration_system",
        "auto_attack_system",
        "auto_defense_system",
        "auto_evaluation_system",
        "agent_security_sdk",
        "fastapi",
    )
    violations: list[str] = []

    for path in Path("src/redsentinel/core").rglob("*.py"):
        for imported in _all_imports(path):
            if imported.startswith(forbidden_prefixes):
                violations.append(f"{path}: {imported}")

    assert violations == []


def test_legacy_package_roots_are_removed() -> None:
    for name in (
        "agent_integration_system",
        "auto_attack_system",
        "auto_defense_system",
        "auto_evaluation_system",
        "sdk",
    ):
        assert not Path(name).exists()


def test_openmanus_runtime_does_not_reference_legacy_packages() -> None:
    paths = (
        Path("infra/openmanus/Dockerfile"),
        Path("third_party/OpenManus/redsentinel_runtime"),
    )
    forbidden = (
        "agent_integration_system",
        "auto_attack_system",
        "auto_defense_system",
        "auto_evaluation_system",
        "agent_security_sdk",
    )
    violations: list[str] = []

    for root in paths:
        files = [root] if root.is_file() else root.rglob("*.py")
        for path in files:
            text = path.read_text(encoding="utf-8")
            for name in forbidden:
                if name in text:
                    violations.append(f"{path}: {name}")

    assert violations == []


def test_openmanus_image_uses_system_chromium_without_playwright_download() -> None:
    dockerfile = Path("infra/openmanus/Dockerfile").read_text(encoding="utf-8")

    assert "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1" in dockerfile
    assert "chromium \\" in dockerfile
    assert "python -m playwright install" not in dockerfile
    assert "p.chromium.launch(headless=True)" in dockerfile


def _module_name(path: Path, src_root: Path) -> str:
    relative = path.relative_to(src_root).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _redsentinel_imports(path: Path) -> list[str]:
    return [name for name in _all_imports(path) if name == "redsentinel" or name.startswith("redsentinel.")]


def _all_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    return imports
