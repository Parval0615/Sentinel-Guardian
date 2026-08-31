from __future__ import annotations

import argparse
import io
import json
import plistlib
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts import package_macos_release as release


pytestmark = pytest.mark.fast


def _write_docker_archive(path: Path, architecture: str) -> None:
    config = json.dumps({"os": "linux", "architecture": architecture}).encode()
    config_name = f"{'a' * 64}.json"
    manifest = json.dumps([{"Config": config_name, "Layers": []}]).encode()
    with tarfile.open(path, "w") as archive:
        for name, content in (("manifest.json", manifest), (config_name, config)):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def test_tree_digest_is_stable_and_content_sensitive(tmp_path: Path) -> None:
    root = tmp_path / "frontend"
    root.mkdir()
    (root / "index.html").write_text("one", encoding="utf-8")
    first = release.tree_digest(root)

    assert first == release.tree_digest(root)
    (root / "index.html").write_text("two", encoding="utf-8")
    assert release.tree_digest(root) != first


def test_bundle_version_comes_from_project_metadata(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "sentinel"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )
    app_path = tmp_path / release.APP_NAME
    plist_path = app_path / "Contents" / "Info.plist"
    plist_path.parent.mkdir(parents=True)
    with plist_path.open("wb") as stream:
        plistlib.dump(
            {
                "CFBundleExecutable": release.EXECUTABLE_NAME,
                "CFBundleIdentifier": release.EXPECTED_BUNDLE_ID,
                "CFBundlePackageType": "APPL",
                "CFBundleShortVersionString": "0.0.0",
            },
            stream,
        )
    executable = app_path / "Contents" / "MacOS" / release.EXECUTABLE_NAME
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)

    version = release.read_project_version(tmp_path)
    release.write_bundle_version(app_path, version)
    release.validate_info_plist(app_path, expected_version=version)

    with plist_path.open("rb") as stream:
        payload = plistlib.load(stream)
    assert payload["CFBundleShortVersionString"] == "1.2.3"
    assert payload["CFBundleVersion"] == "1.2.3"


def test_descriptor_payload_matches_contract(tmp_path: Path) -> None:
    descriptor_path = tmp_path / "agent.json"
    digest = "sha256:" + ("a" * 64)
    descriptor_path.write_text(
        json.dumps(release.descriptor_payload(release.AGENT_BUILDS[0], digest)),
        encoding="utf-8",
    )

    payload = release.validate_descriptor(Path.cwd(), descriptor_path)

    assert payload["schema_version"] == "agent-directory-v0.1"
    assert payload["image"]["digest"] == digest
    assert payload["platform"] == "linux/arm64"
    assert payload["runtime"]["probe_module"] == (
        "redsentinel.adapters.engine.ecommerce_agent.runtime"
    )


def test_openmanus_descriptor_uses_explicit_probe_module(tmp_path: Path) -> None:
    descriptor_path = tmp_path / "agent.json"
    payload = release.descriptor_payload(
        release.AGENT_BUILDS[1],
        "sha256:" + ("b" * 64),
    )
    descriptor_path.write_text(json.dumps(payload), encoding="utf-8")

    validated = release.validate_descriptor(Path.cwd(), descriptor_path)

    assert validated["runtime"]["probe_module"] == (
        "redsentinel_runtime.profile_probe_entry"
    )


def test_descriptor_rejects_unsafe_probe_module(tmp_path: Path) -> None:
    descriptor_path = tmp_path / "agent.json"
    payload = release.descriptor_payload(
        release.AGENT_BUILDS[1],
        "sha256:" + ("c" * 64),
    )
    payload["runtime"]["probe_module"] = "app.agent; unsafe"
    descriptor_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(release.PackagingError, match="runtime.probe_module"):
        release.validate_descriptor(Path.cwd(), descriptor_path)


def test_missing_image_archive_is_a_hard_failure(tmp_path: Path) -> None:
    for build in release.AGENT_BUILDS:
        directory = tmp_path / "agents" / build.directory
        directory.mkdir(parents=True)
        (directory / "agent.json").write_text(
            json.dumps(
                release.descriptor_payload(
                    build,
                    "sha256:" + ("0" * 64),
                )
            ),
            encoding="utf-8",
        )

    with pytest.raises(release.PackagingError, match="缺少必需镜像归档"):
        release.verify_required_images(tmp_path)


def test_archive_platform_is_verified_without_docker(tmp_path: Path) -> None:
    for build in release.AGENT_BUILDS:
        directory = tmp_path / "agents" / build.directory
        directory.mkdir(parents=True)
        image = directory / "image.tar"
        architecture = "amd64" if build.directory == "openmanus" else "arm64"
        _write_docker_archive(image, architecture)
        (directory / "agent.json").write_text(
            json.dumps(release.descriptor_payload(build, release.sha256_file(image))),
            encoding="utf-8",
        )

    with pytest.raises(release.PackagingError, match="镜像归档平台错误"):
        release.verify_required_images(tmp_path)


def test_command_timeout_is_reported_as_packaging_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def expire(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(["docker", "build"], 5)

    monkeypatch.setattr(subprocess, "run", expire)

    with pytest.raises(release.PackagingError, match=r"命令超时 \(5s\)"):
        release.run(["docker", "build"], cwd=tmp_path, timeout=5)


def test_build_app_packages_dynamic_probe_runtime(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    release.build_app(tmp_path, dry_run=True)

    stdout = capsys.readouterr().out
    expected = (
        f"{tmp_path / 'src' / 'redsentinel' / 'profiling' / 'image' / 'probe_runtime.py'}"
        ":redsentinel/profiling/image"
    )
    assert expected in stdout


def test_build_app_packages_ecommerce_demo_source(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    release.build_app(tmp_path, dry_run=True)

    stdout = capsys.readouterr().out
    expected = (
        f"{tmp_path / 'src' / 'redsentinel' / 'adapters' / 'engine' / 'ecommerce_agent'}"
        ":builtin-agents/ecommerce"
    )
    assert expected in stdout


def test_dynamic_probe_runtime_is_required_in_app_bundle(tmp_path: Path) -> None:
    app_path = tmp_path / release.APP_NAME

    with pytest.raises(release.PackagingError, match="缺少动态画像探针资源"):
        release.validate_dynamic_probe_resource(app_path)

    probe_runtime = (
        app_path
        / "Contents"
        / "Frameworks"
        / "redsentinel"
        / "profiling"
        / "image"
        / "probe_runtime.py"
    )
    probe_runtime.parent.mkdir(parents=True)
    probe_runtime.write_text("raise SystemExit(0)\n", encoding="utf-8")
    release.validate_dynamic_probe_resource(app_path)


def test_dry_run_does_not_create_release_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    (repo / "agents" / "电商").mkdir(parents=True)
    (repo / "agents" / "openmanus").mkdir()
    (repo / "frontend").mkdir()
    (repo / "infra" / "openmanus").mkdir(parents=True)
    (repo / "agents" / "电商" / "Dockerfile").write_text("FROM scratch\n")
    (repo / "infra" / "openmanus" / "Dockerfile").write_text("FROM scratch\n")
    output = repo / "dist" / release.DEFAULT_RELEASE_NAME
    zip_path = output.with_suffix(".zip")
    args = argparse.Namespace(
        repo_root=repo,
        output_dir=output,
        zip_path=zip_path,
        reuse_app=repo / release.APP_NAME,
        reuse_images=False,
        reuse_archives=False,
        docker_timeout=1200,
        skip_launch_check=False,
        dry_run=True,
    )

    actual_output, actual_zip = release.package_release(args)

    assert (actual_output, actual_zip) == (output.resolve(), zip_path.resolve())
    assert not output.exists()
    assert not zip_path.exists()
    stdout = capsys.readouterr().out
    assert "docker build --platform linux/arm64" in stdout
    assert "npm run build" in stdout
    assert "create ZIP" in stdout
