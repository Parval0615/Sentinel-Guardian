#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

APP_NAME = "Sentinel Guardian.app"
EXECUTABLE_NAME = "Sentinel Guardian"
EXPECTED_BUNDLE_ID = "ai.redsentinel.guardian"
EXPECTED_PLATFORM = "linux/arm64"
OPENMANUS_BASE_DIGEST = (
    "sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134"
)
DEFAULT_RELEASE_NAME = "Sentinel Guardian-macOS-arm64"
HASH_CHUNK_SIZE = 1024 * 1024
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
PYTHON_MODULE_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)
PROJECT_VERSION_PATTERN = re.compile(
    r'(?ms)^\[project\]\s*$.*?^version\s*=\s*"([0-9]+(?:\.[0-9]+){1,2})"\s*$'
)


class PackagingError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentBuild:
    directory: str
    image: str
    dockerfile: str


AGENT_BUILDS = (
    AgentBuild("电商", "redsentinel/ecommerce-agent:task12", "agents/电商/Dockerfile"),
    AgentBuild("openmanus", "redsentinel/openmanus-real:task12", "infra/openmanus/Dockerfile"),
)


def run(
    command: Sequence[str],
    *,
    cwd: Path,
    dry_run: bool = False,
    capture: bool = False,
    quiet: bool = False,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    if not quiet:
        print("+", " ".join(command))
    if dry_run:
        return subprocess.CompletedProcess(command, 0, "", "")
    try:
        return subprocess.run(
            list(command),
            cwd=cwd,
            check=True,
            text=True,
            capture_output=capture,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise PackagingError(f"缺少必需命令: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise PackagingError(f"命令失败 ({exc.returncode}): {' '.join(command)}{suffix}") from exc
    except subprocess.TimeoutExpired as exc:
        raise PackagingError(
            f"命令超时 ({timeout:.0f}s): {' '.join(command)}"
        ) from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(HASH_CHUNK_SIZE):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files:
        raise PackagingError(f"目录没有可哈希文件: {root}")
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        size = path.stat().st_size
        digest.update(size.to_bytes(8, "big"))
        with path.open("rb") as stream:
            while chunk := stream.read(HASH_CHUNK_SIZE):
                digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def descriptor_payload(build: AgentBuild, digest: str) -> dict[str, object]:
    if build.directory == "电商":
        return {
            "schema_version": "agent-directory-v0.1",
            "agent_id": "ecommerce",
            "name": "电商客服 Agent",
            "image": {
                "type": "docker_archive",
                "path": "image.tar",
                "digest": digest,
            },
            "platform": EXPECTED_PLATFORM,
            "runtime": {
                "requires_privileged": False,
                "required_host_mounts": [],
                "probe_module": "redsentinel.adapters.engine.ecommerce_agent.runtime",
            },
            "expected_frameworks": ["custom"],
            "notes": "Deterministic ecommerce Agent built from agents/电商/Dockerfile.",
        }
    return {
        "schema_version": "agent-directory-v0.1",
        "agent_id": "openmanus",
        "name": "OpenManus Agent",
        "image": {
            "type": "docker_archive",
            "path": "image.tar",
            "digest": digest,
        },
        "platform": EXPECTED_PLATFORM,
        "runtime": {
            "requires_privileged": False,
            "required_host_mounts": [],
            "probe_module": "redsentinel_runtime.profile_probe_entry",
        },
        "expected_frameworks": ["OpenManus", "MCP"],
        "notes": (
            "OpenManus runtime built for linux/arm64 from "
            "infra/openmanus/Dockerfile with python:3.12-slim-bookworm "
            f"pinned at {OPENMANUS_BASE_DIGEST}."
        ),
    }


def validate_descriptor(repo_root: Path, descriptor_path: Path) -> dict[str, object]:
    try:
        payload = json.loads(descriptor_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackagingError(f"Agent descriptor 无效: {descriptor_path}: {exc}") from exc
    allowed = {
        "schema_version",
        "agent_id",
        "name",
        "image",
        "platform",
        "runtime",
        "expected_frameworks",
        "notes",
    }
    if not isinstance(payload, dict) or set(payload) - allowed:
        raise PackagingError(f"Agent descriptor 字段无效: {descriptor_path}")
    if payload.get("schema_version") != "agent-directory-v0.1":
        raise PackagingError(f"Agent descriptor schema_version 无效: {descriptor_path}")
    agent_id = payload.get("agent_id")
    if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
        raise PackagingError(f"Agent descriptor agent_id 无效: {descriptor_path}")
    if not isinstance(payload.get("name"), str) or not payload["name"]:
        raise PackagingError(f"Agent descriptor name 无效: {descriptor_path}")
    image = payload.get("image")
    if not isinstance(image, dict) or set(image) - {"type", "path", "digest"}:
        raise PackagingError(f"Agent descriptor image 无效: {descriptor_path}")
    if image.get("type") not in {"docker_archive", "oci_layout"}:
        raise PackagingError(f"Agent descriptor image.type 无效: {descriptor_path}")
    image_path = image.get("path")
    if not isinstance(image_path, str):
        raise PackagingError(f"Agent descriptor image.path 无效: {descriptor_path}")
    normalized = PurePosixPath(image_path)
    if (
        "\\" in image_path
        or normalized.is_absolute()
        or image_path in {"", "."}
        or ".." in normalized.parts
        or str(normalized) != image_path
    ):
        raise PackagingError(f"Agent descriptor image.path 无效: {descriptor_path}")
    digest = image.get("digest")
    if digest is not None and (
        not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest)
    ):
        raise PackagingError(f"Agent descriptor image.digest 无效: {descriptor_path}")
    runtime = payload.get("runtime", {})
    if not isinstance(runtime, dict) or set(runtime) - {
        "requires_privileged",
        "required_host_mounts",
        "probe_module",
    }:
        raise PackagingError(f"Agent descriptor runtime 无效: {descriptor_path}")
    if not isinstance(runtime.get("requires_privileged", False), bool):
        raise PackagingError(
            f"Agent descriptor runtime.requires_privileged 无效: {descriptor_path}"
        )
    host_mounts = runtime.get("required_host_mounts", [])
    if (
        not isinstance(host_mounts, list)
        or any(
            not isinstance(item, str) or not item.startswith("/") or "\x00" in item
            for item in host_mounts
        )
        or len(host_mounts) != len(set(host_mounts))
    ):
        raise PackagingError(
            f"Agent descriptor runtime.required_host_mounts 无效: {descriptor_path}"
        )
    probe_module = runtime.get("probe_module")
    if probe_module is not None and (
        not isinstance(probe_module, str)
        or not PYTHON_MODULE_PATTERN.fullmatch(probe_module)
    ):
        raise PackagingError(
            f"Agent descriptor runtime.probe_module 无效: {descriptor_path}"
        )
    frameworks = payload.get("expected_frameworks", [])
    if (
        not isinstance(frameworks, list)
        or any(not isinstance(item, str) or not item.strip() for item in frameworks)
        or len(frameworks) != len(set(frameworks))
    ):
        raise PackagingError(f"Agent descriptor expected_frameworks 无效: {descriptor_path}")
    return payload


def docker_available(repo_root: Path, *, dry_run: bool) -> None:
    if dry_run:
        return
    run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        cwd=repo_root,
        capture=True,
        quiet=True,
    )


def image_platform(repo_root: Path, image: str) -> str:
    result = run(
        ["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image],
        cwd=repo_root,
        capture=True,
        quiet=True,
    )
    return result.stdout.strip()


def build_and_export_images(
    repo_root: Path,
    *,
    reuse_images: bool,
    dry_run: bool,
    timeout: float = 1200,
) -> None:
    docker_available(repo_root, dry_run=dry_run)
    for build in AGENT_BUILDS:
        dockerfile = repo_root / build.dockerfile
        if not dockerfile.is_file():
            raise PackagingError(f"缺少 Dockerfile: {dockerfile}")
        if not reuse_images:
            run(
                [
                    "docker",
                    "build",
                    "--platform",
                    EXPECTED_PLATFORM,
                    "--build-arg",
                    "SOURCE_DATE_EPOCH=0",
                    "--provenance=false",
                    "-f",
                    str(dockerfile),
                    "-t",
                    build.image,
                    ".",
                ],
                cwd=repo_root,
                dry_run=dry_run,
                timeout=timeout,
            )
        if dry_run:
            print(f"+ validate Docker image platform {build.image} == {EXPECTED_PLATFORM}")
            print(f"+ docker save {build.image} -> agents/{build.directory}/image.tar")
            continue
        platform = image_platform(repo_root, build.image)
        if platform != EXPECTED_PLATFORM:
            raise PackagingError(
                f"镜像平台错误: {build.image} 是 {platform!r}，要求 {EXPECTED_PLATFORM!r}"
            )
        agent_dir = repo_root / "agents" / build.directory
        agent_dir.mkdir(parents=True, exist_ok=True)
        temporary = agent_dir / f".image-{uuid.uuid4().hex}.tar"
        try:
            run(
                ["docker", "save", "--output", str(temporary), build.image],
                cwd=repo_root,
                timeout=timeout,
            )
            if not temporary.is_file() or temporary.stat().st_size == 0:
                raise PackagingError(f"docker save 未生成有效归档: {build.image}")
            digest = sha256_file(temporary)
            temporary.replace(agent_dir / "image.tar")
            payload = descriptor_payload(build, digest)
            (agent_dir / "agent.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            validate_descriptor(repo_root, agent_dir / "agent.json")
        finally:
            temporary.unlink(missing_ok=True)


def build_frontend(repo_root: Path, *, dry_run: bool) -> None:
    frontend = repo_root / "frontend"
    if not (frontend / "node_modules").is_dir():
        run(["npm", "install"], cwd=frontend, dry_run=dry_run)
    run(["npm", "run", "build"], cwd=frontend, dry_run=dry_run)
    if not dry_run and not (frontend / "dist" / "index.html").is_file():
        raise PackagingError("前端构建成功但 frontend/dist/index.html 不存在")


def build_app(repo_root: Path, *, dry_run: bool) -> Path:
    output = repo_root / "build" / "task12-desktop"
    executable = repo_root / ".venv" / "bin" / "python"
    if not executable.is_file():
        executable = Path(sys.executable)
    run(
        [
            "env",
            f"PYINSTALLER_CONFIG_DIR={output / 'cache'}",
            str(executable),
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--windowed",
            "--name",
            EXECUTABLE_NAME,
            "--osx-bundle-identifier",
            EXPECTED_BUNDLE_ID,
            "--distpath",
            str(output / "dist"),
            "--workpath",
            str(output / "work"),
            "--specpath",
            str(output),
            "--collect-all",
            "webview",
            "--add-data",
            f"{repo_root / 'frontend' / 'dist'}:frontend/dist",
            "--add-data",
            f"{repo_root / 'configs'}:configs",
            "--add-data",
            (
                f"{repo_root / 'src' / 'redsentinel' / 'profiling' / 'image' / 'probe_runtime.py'}"
                ":redsentinel/profiling/image"
            ),
            "--add-data",
            (
                f"{repo_root / 'src' / 'redsentinel' / 'adapters' / 'engine' / 'ecommerce_agent'}"
                ":builtin-agents/ecommerce"
            ),
            str(repo_root / "src" / "redsentinel" / "apps" / "desktop_launcher.py"),
        ],
        cwd=repo_root,
        dry_run=dry_run,
    )
    return output / "dist" / APP_NAME


def verify_required_images(repo_root: Path) -> None:
    for build in AGENT_BUILDS:
        directory = repo_root / "agents" / build.directory
        image = directory / "image.tar"
        descriptor_path = directory / "agent.json"
        if not image.is_file() or image.stat().st_size == 0:
            raise PackagingError(f"缺少必需镜像归档: {image}")
        descriptor = validate_descriptor(repo_root, descriptor_path)
        if not descriptor.get("runtime", {}).get("probe_module"):  # type: ignore[union-attr]
            raise PackagingError(
                f"必需镜像缺少 runtime.probe_module: {descriptor_path}"
            )
        expected = descriptor["image"]["digest"]  # type: ignore[index]
        actual = sha256_file(image)
        if expected != actual:
            raise PackagingError(
                f"镜像摘要不匹配: {image} descriptor={expected} actual={actual}"
            )
        with tarfile.open(image, "r:*") as archive:
            members = {
                member.name.removeprefix("./"): member
                for member in archive.getmembers()
                if member.isfile()
            }
            manifest_member = members.get("manifest.json")
            if manifest_member is None:
                raise PackagingError(f"镜像不是 docker save 兼容归档: {image}")
            manifest_stream = archive.extractfile(manifest_member)
            if manifest_stream is None:
                raise PackagingError(f"无法读取镜像 manifest: {image}")
            manifest = json.load(manifest_stream)
            if not isinstance(manifest, list) or len(manifest) != 1:
                raise PackagingError(f"镜像必须恰好包含一个 manifest: {image}")
            config_name = manifest[0].get("Config")
            config_member = members.get(str(config_name))
            if config_member is None:
                raise PackagingError(f"镜像缺少 config: {image}")
            config_stream = archive.extractfile(config_member)
            if config_stream is None:
                raise PackagingError(f"无法读取镜像 config: {image}")
            config = json.load(config_stream)
        platform = f"{config.get('os')}/{config.get('architecture')}"
        if platform != EXPECTED_PLATFORM:
            raise PackagingError(
                f"镜像归档平台错误: {image} 是 {platform!r}，要求 {EXPECTED_PLATFORM!r}"
            )


def sync_frontend(repo_root: Path, app_path: Path) -> None:
    source = repo_root / "frontend" / "dist"
    target = app_path / "Contents" / "Resources" / "frontend" / "dist"
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target)


def read_project_version(repo_root: Path) -> str:
    pyproject_path = repo_root / "pyproject.toml"
    try:
        content = pyproject_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PackagingError(f"无法读取项目版本: {pyproject_path}") from exc
    match = PROJECT_VERSION_PATTERN.search(content)
    if match is None:
        raise PackagingError("pyproject.toml 缺少有效的 [project].version")
    return match.group(1)


def write_bundle_version(app_path: Path, version: str) -> None:
    plist_path = app_path / "Contents" / "Info.plist"
    try:
        with plist_path.open("rb") as stream:
            payload = plistlib.load(stream)
        payload["CFBundleShortVersionString"] = version
        payload["CFBundleVersion"] = version
        with plist_path.open("wb") as stream:
            plistlib.dump(payload, stream)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise PackagingError(f"无法写入应用版本: {plist_path}") from exc


def validate_info_plist(app_path: Path, *, expected_version: str | None = None) -> None:
    plist_path = app_path / "Contents" / "Info.plist"
    try:
        with plist_path.open("rb") as stream:
            payload = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise PackagingError(f"Info.plist 无效: {plist_path}") from exc
    expected = {
        "CFBundleExecutable": EXECUTABLE_NAME,
        "CFBundleIdentifier": EXPECTED_BUNDLE_ID,
        "CFBundlePackageType": "APPL",
    }
    if expected_version is not None:
        expected["CFBundleShortVersionString"] = expected_version
        expected["CFBundleVersion"] = expected_version
    for key, value in expected.items():
        if payload.get(key) != value:
            raise PackagingError(
                f"Info.plist {key}={payload.get(key)!r}，要求 {value!r}"
            )
    executable = app_path / "Contents" / "MacOS" / EXECUTABLE_NAME
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise PackagingError(f"应用主程序不存在或不可执行: {executable}")


def validate_dynamic_probe_resource(app_path: Path) -> None:
    probe_runtime = (
        app_path
        / "Contents"
        / "Frameworks"
        / "redsentinel"
        / "profiling"
        / "image"
        / "probe_runtime.py"
    )
    if not probe_runtime.is_file():
        raise PackagingError(f"应用缺少动态画像探针资源: {probe_runtime}")


def validate_macho_arm64(repo_root: Path, app_path: Path) -> int:
    count = 0
    for path in sorted(candidate for candidate in app_path.rglob("*") if candidate.is_file()):
        result = run(["file", "-b", str(path)], cwd=repo_root, capture=True, quiet=True)
        description = result.stdout.strip()
        if "Mach-O" not in description:
            continue
        count += 1
        if "arm64" not in description:
            raise PackagingError(f"发现非 arm64 Mach-O: {path}: {description}")
    if count == 0:
        raise PackagingError(f"应用内没有 Mach-O 文件: {app_path}")
    return count


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def first_launch_check(app_path: Path, timeout: float = 20.0) -> None:
    executable = app_path / "Contents" / "MacOS" / EXECUTABLE_NAME
    port = available_port()
    launch_home = app_path.parent / ".launch-home"
    launch_home.mkdir()
    env = {
        **os.environ,
        "HOME": str(launch_home),
        "RED_SENTINEL_STORAGE_ROOT": str(launch_home / "storage"),
        "RED_SENTINEL_NO_WINDOW": "1",
        "RED_SENTINEL_PORT": str(port),
        "RED_SENTINEL_ENV": "development",
    }
    process = subprocess.Popen(
        [str(executable)],
        cwd=app_path.parent,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                raise PackagingError(
                    f"应用首次启动检查提前退出 ({process.returncode}): "
                    f"{(stderr or stdout)[-1000:]}"
                )
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/v1/health",
                    timeout=0.5,
                ) as response:
                    if response.status == 200:
                        return
            except (OSError, TimeoutError):
                time.sleep(0.2)
        raise PackagingError(f"应用首次启动检查超时: {timeout:.0f}s")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        shutil.rmtree(launch_home, ignore_errors=True)


def write_release_manifest(release_root: Path, frontend_digest: str) -> None:
    agents: dict[str, dict[str, object]] = {}
    for build in AGENT_BUILDS:
        directory = release_root / "agents" / build.directory
        descriptor = json.loads((directory / "agent.json").read_text(encoding="utf-8"))
        agents[build.directory] = {
            "agent_id": descriptor["agent_id"],
            "descriptor_sha256": sha256_file(directory / "agent.json"),
            "image_sha256": sha256_file(directory / "image.tar"),
            "image_bytes": (directory / "image.tar").stat().st_size,
        }
    payload = {
        "schema_version": "sentinel-guardian-release-v0.1",
        "platform": "macos/arm64",
        "app": APP_NAME,
        "frontend_tree_sha256": frontend_digest,
        "agents": agents,
    }
    (release_root / "release-manifest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def package_release(args: argparse.Namespace) -> tuple[Path, Path]:
    repo_root = args.repo_root.resolve()
    output_app = args.output_dir.resolve()
    zip_path = args.zip_path.resolve()

    if args.reuse_archives:
        if args.dry_run:
            print("+ validate existing agents/*/image.tar archives")
        else:
            verify_required_images(repo_root)
    else:
        build_and_export_images(
            repo_root,
            reuse_images=args.reuse_images,
            dry_run=args.dry_run,
            timeout=args.docker_timeout,
        )
    build_frontend(repo_root, dry_run=args.dry_run)
    app_source = args.reuse_app.resolve() if args.reuse_app else build_app(repo_root, dry_run=args.dry_run)

    if args.dry_run:
        print(f"+ assemble and validate application bundle {output_app}")
        print(f"+ create ZIP {zip_path}")
        return output_app, zip_path

    verify_required_images(repo_root)
    if not app_source.is_dir():
        raise PackagingError(f"应用包不存在: {app_source}")
    if output_app == repo_root or repo_root.is_relative_to(output_app):
        raise PackagingError("应用输出不能是仓库根目录或其父目录")
    output_app.parent.mkdir(parents=True, exist_ok=True)
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    staging_app = output_app.parent / (
        f"{output_app.stem}-staging-{uuid.uuid4().hex}.app"
    )
    zip_temporary = zip_path.with_name(f".{zip_path.name}.tmp-{uuid.uuid4().hex}")
    try:
        project_version = read_project_version(repo_root)
        run(["ditto", str(app_source), str(staging_app)], cwd=repo_root)
        resources = staging_app / "Contents" / "Resources"
        embedded_agents = resources / "my-agents"
        if embedded_agents.exists():
            shutil.rmtree(embedded_agents)
        embedded_agents_link = (
            staging_app / "Contents" / "Frameworks" / "my-agents"
        )
        if embedded_agents_link.is_symlink():
            embedded_agents_link.unlink()
        sync_frontend(repo_root, staging_app)
        write_bundle_version(staging_app, project_version)
        bundled_agents = resources / "agents"
        if bundled_agents.exists():
            shutil.rmtree(bundled_agents)
        shutil.copytree(repo_root / "agents", bundled_agents)
        shutil.copy2(
            repo_root / "Sentinel Guardian 使用说明.md",
            resources / "使用说明.md",
        )

        frontend_digest = tree_digest(repo_root / "frontend" / "dist")
        if (
            tree_digest(resources / "frontend" / "dist")
            != frontend_digest
        ):
            raise PackagingError("应用内前端与本次构建产物哈希不一致")

        validate_info_plist(staging_app, expected_version=project_version)
        validate_dynamic_probe_resource(staging_app)
        validate_macho_arm64(repo_root, staging_app)
        verify_required_images_in_release(repo_root, resources)
        write_release_manifest(resources, frontend_digest)
        run(
            ["codesign", "--force", "--deep", "--sign", "-", str(staging_app)],
            cwd=repo_root,
        )
        run(
            ["codesign", "--verify", "--deep", "--strict", str(staging_app)],
            cwd=repo_root,
            capture=True,
        )
        if not args.skip_launch_check:
            first_launch_check(staging_app)

        if output_app.exists():
            shutil.rmtree(output_app)
        staging_app.replace(output_app)
        zip_temporary.unlink(missing_ok=True)
        run(
            [
                "ditto",
                "-c",
                "-k",
                "--norsrc",
                "--keepParent",
                str(output_app),
                str(zip_temporary),
            ],
            cwd=repo_root,
        )
        zip_temporary.replace(zip_path)
        for legacy in (
            repo_root / "dist",
            repo_root / "recovered",
            repo_root / "交付物-打开这里",
        ):
            if legacy.exists() and not output_app.is_relative_to(legacy):
                shutil.rmtree(legacy)
        return output_app, zip_path
    finally:
        if staging_app.exists():
            shutil.rmtree(staging_app)
        zip_temporary.unlink(missing_ok=True)
        if not args.dry_run:
            for generated in (
                repo_root / "build" / "task12-desktop",
                repo_root / "frontend" / "dist",
            ):
                if generated.exists() and not output_app.is_relative_to(generated):
                    shutil.rmtree(generated)
            build_root = repo_root / "build"
            if build_root.is_dir() and not any(build_root.iterdir()):
                build_root.rmdir()


def verify_required_images_in_release(repo_root: Path, release_root: Path) -> None:
    source_agents = repo_root / "agents"
    release_agents = release_root / "agents"
    expected_directories = {build.directory for build in AGENT_BUILDS}
    actual_directories = {path.name for path in release_agents.iterdir() if path.is_dir()}
    if actual_directories != expected_directories:
        raise PackagingError(
            f"分发 Agent 目录错误: actual={sorted(actual_directories)!r}"
        )
    for build in AGENT_BUILDS:
        source = source_agents / build.directory
        target = release_agents / build.directory
        if sha256_file(source / "image.tar") != sha256_file(target / "image.tar"):
            raise PackagingError(f"复制后的镜像摘要变化: {build.directory}")
        validate_descriptor(repo_root, target / "agent.json")
        descriptor = json.loads((target / "agent.json").read_text(encoding="utf-8"))
        if descriptor["image"]["digest"] != sha256_file(target / "image.tar"):
            raise PackagingError(f"分发 descriptor 摘要不匹配: {build.directory}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build and verify the Sentinel Guardian macOS arm64 distribution."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(APP_NAME),
    )
    parser.add_argument(
        "--zip-path",
        type=Path,
        default=Path(f"{DEFAULT_RELEASE_NAME}.zip"),
    )
    parser.add_argument(
        "--reuse-app",
        type=Path,
        help="Explicitly reuse an existing .app; the freshly built frontend is still synchronized.",
    )
    image_group = parser.add_mutually_exclusive_group()
    image_group.add_argument(
        "--reuse-images",
        action="store_true",
        help="Reuse the two tagged local images instead of rebuilding them.",
    )
    image_group.add_argument(
        "--reuse-archives",
        action="store_true",
        help="Reuse existing validated agents/*/image.tar files without contacting Docker.",
    )
    parser.add_argument(
        "--docker-timeout",
        type=float,
        default=1200,
        help="Per Docker build/save timeout in seconds (default: 1200).",
    )
    parser.add_argument(
        "--skip-launch-check",
        action="store_true",
        help="Skip the HTTP health check of the packaged executable.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print build commands without changing image or release artifacts.",
    )
    args = parser.parse_args(argv)
    if not args.output_dir.is_absolute():
        args.output_dir = args.repo_root / args.output_dir
    if not args.zip_path.is_absolute():
        args.zip_path = args.repo_root / args.zip_path
    if args.reuse_app and not args.reuse_app.is_absolute():
        args.reuse_app = args.repo_root / args.reuse_app
    return args


def main(argv: Sequence[str] | None = None) -> int:
    try:
        output_dir, zip_path = package_release(parse_args(argv))
    except PackagingError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Release app: {output_dir}")
    print(f"Release ZIP: {zip_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
