#!/usr/bin/env python3
"""Build and verify the Sentinel Guardian Windows x86_64 distribution.

Produces:
  - <output-dir>/Sentinel Guardian.exe  (via PyInstaller --onefile, or the dist directory)
  - <zip-path>/Sentinel Guardian-Windows-x86_64.zip

Usage:
    python scripts/package_windows_release.py [options]

    --dry-run          Print commands without executing them.
    --reuse-images     Reuse already-tagged local Docker images.
    --reuse-archives   Reuse existing agents/*/image.tar files without Docker.
    --skip-launch-check  Skip HTTP health-check of the built executable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

APP_NAME = "Sentinel Guardian"
EXECUTABLE_NAME = "Sentinel Guardian"
EXPECTED_BUNDLE_ID = "ai.redsentinel.guardian"
EXPECTED_PLATFORM = "linux/amd64"
DEFAULT_RELEASE_NAME = "Sentinel Guardian-Windows-x86_64"
HASH_CHUNK_SIZE = 1024 * 1024
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
PYTHON_MODULE_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)


class PackagingError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentBuild:
    directory: str
    image: str
    dockerfile: str


AGENT_BUILDS = (
    AgentBuild("电商", "redsentinel/ecommerce-agent:task12-amd64", "agents/电商/Dockerfile"),
    AgentBuild("openmanus", "redsentinel/openmanus-real:task12-amd64", "infra/openmanus/Dockerfile"),
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
        print("+", " ".join(str(c) for c in command))
    if dry_run:
        return subprocess.CompletedProcess(list(command), 0, "", "")
    try:
        return subprocess.run(
            [str(c) for c in command],
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
        raise PackagingError(f"命令失败 ({exc.returncode}): {' '.join(str(c) for c in command)}{suffix}") from exc
    except subprocess.TimeoutExpired as exc:
        raise PackagingError(
            f"命令超时 ({timeout:.0f}s): {' '.join(str(c) for c in command)}"
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
            "notes": "Ecommerce Agent built for linux/amd64 from agents/电商/Dockerfile.",
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
        "notes": "OpenManus runtime built for linux/amd64 from infra/openmanus/Dockerfile.",
    }


def validate_descriptor(repo_root: Path, descriptor_path: Path) -> dict[str, object]:
    try:
        payload = json.loads(descriptor_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackagingError(f"Agent descriptor 无效: {descriptor_path}: {exc}") from exc
    allowed = {
        "schema_version", "agent_id", "name", "image", "platform",
        "runtime", "expected_frameworks", "notes",
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
        "requires_privileged", "required_host_mounts", "probe_module",
    }:
        raise PackagingError(f"Agent descriptor runtime 无效: {descriptor_path}")
    if not isinstance(runtime.get("requires_privileged", False), bool):
        raise PackagingError(f"Agent descriptor runtime.requires_privileged 无效: {descriptor_path}")
    host_mounts = runtime.get("required_host_mounts", [])
    if (
        not isinstance(host_mounts, list)
        or any(
            not isinstance(item, str) or not item.startswith("/") or "\x00" in item
            for item in host_mounts
        )
        or len(host_mounts) != len(set(host_mounts))
    ):
        raise PackagingError(f"Agent descriptor runtime.required_host_mounts 无效: {descriptor_path}")
    probe_module = runtime.get("probe_module")
    if probe_module is not None and (
        not isinstance(probe_module, str)
        or not PYTHON_MODULE_PATTERN.fullmatch(probe_module)
    ):
        raise PackagingError(f"Agent descriptor runtime.probe_module 无效: {descriptor_path}")
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
                    "docker", "build",
                    "--platform", EXPECTED_PLATFORM,
                    "--build-arg", "SOURCE_DATE_EPOCH=0",
                    "--provenance=false",
                    "-f", str(dockerfile),
                    "-t", build.image,
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
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    if not (frontend / "node_modules").is_dir():
        run([npm_cmd, "install"], cwd=frontend, dry_run=dry_run)
    run([npm_cmd, "run", "build"], cwd=frontend, dry_run=dry_run)
    if not dry_run and not (frontend / "dist" / "index.html").is_file():
        raise PackagingError("前端构建成功但 frontend/dist/index.html 不存在")


def _python_executable(repo_root: Path) -> Path:
    for candidate in (
        repo_root / ".venv" / "Scripts" / "python.exe",
        repo_root / ".venv" / "bin" / "python",
    ):
        if candidate.is_file():
            return candidate
    return Path(sys.executable)


def build_app(repo_root: Path, output_dir: Path, *, dry_run: bool) -> Path:
    output = output_dir
    executable = _python_executable(repo_root)
    dist_path = output / "dist"
    run(
        [
            str(executable),
            "-m", "PyInstaller",
            "--noconfirm",
            "--clean",
            "--windowed",
            "--name", EXECUTABLE_NAME,
            "--distpath", str(dist_path),
            "--workpath", str(output / "work"),
            "--specpath", str(output),
            "--collect-all", "webview",
            "--add-data", f"{repo_root / 'frontend' / 'dist'}{os.pathsep}frontend/dist",
            "--add-data", f"{repo_root / 'configs'}{os.pathsep}configs",
            "--add-data", (
                f"{repo_root / 'src' / 'redsentinel' / 'profiling' / 'image' / 'probe_runtime.py'}"
                f"{os.pathsep}redsentinel/profiling/image"
            ),
            "--add-data", (
                f"{repo_root / 'src' / 'redsentinel' / 'adapters' / 'engine' / 'ecommerce_agent'}"
                f"{os.pathsep}builtin-agents/ecommerce"
            ),
            str(repo_root / "src" / "redsentinel" / "apps" / "desktop_launcher.py"),
        ],
        cwd=repo_root,
        dry_run=dry_run,
    )
    app_dir = dist_path / EXECUTABLE_NAME
    if not dry_run and not app_dir.is_dir():
        raise PackagingError(f"PyInstaller 输出目录不存在: {app_dir}")
    return app_dir


def verify_required_images(repo_root: Path) -> None:
    for build in AGENT_BUILDS:
        directory = repo_root / "agents" / build.directory
        image = directory / "image.tar"
        descriptor_path = directory / "agent.json"
        if not image.is_file() or image.stat().st_size == 0:
            raise PackagingError(f"缺少必需镜像归档: {image}")
        descriptor = validate_descriptor(repo_root, descriptor_path)
        if not descriptor.get("runtime", {}).get("probe_module"):  # type: ignore[union-attr]
            raise PackagingError(f"必需镜像缺少 runtime.probe_module: {descriptor_path}")
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


def assemble_release_dir(
    repo_root: Path,
    app_dir: Path,
    staging_dir: Path,
) -> None:
    """复制 app 目录、agent 镜像、文档到分发暂存目录。"""
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True)

    # 复制 PyInstaller 输出目录
    app_target = staging_dir / EXECUTABLE_NAME
    shutil.copytree(app_dir, app_target)

    # 同步最新前端到分发目录内的 _internal（PyInstaller 打包后资源目录）
    internal = app_target / "_internal"
    if internal.is_dir():
        fe_target = internal / "frontend" / "dist"
        fe_target.parent.mkdir(parents=True, exist_ok=True)
        if fe_target.exists():
            shutil.rmtree(fe_target)
        shutil.copytree(repo_root / "frontend" / "dist", fe_target)

    # 嵌入 agent 镜像
    agents_target = staging_dir / "agents"
    shutil.copytree(repo_root / "agents", agents_target)

    # 使用说明
    readme_src = repo_root / "Sentinel Guardian 使用说明.md"
    if readme_src.is_file():
        shutil.copy2(readme_src, staging_dir / "使用说明.md")


def write_release_manifest(staging_dir: Path, frontend_digest: str) -> None:
    agents: dict[str, dict[str, object]] = {}
    for build in AGENT_BUILDS:
        directory = staging_dir / "agents" / build.directory
        descriptor = json.loads((directory / "agent.json").read_text(encoding="utf-8"))
        agents[build.directory] = {
            "agent_id": descriptor["agent_id"],
            "descriptor_sha256": sha256_file(directory / "agent.json"),
            "image_sha256": sha256_file(directory / "image.tar"),
            "image_bytes": (directory / "image.tar").stat().st_size,
        }
    payload = {
        "schema_version": "sentinel-guardian-release-v0.1",
        "platform": "windows/x86_64",
        "app": f"{EXECUTABLE_NAME}/{EXECUTABLE_NAME}.exe",
        "frontend_tree_sha256": frontend_digest,
        "agents": agents,
    }
    (staging_dir / "release-manifest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def create_zip(staging_dir: Path, zip_path: Path) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = zip_path.with_name(f".{zip_path.name}.tmp-{uuid.uuid4().hex}")
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for file_path in sorted(staging_dir.rglob("*")):
                if file_path.is_file():
                    zf.write(file_path, file_path.relative_to(staging_dir.parent))
        tmp.replace(zip_path)
    finally:
        tmp.unlink(missing_ok=True)


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def first_launch_check(app_dir: Path, timeout: float = 20.0) -> None:
    executable = app_dir / (EXECUTABLE_NAME + ".exe")
    if not executable.is_file():
        # --windowed 下 PyInstaller 生成 exe 在 app_dir 根目录
        candidates = list(app_dir.glob("*.exe"))
        if not candidates:
            raise PackagingError(f"找不到可执行文件: {app_dir}")
        executable = candidates[0]
    port = available_port()
    launch_home = app_dir.parent / ".launch-home"
    launch_home.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "RED_SENTINEL_STORAGE_ROOT": str(launch_home / "storage"),
        "RED_SENTINEL_NO_WINDOW": "1",
        "RED_SENTINEL_PORT": str(port),
        "RED_SENTINEL_ENV": "development",
    }
    process = subprocess.Popen(
        [str(executable)],
        cwd=app_dir,
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


def package_release(args: argparse.Namespace) -> tuple[Path, Path]:
    repo_root = args.repo_root.resolve()
    build_output = repo_root / "build" / "task12-desktop-windows"
    staging_dir = build_output / "staging" / DEFAULT_RELEASE_NAME
    output_dir = args.output_dir.resolve()
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

    if args.dry_run:
        print(f"+ PyInstaller build -> {build_output / 'dist' / EXECUTABLE_NAME}")
        print(f"+ assemble staging dir {staging_dir}")
        print(f"+ create ZIP {zip_path}")
        return output_dir, zip_path

    verify_required_images(repo_root)

    app_dir = build_app(repo_root, build_output, dry_run=False)

    assemble_release_dir(repo_root, app_dir, staging_dir)

    frontend_digest = tree_digest(repo_root / "frontend" / "dist")
    write_release_manifest(staging_dir, frontend_digest)

    if not args.skip_launch_check:
        first_launch_check(staging_dir / EXECUTABLE_NAME)

    create_zip(staging_dir, zip_path)

    # 复制最终分发目录到 output_dir
    if output_dir.exists():
        shutil.rmtree(output_dir)
    shutil.copytree(staging_dir, output_dir)

    return output_dir, zip_path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build and verify the Sentinel Guardian Windows x86_64 distribution."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(DEFAULT_RELEASE_NAME),
    )
    parser.add_argument(
        "--zip-path",
        type=Path,
        default=Path(f"{DEFAULT_RELEASE_NAME}.zip"),
    )
    image_group = parser.add_mutually_exclusive_group()
    image_group.add_argument(
        "--reuse-images",
        action="store_true",
        help="Reuse already-tagged local Docker images instead of rebuilding.",
    )
    image_group.add_argument(
        "--reuse-archives",
        action="store_true",
        help="Reuse existing agents/*/image.tar files without contacting Docker.",
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
        help="Print build commands without executing them.",
    )
    args = parser.parse_args(argv)
    if not args.output_dir.is_absolute():
        args.output_dir = args.repo_root / args.output_dir
    if not args.zip_path.is_absolute():
        args.zip_path = args.repo_root / args.zip_path
    return args


def main(argv: Sequence[str] | None = None) -> int:
    try:
        output_dir, zip_path = package_release(parse_args(argv))
    except PackagingError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Release dir: {output_dir}")
    print(f"Release ZIP: {zip_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
