from __future__ import annotations

import os
import shutil
from pathlib import Path


DOCKER_DESKTOP_CLI = Path(
    "/Applications/Docker.app/Contents/Resources/bin/docker"
)


def resolve_docker_binary() -> str:
    configured = os.environ.get("RED_SENTINEL_DOCKER_BINARY", "").strip()
    if configured:
        return configured
    discovered = shutil.which("docker")
    if discovered:
        return discovered
    if DOCKER_DESKTOP_CLI.is_file():
        return str(DOCKER_DESKTOP_CLI)
    return "docker"


__all__ = ["DOCKER_DESKTOP_CLI", "resolve_docker_binary"]
