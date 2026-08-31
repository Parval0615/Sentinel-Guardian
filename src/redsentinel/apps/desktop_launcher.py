from __future__ import annotations

import logging
import os
import secrets
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

import uvicorn

from redsentinel.application.engine.app import create_app


APP_NAME = "Sentinel Guardian"
DEFAULT_PORT = 8765


def main() -> None:
    support_root = _support_root()
    support_root.mkdir(parents=True, exist_ok=True)
    _configure_logging(support_root / "app.log")

    resource_root = _resource_root()
    os.chdir(resource_root)
    os.environ.setdefault("RED_SENTINEL_RESOURCE_ROOT", str(resource_root))
    os.environ.setdefault("RED_SENTINEL_ENV", "development")
    os.environ.setdefault("RED_SENTINEL_JWT_SECRET", _jwt_secret(support_root))

    requested_port = int(os.environ.get("RED_SENTINEL_PORT", str(DEFAULT_PORT)))
    if _is_sentinel_running(requested_port):
        _show_window(requested_port, support_root)
        return
    port = _available_port(requested_port)
    storage_root = Path(
        os.environ.get(
            "RED_SENTINEL_STORAGE_ROOT",
            str(support_root / "runs" / "product"),
        )
    )
    app = create_app(storage_root=storage_root)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="info")
    )
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    _wait_until_ready(port)
    if os.environ.get("RED_SENTINEL_NO_WINDOW") == "1":
        server_thread.join()
        return
    try:
        _show_window(port, support_root)
    finally:
        server.should_exit = True
        server_thread.join(timeout=5)


def _support_root() -> Path:
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(local_app_data) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path.home() / ".local" / "share" / APP_NAME


def _resource_root() -> Path:
    if getattr(sys, "frozen", False):
        if sys.platform == "darwin":
            resources = Path(sys.executable).resolve().parents[1] / "Resources"
            if resources.is_dir():
                return resources
        bundled = getattr(sys, "_MEIPASS", None)
        if bundled:
            return Path(bundled).resolve()
    return Path(__file__).resolve().parents[3]


def _agent_root() -> Path:
    if getattr(sys, "frozen", False):
        bundled = _resource_root() / "agents"
        if bundled.is_dir():
            return bundled
    return Path(sys.executable).resolve().parents[3] / "agents"


def _jwt_secret(support_root: Path) -> str:
    secret_path = support_root / "jwt-secret"
    if secret_path.is_file():
        return secret_path.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(48)
    temporary = secret_path.with_suffix(".tmp")
    temporary.write_text(secret, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, secret_path)
    return secret


def _available_port(preferred: int) -> int:
    for port in range(preferred, preferred + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            try:
                candidate.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("No available local port found.")


def _is_sentinel_running(port: int) -> bool:
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/v1/health",
            timeout=0.5,
        ) as response:
            return response.status == 200
    except Exception:
        return False


def _wait_until_ready(port: int) -> None:
    for _ in range(100):
        if _is_sentinel_running(port):
            return
        time.sleep(0.1)
    raise RuntimeError("The local web service did not become ready.")


def _show_window(port: int, support_root: Path) -> None:
    if os.environ.get("RED_SENTINEL_NO_WINDOW") == "1":
        return
    import webview

    webview.create_window(
        APP_NAME,
        f"http://127.0.0.1:{port}/",
        width=1280,
        height=820,
        min_size=(960, 640),
    )
    gui = _webview_gui()
    webview.start(
        gui=gui,
        private_mode=False,
        storage_path=str(support_root / "webview"),
    )


def _webview_gui() -> str:
    if sys.platform == "win32":
        return "edgechromium"
    if sys.platform == "darwin":
        return "cocoa"
    return "gtk"


def _configure_logging(path: Path) -> None:
    logging.basicConfig(
        filename=path,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


if __name__ == "__main__":
    main()
