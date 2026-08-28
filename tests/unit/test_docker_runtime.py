from redsentinel.core.docker_runtime import resolve_docker_binary


def test_docker_binary_prefers_explicit_configuration(monkeypatch) -> None:
    monkeypatch.setenv(
        "RED_SENTINEL_DOCKER_BINARY",
        "/custom/docker/bin/docker",
    )

    assert resolve_docker_binary() == "/custom/docker/bin/docker"


def test_docker_binary_uses_path_discovery(monkeypatch) -> None:
    monkeypatch.delenv("RED_SENTINEL_DOCKER_BINARY", raising=False)
    monkeypatch.setattr(
        "redsentinel.core.docker_runtime.shutil.which",
        lambda _name: "/usr/local/bin/docker",
    )

    assert resolve_docker_binary() == "/usr/local/bin/docker"
