# syntax=docker/dockerfile:1.7

ARG PYTHON_BASE_IMAGE=python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134
FROM ${PYTHON_BASE_IMAGE}

ARG APT_MIRROR=
ARG APT_SECURITY_MIRROR=
ARG APT_RETRIES=5
ARG APT_HTTP_TIMEOUT=20
ARG PIP_INDEX_URL=

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    OPENMANUS_ROOT=/opt/openmanus \
    OPENMANUS_WORKSPACE=/workspace \
    RED_SENTINEL_ARTIFACTS=/tmp/redsentinel-artifacts \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    PYTHONPATH=/opt/openmanus:/opt/openmanus/redsentinel_runtime:/opt/redsentinel/src

WORKDIR /opt/openmanus

RUN --mount=type=cache,id=openmanus-apt-arm64,target=/var/cache/apt,sharing=locked \
    if [ -n "$APT_SECURITY_MIRROR" ]; then \
        sed -i "s|http://deb.debian.org/debian-security|$APT_SECURITY_MIRROR|g" /etc/apt/sources.list.d/debian.sources; \
    fi \
    && if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|http://deb.debian.org/debian|$APT_MIRROR|g" /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get \
        -o Acquire::Retries="$APT_RETRIES" \
        -o Acquire::http::Timeout="$APT_HTTP_TIMEOUT" \
        -o Acquire::https::Timeout="$APT_HTTP_TIMEOUT" \
        update \
    && apt-get \
        -o Acquire::Retries="$APT_RETRIES" \
        -o Acquire::http::Timeout="$APT_HTTP_TIMEOUT" \
        -o Acquire::https::Timeout="$APT_HTTP_TIMEOUT" \
        install -y --no-install-recommends \
        build-essential \
        curl \
        git \
        ca-certificates \
        chromium \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY third_party/OpenManus/upstream/requirements.txt /tmp/openmanus-upstream-requirements.txt

RUN python -m pip install --no-cache-dir --upgrade pip \
    && grep -Ev '^(crawl4ai|browsergym)' /tmp/openmanus-upstream-requirements.txt > /tmp/openmanus-real-requirements.txt \
    && if [ -n "$PIP_INDEX_URL" ]; then \
        python -m pip install --no-cache-dir -i "$PIP_INDEX_URL" -r /tmp/openmanus-real-requirements.txt; \
    else \
        python -m pip install --no-cache-dir -r /tmp/openmanus-real-requirements.txt; \
    fi \
    && if [ -n "$PIP_INDEX_URL" ]; then \
        python -m pip install --no-cache-dir -i "$PIP_INDEX_URL" structlog; \
    else \
        python -m pip install --no-cache-dir structlog; \
    fi \
    && PLAYWRIGHT_CHROMIUM_PATH="$(python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); print(p.chromium.executable_path); p.stop()")" \
    && PLAYWRIGHT_REVISION="$(basename "$(dirname "$(dirname "$PLAYWRIGHT_CHROMIUM_PATH")")" | cut -d- -f2)" \
    && PLAYWRIGHT_HEADLESS_PATH="$PLAYWRIGHT_BROWSERS_PATH/chromium_headless_shell-$PLAYWRIGHT_REVISION/chrome-linux/headless_shell" \
    && mkdir -p "$(dirname "$PLAYWRIGHT_CHROMIUM_PATH")" \
    && mkdir -p "$(dirname "$PLAYWRIGHT_HEADLESS_PATH")" \
    && ln -sf /usr/bin/chromium "$PLAYWRIGHT_CHROMIUM_PATH" \
    && ln -sf /usr/bin/chromium "$PLAYWRIGHT_HEADLESS_PATH"

COPY third_party/OpenManus/upstream/ /opt/openmanus/
COPY third_party/OpenManus/redsentinel_runtime/ /opt/openmanus/redsentinel_runtime/
RUN printf '%s\n' \
        '[llm]' \
        'model = "redsentinel-build-healthcheck"' \
        'base_url = "https://example.invalid/v1"' \
        'api_key = "build-healthcheck-not-a-runtime-secret"' \
        '[daytona]' \
        'daytona_api_key = "redsentinel-disabled"' \
        > /opt/openmanus/config/config.toml \
    && python -c "from app.tool.browser_use_tool import BrowserUseTool; BrowserUseTool()" \
    && python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); browser = p.chromium.launch(headless=True); page = browser.new_page(); page.set_content('<title>sentinel-healthcheck</title>'); assert page.title() == 'sentinel-healthcheck'; browser.close(); p.stop()"
COPY src/ /opt/redsentinel/src/
COPY configs/ /opt/redsentinel/configs/
COPY datasets/ /opt/redsentinel/datasets/
COPY schemas/ /opt/redsentinel/schemas/

RUN mkdir -p /workspace /tmp/redsentinel-artifacts

COPY infra/openmanus/entrypoint.sh /entrypoint.sh
COPY infra/openmanus/mock_metadata_server.py /opt/openmanus/redsentinel_runtime/mock_metadata_server.py
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
