# AgentVulnBench case image: modelcontextprotocol/python-sdk (v1.x line) at REPO_SHA.
# Dependencies are resolved as of 2026-09-05 (uv --exclude-newer), the day after fix 3eed7ce.
# UV_DYNAMIC_VERSIONING_BYPASS lets the tarball tree (no .git) build under hatchling.
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG REPO_SHA
ADD https://codeload.github.com/modelcontextprotocol/python-sdk/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN pip install --no-cache-dir uv==0.5.11 \
 && mkdir -p /src /opt/bench && tar xzf /tmp/src.tgz -C /src --strip-components=1 && rm /tmp/src.tgz \
 && UV_DYNAMIC_VERSIONING_BYPASS=1.29.1 uv pip install --system --no-cache --exclude-newer 2026-09-05T00:00:00Z /src \
 && echo "${REPO_SHA}" > /opt/bench/sha
RUN useradd -m svc
USER svc
WORKDIR /home/svc
