# AgentVulnBench case image: ag2ai/ag2 at REPO_SHA (package "ag2", uv_build backend).
# Dependencies resolved as of 2026-09-30 (uv --exclude-newer), the day after fix 3cd8672.
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG REPO_SHA
ADD https://codeload.github.com/ag2ai/ag2/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN pip install --no-cache-dir uv \
 && mkdir -p /src /opt/bench && tar xzf /tmp/src.tgz -C /src --strip-components=1 && rm /tmp/src.tgz \
 && uv pip install --system --no-cache --exclude-newer 2026-09-30 /src \
 && rm -rf /src && echo "${REPO_SHA}" > /opt/bench/sha
RUN useradd -m app && mkdir -p /home/app/ws && chown app:app /home/app/ws
USER app
WORKDIR /home/app
