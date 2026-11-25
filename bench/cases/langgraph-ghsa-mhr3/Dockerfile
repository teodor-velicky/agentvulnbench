# AgentVulnBench case image: langchain-ai/langgraph `langgraph-checkpoint` at REPO_SHA.
# Only libs/checkpoint is needed (the cache + serde live there). Dependencies are resolved as of
# 2026-01-13 (uv --exclude-newer), the day after fix f91d79d. A loopback redis-server is the
# attacker-writable cache backend (RedisCache); it never leaves the container (--network none).
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG REPO_SHA
RUN apt-get update && apt-get install -y --no-install-recommends redis-server \
 && rm -rf /var/lib/apt/lists/*
ADD https://codeload.github.com/langchain-ai/langgraph/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN pip install --no-cache-dir uv==0.5.11 \
 && mkdir -p /src /opt/bench \
 && tar xzf /tmp/src.tgz -C /src --strip-components=1 --wildcards "*/libs/checkpoint/*" \
 && rm /tmp/src.tgz \
 && uv pip install --system --no-cache --exclude-newer 2026-01-13T00:00:00Z /src/libs/checkpoint redis \
 && echo "${REPO_SHA}" > /opt/bench/sha
RUN useradd -m svc
USER svc
WORKDIR /home/svc
