# AgentVulnBench case image: agno-agi/agno libs/agno (agno) at REPO_SHA.
# deps resolved as of 2026-01-09 (just after fix cbf6755, 2026-01-07) so both trees build.
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG REPO_SHA
ADD https://codeload.github.com/agno-agi/agno/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN pip install --no-cache-dir uv \
 && mkdir -p /src /opt/bench \
 && tar xzf /tmp/src.tgz -C /src --strip-components=1 --wildcards '*/libs/agno/*' && rm /tmp/src.tgz \
 && uv pip install --system --exclude-newer 2026-01-09 /src/libs/agno \
 && echo "${REPO_SHA}" > /opt/bench/sha
RUN useradd -m agent
USER agent
WORKDIR /home/agent
