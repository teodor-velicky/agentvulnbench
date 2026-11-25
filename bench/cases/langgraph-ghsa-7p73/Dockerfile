# AgentVulnBench case image: langchain-ai/langgraph libs/checkpoint-sqlite at REPO_SHA.
# deps resolved as of 2025-07-26 (day after fix bc9d45b, CVE-2025-64104) so both trees build.
# libs/checkpoint (same tree) is extracted too: checkpoint-sqlite pins it as a uv path source.
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG REPO_SHA
ADD https://codeload.github.com/langchain-ai/langgraph/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN pip install --no-cache-dir uv && mkdir -p /src /opt/bench \
 && tar xzf /tmp/src.tgz -C /src --strip-components=1 --wildcards '*/libs/checkpoint-sqlite/*' '*/libs/checkpoint/*' && rm /tmp/src.tgz \
 && uv pip install --system --exclude-newer 2025-07-26 /src/libs/checkpoint-sqlite && echo "${REPO_SHA}" > /opt/bench/sha
RUN useradd -m app
USER app
WORKDIR /home/app
