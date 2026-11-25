# AgentVulnBench case image: BerriAI/litellm proxy (litellm[proxy]) at REPO_SHA.
# Dependencies are exact pins in pyproject (proxy extra); uv --exclude-newer 2026-04-26 (day after
# fix 73869f0) bounds anything unpinned. No database: the proxy runs from config.yaml + master key.
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG REPO_SHA
ADD https://codeload.github.com/BerriAI/litellm/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN pip install --no-cache-dir uv \
 && mkdir -p /src /opt/bench \
 && tar xzf /tmp/src.tgz -C /src --strip-components=1 \
 && rm /tmp/src.tgz \
 && uv pip install --system --no-cache --exclude-newer 2026-04-26 "/src[proxy]" \
 && rm -rf /src && echo "${REPO_SHA}" > /opt/bench/sha
RUN useradd -m svc
USER svc
WORKDIR /home/svc
ENV LITELLM_LOCAL_MODEL_COST_MAP=True
