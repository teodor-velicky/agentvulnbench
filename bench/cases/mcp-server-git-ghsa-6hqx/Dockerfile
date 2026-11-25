# AgentVulnBench case image: modelcontextprotocol/servers src/git (mcp-server-git) at REPO_SHA.
# deps resolved as of 2026-11-11 (day after fix a4a43ac, GHSA-6hqx-gqrx-c5r2) so both trees build.
# Debian git is 2.39 (>= 2.31), so the fix's GIT_CONFIG_COUNT overrides take effect.
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG REPO_SHA
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ADD https://codeload.github.com/modelcontextprotocol/servers/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN pip install --no-cache-dir uv \
 && mkdir -p /src /opt/bench \
 && tar xzf /tmp/src.tgz -C /src --strip-components=1 --wildcards '*/src/git/*' && rm /tmp/src.tgz \
 && uv pip install --system --exclude-newer 2026-11-11 /src/src/git \
 && echo "${REPO_SHA}" > /opt/bench/sha
# /srv/repo stands for the untrusted repository the user cloned; the driver writes its config.
RUN useradd -m agent \
 && git config --system init.defaultBranch main \
 && git init -q /srv/repo \
 && printf 'readme\n' > /srv/repo/README.md \
 && chown -R agent:agent /srv
USER agent
WORKDIR /home/agent
