# AgentVulnBench case image: modelcontextprotocol/inspector `server` workspace at REPO_SHA.
# Runtime deps pinned (the monorepo lockfile covers all 3 workspaces); tsx runs the server's
# TS source directly, so no tsc build step is needed. Both vuln and fix trees build identically.
FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0
ARG REPO_SHA
ADD https://codeload.github.com/modelcontextprotocol/inspector/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN mkdir -p /app /opt/bench \
 && tar xzf /tmp/src.tgz -C /app --strip-components=1 --wildcards '*/server/*' \
 && rm /tmp/src.tgz && echo "${REPO_SHA}" > /opt/bench/sha
# Minimal package.json at /app so the server's deps (and tsx) resolve from /app/node_modules.
COPY package.json /app/package.json
RUN cd /app && npm install --no-audit --no-fund --loglevel=error
RUN useradd -m app && chown -R app /app
USER app
WORKDIR /app
