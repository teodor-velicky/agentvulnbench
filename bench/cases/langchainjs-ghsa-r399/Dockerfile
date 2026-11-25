# AgentVulnBench case image: langchain-ai/langchainjs libs/langchain-core (@langchain/core) at REPO_SHA.
# Runtime deps are pinned (no monorepo lockfile for a single workspace); tsx runs the TS source
# directly, so no compile/turbo step is needed. Both vuln and fix trees build identically.
FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0
ARG REPO_SHA
ADD https://codeload.github.com/langchain-ai/langchainjs/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN mkdir -p /src /opt/bench \
 && tar xzf /tmp/src.tgz -C /src --strip-components=1 --wildcards '*/libs/langchain-core/*' \
 && rm /tmp/src.tgz && echo "${REPO_SHA}" > /opt/bench/sha
# Minimal package.json at /src so @langchain/core's runtime deps resolve upward from
# /src/libs/langchain-core/src/**. Pinned versions keep the build deterministic.
COPY package.json /src/package.json
RUN cd /src && npm install --no-audit --no-fund --loglevel=error
RUN useradd -m app && chown -R app /src
USER app
WORKDIR /src
