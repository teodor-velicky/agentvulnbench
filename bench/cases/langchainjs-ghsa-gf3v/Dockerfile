# AgentVulnBench case image: langchain-ai/langchainjs at REPO_SHA, only what the loader needs:
# libs/langchain-core (whole) and the RecursiveUrlLoader source file from libs/langchain-community.
# "@langchain/core/*" imports map to the core TS source via tsconfig paths; tsx runs the TS directly
# (no turbo/tsc). Runtime deps are pinned to exact versions inside core 1.1.20's declared ranges.
FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0
ARG REPO_SHA
ADD https://codeload.github.com/langchain-ai/langchainjs/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN mkdir -p /src /opt/bench \
 && tar xzf /tmp/src.tgz -C /src --strip-components=1 --wildcards "*/libs/langchain-core/*" \
    "*/libs/langchain-community/src/document_loaders/web/recursive_url.ts" \
 && rm /tmp/src.tgz && echo "${REPO_SHA}" > /opt/bench/sha
COPY package.json tsconfig.json /src/
RUN cd /src && npm install --no-audit --no-fund --loglevel=error
RUN useradd -m app && chown -R app /src
USER app
WORKDIR /src
