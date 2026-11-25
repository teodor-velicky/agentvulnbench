# AgentVulnBench case image: huggingface/smolagents at REPO_SHA (vuln or fix).
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG REPO_SHA
ADD https://codeload.github.com/huggingface/smolagents/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN mkdir -p /src /opt/bench && tar xzf /tmp/src.tgz -C /src --strip-components=1 && rm /tmp/src.tgz \
 && pip install --no-cache-dir /src && echo "${REPO_SHA}" > /opt/bench/sha
RUN useradd -m agent
USER agent
WORKDIR /home/agent
