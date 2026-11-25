# AgentVulnBench case image: run-llama/llama_index llama-index-core at REPO_SHA.
# deps resolved as of 2024-03-28 (just after fix 2c92e88, 2024-03-26) so both trees build.
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG REPO_SHA
ADD https://codeload.github.com/run-llama/llama_index/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN pip install --no-cache-dir uv \
 && mkdir -p /src /opt/bench \
 && tar xzf /tmp/src.tgz -C /src --strip-components=1 --wildcards '*/llama-index-core/*' && rm /tmp/src.tgz \
 && uv pip install --system --exclude-newer 2024-03-28 /src/llama-index-core pandas numpy \
 && echo "${REPO_SHA}" > /opt/bench/sha
RUN useradd -m app
USER app
WORKDIR /home/app
