# CHAINLAB case image: langroid at the version passed as build arg PKG_VERSION,
# with a loopback Neo4j-compatible server (memgraph) in the SAME image so the
# Cypher sink has a real, DB-backed oracle that runs entirely under --network none.
#
# vuln = 0.65.4 (Neo4jChatAgent.cypher_retrieval_tool passes LLM Cypher straight to
#   read_query -> neo4j session.run(query) with no validation; the RAG/read path
#   executes arbitrary writes),
# fix  = 0.65.5 (adds cypher_validator.validate_cypher_query; the retrieval path is
#   restricted to read-only Cypher and both paths reject LOAD CSV / apoc.* / dbms.* /
#   CALL db.* unless allow_dangerous_operations=True, default False).
#
# Base = the official memgraph image (Ubuntu 24.04): memgraph is a Neo4j-bolt-compatible
# Cypher database that starts in ~2s (no JVM), which the driver brings up on loopback.
# langroid[neo4j] installs into a venv; langroid connects to it via the real `neo4j`
# bolt driver (the exact code path the framework uses). litellm / a real LLM are NOT
# installed: the driver plugs langroid's own MockLM (the framework's fake-LLM interface)
# as the agent's llm, exactly as the LangChain cases use FakeListLLM. tiktoken's BPE
# vocab is pre-cached at build time so the runtime import needs no network. The langroid
# version is read back from dist metadata into /opt/chainlab/version, so a wrong/missing
# install fails the build.
FROM memgraph/memgraph:3.14.0
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir uv
ARG PKG_VERSION
ENV TIKTOKEN_CACHE_DIR=/opt/tiktoken_cache
RUN /opt/venv/bin/uv pip install --python /opt/venv/bin/python --exclude-newer 2026-06-15T06:00:00Z "langroid[neo4j]==${PKG_VERSION}" \
 && mkdir -p /opt/tiktoken_cache \
 && /opt/venv/bin/python -c "import tiktoken; [tiktoken.get_encoding(e) for e in ['cl100k_base','o200k_base','gpt2','p50k_base','r50k_base']]" \
 && mkdir -p /opt/chainlab \
 && /opt/venv/bin/python -c "import importlib.metadata as m, pathlib; pathlib.Path('/opt/chainlab/version').write_text(m.version('langroid'))"
# The base image's ENTRYPOINT is the memgraph binary; clear it so the harness's
# `... sleep infinity` command (and the version-check `--entrypoint cat`) run as given.
ENTRYPOINT []
USER memgraph
WORKDIR /tmp
