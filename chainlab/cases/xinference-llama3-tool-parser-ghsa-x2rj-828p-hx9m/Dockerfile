# CHAINLAB case image: xinference at the version passed as build arg PKG_VERSION.
# vuln = 2.5.0 (Llama3ToolParser.extract_tool_calls eval()s the model completion),
# fix  = 2.7.0 (json.loads / ast.literal_eval; commit 1b3d220f, PR #4786).
#
# Installed with --no-deps: the Llama3 tool-call parser and the whole tool_parsers
# subpackage are stdlib-only (json/re/typing + the local register_tool_parser and
# abstract_tool_parser), so none of xinference's heavy serving dependencies (torch,
# gradio, modelscope, xoscar, ...) are needed to exercise the sink. The driver loads
# the REAL, version-pinned Llama3ToolParser class and skips only the unrelated
# model-serving package __init__ (see driver.py). The version is read back from the
# installed dist metadata, so a wrong/missing install fails the build.
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG PKG_VERSION
RUN pip install --no-cache-dir uv \
 && mkdir -p /opt/chainlab \
 && uv pip install --system --no-deps --exclude-newer 2026-04-26 "xinference==${PKG_VERSION}" \
 && python -c "import importlib.metadata as m, pathlib; pathlib.Path('/opt/chainlab/version').write_text(m.version('xinference'))"
RUN useradd -m app
USER app
WORKDIR /home/app
