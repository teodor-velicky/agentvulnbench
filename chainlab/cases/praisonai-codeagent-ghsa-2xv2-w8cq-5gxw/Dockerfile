# CHAINLAB case image: praisonaiagents at the version passed as build arg PKG_VERSION.
# vuln = 1.6.77 (CodeAgent._execute_python runs model-authored code via
#   subprocess.run(["python", tmp], env=os.environ.copy()) with no sandbox, ignoring
#   CodeConfig(sandbox=True)),
# fix  = 1.6.78 (routes through tools/python_tools.execute_code with sandbox honoured;
#   the sandbox rejects every import statement).
#
# Base deps only (pydantic/rich/openai/posthog/PyYAML/aiohttp/croniter -- all light, no
# torch). litellm is NOT installed: the driver plugs a fake litellm (the scripted model)
# into agent._litellm, exactly as the LangChain cases use FakeListLLM. The version is read
# back from the installed dist metadata so a wrong/missing install fails the build.
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c
ARG PKG_VERSION
RUN pip install --no-cache-dir uv \
 && mkdir -p /opt/chainlab \
 && uv pip install --system --exclude-newer 2026-06-26 "praisonaiagents==${PKG_VERSION}" \
 && python -c "import importlib.metadata as m, pathlib; pathlib.Path('/opt/chainlab/version').write_text(m.version('praisonaiagents'))"
RUN useradd -m app
USER app
WORKDIR /home/app
