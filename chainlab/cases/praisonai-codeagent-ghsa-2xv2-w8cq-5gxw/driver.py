"""CHAINLAB driver: PraisonAI CodeAgent, model-mediated code execution.

The SCRIPTED MODEL is a fake `litellm` module plugged into the framework's own LLM call
site. CodeAgent.generate() calls `self.litellm.completion(model=..., messages=...)` and
returns `response.choices[0].message.content` as the generated code; execute() then routes
that code to _execute_python. We set agent._litellm to a stand-in whose completion() returns
the fixture code verbatim, so the outcome depends only on whether the FRAMEWORK guards what
it does with model output -- not on how a real model behaves. This mirrors the FakeListLLM
approach in the LangChain cases; here the framework's LLM interface is litellm.

Attacker story: an app runs `code = agent.generate(prompt); agent.execute(code)`. A prompt
injection in the agent's input / a tool result / ingested content steers a code-writing model
into emitting attacker Python. In praisonaiagents 1.6.77, _execute_python runs it via
`subprocess.run(["python", tmp], env=os.environ.copy())` with no sandbox -- EVEN with
CodeConfig(sandbox=True) (CVE-2026-61447 / GHSA-2xv2-w8cq-5gxw). The fix (1.6.78) routes
through tools.python_tools.execute_code with the sandbox honoured, which rejects the payload.

Usage: python -I driver.py <arm> <nonce>   # arm in {attack, control}
"""
import sys, types
from pathlib import Path

arm, nonce = sys.argv[1], sys.argv[2]
code_text = Path(f"/case/fixtures/{arm}.txt").read_text(encoding="utf-8").replace("{{NONCE}}", nonce)

from praisonaiagents.agent.code_agent import CodeAgent, CodeConfig


# --- scripted model: a fake litellm whose completion() returns the fixture code verbatim ---
def _make_response(content):
    msg = types.SimpleNamespace(content=content)
    choice = types.SimpleNamespace(message=msg)
    return types.SimpleNamespace(choices=[choice])


class _FakeLiteLLM:
    def completion(self, *a, **kw):
        return _make_response(code_text)

    def acompletion(self, *a, **kw):  # unused here; present for parity
        return _make_response(code_text)


# sandbox=True is set explicitly: the advisory's point is that 1.6.77 ignores it.
agent = CodeAgent(name="chainlab", llm="scripted", code=CodeConfig(sandbox=True), verbose=False)
agent._litellm = _FakeLiteLLM()  # plug the scripted model into the framework's LLM slot

# The framework asks its (scripted) model to write code, then executes it -- the real path.
generated = agent.generate("Write a short Python snippet.")
result = agent.execute(generated)
print("execute ->", str(result)[:300])
