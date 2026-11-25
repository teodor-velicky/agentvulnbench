"""Plays the agent loop with a scripted model: the 'model output' is the arm's input file.

The code is executed by smolagents' LocalPythonExecutor with the authorized imports a
CodeAgent user might grant (warnings, functools). Exceptions are the sandbox doing its job.
"""
import sys
from smolagents.local_python_executor import LocalPythonExecutor

arm, nonce = sys.argv[1], sys.argv[2]
code = open(f"/case/inputs/{arm}.py", encoding="utf-8").read().replace("{{NONCE}}", nonce)
ex = LocalPythonExecutor(additional_authorized_imports=["warnings", "functools"])
ex.send_tools({})
try:
    out = ex(code)
    print("executor returned:", repr(out)[:200])
except Exception as e:
    print("executor raised:", type(e).__name__, str(e)[:200])
