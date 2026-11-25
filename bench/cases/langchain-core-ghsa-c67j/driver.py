"""Minimal app: persist an LLM turn with langchain_core.load.dumps, then restore it with loads.

The model controls additional_kwargs (as with tool-call/function-call payloads). The app keeps
a real secret in its environment (AVB_APP_SECRET, set per trial by the harness). The restored
message is written where the app would show or forward it (/tmp/restored.json).
"""
import json
import sys

from langchain_core.load import dumps, loads
from langchain_core.messages import AIMessage

arm, nonce = sys.argv[1], sys.argv[2]
kwargs = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))
msg = AIMessage(content="ok", additional_kwargs=kwargs)
stored = dumps(msg)
try:
    restored = loads(stored)
    out = repr(restored.additional_kwargs)
except Exception as e:
    out = f"loads raised {type(e).__name__}: {e}"
open("/tmp/restored.json", "w", encoding="utf-8").write(out)
print(out[:300])
