"""CHAINLAB driver: Xinference Llama3 tool-call parser, serving-layer model-mediated RCE.

The SCRIPTED MODEL here is the raw model completion string that Xinference's own
Transformers-backend chat path feeds to its Llama3 tool-call parser. In Xinference the
flow is: /v1/chat/completions -> handle_chat_result_non_streaming -> _post_process_completion
-> Llama3ToolParser.extract_tool_calls(model_output). In 2.5.0 that method does
`eval(model_output, {}, {})`, so any Python expression the model emits runs on the server
(CVE-2026-61539 / GHSA-x2rj-828p-hx9m). The fix (2.7.0) parses with json.loads / ast.literal_eval.

We exercise the REAL, version-pinned Llama3ToolParser class -- the exact sink -- with the
attacker-chosen completion. A positive result depends only on whether the FRAMEWORK guards
what it does with model output, not on how a real model behaves. That is the CHAINLAB rule.

Because xinference is installed with --no-deps (the parser path is stdlib-only), we must
avoid running xinference.model.llm.__init__, whose model-serving setup imports torch/xoscar
and is unrelated to the parser. We locate the installed package via find_spec (which does
NOT execute any __init__) and insert lightweight path-stubs for the parent packages, then
import the real parser subpackage. The parser class itself is unmodified upstream code.

Usage: python -I driver.py <arm> <nonce>   # arm in {attack, control}
"""
import sys, types, importlib, importlib.util
from pathlib import Path

arm, nonce = sys.argv[1], sys.argv[2]
model_output = Path(f"/case/fixtures/{arm}.txt").read_text(encoding="utf-8").strip().replace("{{NONCE}}", nonce)

# Locate the installed xinference package dir WITHOUT executing its __init__ (which needs
# the full serving stack). find_spec returns the package search locations only.
spec = importlib.util.find_spec("xinference")
base = Path(spec.submodule_search_locations[0])
for name, rel in (("xinference", "."), ("xinference.model", "model"), ("xinference.model.llm", "model/llm")):
    m = types.ModuleType(name)
    m.__path__ = [str((base / rel).resolve())]
    m.__package__ = name
    sys.modules[name] = m

# Real, version-pinned framework code. tool_parsers/__init__ (stdlib-only) registers the
# parsers; Llama3ToolParser.extract_tool_calls is the sink.
parser_mod = importlib.import_module("xinference.model.llm.tool_parsers.llama3_tool_parser")
parser = parser_mod.Llama3ToolParser()

# The scripted model's completion is parsed by the framework. In 2.5.0 it is eval'd.
result = parser.extract_tool_calls(model_output)
print("extract_tool_calls ->", str(result)[:200])
