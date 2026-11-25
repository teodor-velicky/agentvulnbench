"""Minimal PandasQueryEngine path: the (scripted) model's pandas code goes to the output parser,
which runs it through safe_exec/safe_eval. The arm's input is the model output verbatim.

safe_eval/safe_exec build restricted globals from ALLOWED_BUILTINS but set no '__builtins__' key,
so Python auto-injects the real builtins module, leaving open()/exec()/compile() reachable by
bare name (GHSA-wvpx / CVE-2024-3098).
"""
import sys

import pandas as pd
from llama_index.core.query_engine.pandas.output_parser import PandasInstructionParser

arm, nonce = sys.argv[1], sys.argv[2]
code = open(f"/case/inputs/{arm}.txt", encoding="utf-8").read().replace("{{NONCE}}", nonce)

df = pd.DataFrame({"city": ["Paris", "Tokyo", "Lagos"], "population": [2, 14, 15]})
parser = PandasInstructionParser(df)
out = parser.parse(code)
print(str(out)[:300])
