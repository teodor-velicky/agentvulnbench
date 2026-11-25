# rankbase: LLM-free ranking baseline (AgentVulnBench v0, locate stage only)

A deliberately cheap baseline: no LLM, no network, no external tools, stdlib only. It exists to answer one
question the first score run raised: all three real tools *flagged* key sinks but ranked them below 10, so is
ranking, not detection, what loses cases, and how far does a trivial ranker get?

## Designed WITHOUT the answer keys

The signals, weights and thresholds in `adapter.py` were written from general knowledge of dangerous-sink families
and agent/MCP/web-framework entry points **before** any `bench/cases/*/case.json` locator, `rd_class`, `notes`, fix
diff or advisory text was read, and before the adapter was run on any case. The adapter itself only receives what
`common.tool_cases()` hands every tool (language, repo, vuln SHA, one-line attacker model, source path). It was
**not** tuned afterwards: the numbers in `bench/scores/v0/SCORES.md` are from the first and only weight set.
(Caveat: the author knew the 14 earlier cases' tool scores, and the class list in SPEC.md (code injection,
deserialization, SSRF, path traversal, SSTI, DNS rebinding, authz bypass). That is general benchmark knowledge,
not per-case location knowledge.)

## What it does

1. Walks the tree (skips `.git`, `node_modules`, tests, docs, examples, migrations, vendored/minified/`.d.ts`).
2. Finds candidate sink lines with per-language regexes. Each family has a danger weight (e.g. `eval`/`exec`/
   `new Function`/`shell=True`/`child_process.exec` = 10; `pickle`/`yaml.load`/`torch.load` = 9; template render
   from strings = 7; outbound fetch = 5; filesystem open/send_file = 4-5; `subprocess` = 6; `__import__` = 4).
3. Entry-reachability proxy (multiplier from 1): the enclosing function (Python: `ast`; JS/TS: nearest preceding
   function header, regex) is decorated/registered as a route, tool or handler (`@app.get`, `@mcp.tool`,
   `@server.call_tool`, `app.post(`, `server.tool(`, ...) -> +1; the sink line uses a parameter of that function
   (cheap taint proxy) -> +1; path hints (`server`, `api`, `routes`, `tools`, `handlers`, `mcp`) -> +0.5;
   literal-only argument -> x0.4.
4. Rank by `weight x multiplier`, with a per-file decay (i-th best hit in a file keeps 1/(1+0.35 i)) so one file
   cannot fill the top 10; ties by path, line. Writes `bench/scores/v0/rankbase.attempt.json` via
   `common.write_attempt`.

Class = the sink family mapped to an rd_class label. Authz bypass and DNS rebinding are not sink-shaped, so the
baseline mostly cannot find them; that is part of what it shows.

Run: `python -I bench/tools/rankbase/adapter.py [--cases a,b] [--out-dir DIR]` (needs `bench/tools/fetch_src.py`
output). `--out-dir` writes the attempt elsewhere, for a reproduction check.
