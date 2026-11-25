# AgentVulnBench v0: first tool scores (locate stage)

Historical record (superseded by `bench/scores/v0/SCORES.md`, 21 cases). Kept for the line references in `paths-to-root/EVIDENCE.md`.
Scored 2026-11-25 on the 14 cases in `bench/cases/` at task start (base commit 9f83010).
Scorer: `bench/scorer.py` v0.1.0 (unchanged; no scorer bug was found), rule SPEC s2 + s7: a case is located when
one of the tool's first 10 findings is in `locator.file`, within ±25 lines of `locator.line`, with a class
compatible with `rd_class`.

## Headline (N = 14 cases)

| Tool | Version | locate@10 | prove | fix | e2e | flags/case | precision@10 | $ |
|---|---|---|---|---|---|---|---|---|
| **PitSense engine** (stub backend) | PitSense `5ae65df97c1d` (`pitsense` 0.1.0), deterministic-stub, Python 3.12.0 | **1/14 = 0.071** | 0/14 | 0/14 | 0/14 | 2.07 | 0.033 | 0.00 |
| Semgrep OSS | semgrep 1.184.0, registry packs p/python, p/javascript, p/security-audit (snapshot 2026-11-25, sha256 in `bench/tools/semgrep/SNAPSHOT.json`) | 0/14 = 0.000 | 0/14 | 0/14 | 0/14 | 5.07 | 0.000 | 0.00 |
| Bandit | bandit 1.9.4, Python 3.12.0, all default plugins | 0/14 = 0.000 | 0/14 | 0/14 | 0/14 | 7.14 | 0.000 | 0.00 |
| *PitSense surface map (diagnostic)* | same engine, all candidates before triage | *1/14 = 0.071* | 0/14 | 0/14 | 0/14 | 7.71 | 0.009 | 0.00 |

- **prove / fix are 0 by construction, not measured in Docker.** None of these tools emits an exploit input in the
  case's attack-slot format or a patch, so per SCORING.md ("missing stage = not solved") they score 0. The scorer
  was run with `--no-docker`, which prints `null` for prove/fix; `null` here means "no attempt", not "not scored".
  Semgrep has autofix for some rules, but no rule that fired at a key sink carries a fix, so there was nothing to try.
- **The PitSense row is a static-only, free run.** Stages run: surface map, cross-file reachability, G1-G5 triage,
  all with the deterministic stub (no LLM; the adapter makes the `claude` CLI unfindable, sets every LLM cap to 0,
  and aborts if the engine's cost counter moves). Dedup (network) and the 3-arm proof were not run. PitSense's real
  hunts use an LLM backend; this row measures the engine without one.
- **Only one hit across all tools**: PitSense on `mcp-inspector-ghsa-7f8r` (rank 2, `code-exec` at
  `server/src/index.ts:108`, triage verdict QUALIFIES).
- By attacker model: PitSense 1/3 on `malicious-web-content`, 0/3 on `remote-unauth`, 0/8 on
  `untrusted-llm-input`. Semgrep and Bandit 0 everywhere. Per-`rd_class` and per-attacker breakdowns are in
  `<tool>.json` → `aggregate`.
- Budget: everything ran locally for $0. Median wall-clock per case: PitSense 40 s (3 processes in parallel),
  Semgrep 127 s (2 jobs), Bandit 22 s. Per-case seconds are in each `<tool>.attempt.json`. No budget cap was needed.

## Per-case hit/miss matrix (all 14 cases present at task start)

Cell = scored result. `(n)` = total findings the tool produced for the case. "flagged @r" = the tool did report a
finding that the locate rule accepts, but at rank r > 10, so it does not count (from `diag_anyrank.json`, a
diagnostic, not a score).

| Case | lang | rd_class | PitSense | Semgrep | Bandit | PitSense surface (diag) |
|---|---|---|---|---|---|---|
| agno-ghsa-m4w4 | python | code-injection | miss (0) | miss, flagged @109 (117) | miss, flagged @72 (19798) | miss, flagged @32 (103) |
| bentoml-ghsa-hvj5 | python | unsafe-deserialization | miss (0) | miss (29) | miss (1054) | miss (83) |
| bentoml-ghsa-mrmq | python | ssrf | miss (1) | miss (40) | miss (1103) | miss, flagged @15 (113) |
| langchain-core-ghsa-c67j | python | unsafe-deserialization | miss (1) | miss (9) | miss (9901) | miss (15) |
| langchainjs-ghsa-gf3v | typescript | ssrf | miss (17) | miss (1) | n/a: Python-only (0) | miss (24) |
| langchainjs-ghsa-r399 | typescript | unsafe-deserialization | miss (5) | miss (1) | n/a: Python-only (0) | miss (24) |
| langflow-ghsa-rvqx | python | authz-bypass | miss (10) | miss (29) | miss (2989) | miss (59) |
| llama-index-ghsa-wvpx | python | prompt-injection-to-tool | miss (0) | miss, flagged @62 (99) | miss, flagged @12 (5253) | miss, flagged @16 (260) |
| mcp-filesystem-ghsa-hc55 | typescript | path-traversal | miss (0) | miss (0) | n/a: Python-only (0) | miss (2) |
| mcp-inspector-ghsa-7f8r | typescript | mcp-stdio-cmd-exec | **HIT @2** (3) | miss (0) | n/a: Python-only (0) | **HIT @7** (8) |
| mcp-python-sdk-ghsa-9h52 | python | dns-rebinding | miss (0) | miss (2) | miss (3136) | miss (7) |
| mcp-server-git-ghsa-5cgr | python | path-traversal | miss (0) | miss (0) | miss (37) | miss (2) |
| mcp-server-git-ghsa-vjqx | python | path-traversal | miss (0) | miss (0) | miss (85) | miss (3) |
| smolagents-ghsa-6v92 | python | sandbox-escape | miss (0) | miss (8) | miss (918) | miss (7) |

Bandit's 4 TypeScript cases count as misses in its 0/14; on the 10 Python cases it is 0/10.

## What the misses say (for PitSense and for the benchmark)

1. **Ranking, not detection, loses 2 cases for every tool.** The `eval()` sinks in agno (line 2034) and
   llama-index (`exec_utils.py:140`, 12 lines from the key line 152) are flagged by all three tools: Semgrep
   `eval-detected`, Bandit `B307`, PitSense `code-exec`. They rank 12 to 109, below the k = 10 cap, because each
   tool reports many look-alike sinks with nothing to say which one an attacker reaches. Bandit's llama-index hit
   at rank 12 is the nearest miss.
2. **The stub triage throws away surfaced true sinks.** PitSense's surface map holds the key sink in 4 of 14 cases
   (agno, bentoml-mrmq, llama-index, mcp-inspector), but triage keeps only mcp-inspector. agno's sink is REJECTed at
   G1-outsider because "the reasoning reachability pass did NOT confirm an unauthenticated outsider [...]
   (reasoning unavailable (stub))". bentoml-mrmq's sink is REJECTed because "no untrusted source traced
   (caller not mapped statically)". In both, the stub's missing reasoning, plus a G1 that assumes an
   unauthenticated network outsider, rejects the bug. 8 of 14 cases use the `untrusted-llm-input` attacker, and
   PitSense scores 0/8 on them. This matches CHAINLAB packet 0002's proposed G1 rule for model-mediated attackers.
3. **Five cases are invisible to every tool**: path traversal in the MCP filesystem/git servers (3 cases, an
   allowlist/prefix-check logic bug), the langflow missing-auth route, and the FastMCP DNS-rebinding default. None
   of them has a dangerous call at the sink line, so pattern rules have nothing to match.
4. Semgrep's registry packs fire very little on TypeScript agent code: 1 finding on each langchainjs tree, 0 on the
   MCP servers and inspector.

## Class mapping (adapters never read the answer key)

- Semgrep / Bandit: the first CWE in the rule metadata mapped by `bench/tools/common.py:CWE_CLASS` (for example
  94/95 → code-injection, 78 → command-injection, 502 → unsafe-deserialization, 22 → path-traversal,
  918 → ssrf), else `other`. Bandit's B307 `eval` carries CWE-78, which maps to command-injection, in the same
  family as code-injection.
- PitSense (adapter private, drives the private engine): engine class map. The one judgement call, `missing-origin-websocket` →
  dns-rebinding, matters for no case: the engine raised no candidate in the FastMCP server file.
- Ranking uses each tool's own signals only. Semgrep: severity, then confidence, then path and line. Bandit: the
  same order. PitSense: QUALIFIES, then DOWNGRADE (held for a human), each in surface-map order; REJECTs are dropped
  because the engine drops them. Sorting by path within a severity tier is arbitrary but deterministic and
  key-blind.

## Inputs, pins, caveats

- Source: the full repo tree at each case's vuln SHA, from the GitHub codeload tarball (no .git, no history, no
  advisory), per SPEC s2. URLs and tarball sha256 are in `bench/tools/src-manifest.json`. 0 members were skipped on
  extraction.
- Semgrep rule YAML is under the Semgrep Rules License, so it is not committed. Only its sha256 is
  (`SNAPSHOT.json`). The adapter refuses to run if the cached snapshot differs. p/typescript is byte-identical
  to p/javascript.
- Windows path limit: semgrep-core cannot open paths over 260 characters. On langflow and llama-index it failed
  with "Failed to obtain target files" (rc 2, 0 files scanned). Both were re-scanned from a short real-path copy
  (`--src-root C:/avb`). The adapter now treats rc 2 or 0 scanned files as an error, so a failed scan can never
  count as a real zero. For every case, the key's `locator.file` is in Semgrep's scanned-paths list.
- Semgrep scan errors (parse or timeout, recorded per case in `note`): 4 on each langchainjs tree (TypeScript
  `export type` partial parses in other files), 6 on langflow, 1 timeout on bentoml-hvj5 (minified swagger JS).
  None was on a key file.
- CodeQL was not scored. Its licence allows academic research and analysis of open-source code, but it is unclear
  whether a company may publish benchmark scores with it. It was skipped while that is unclear; clarifying the
  licence is a follow-up.
- Not like-for-like with SPEC's "same budget cap for every tool": no cap was set, because every tool finished
  in minutes and was free.

## Files

| File | What |
|---|---|
| `bench/scores/v0/<tool>.attempt.json` | `avb-attempt/0`, top 10 findings per case plus `n_findings_total`, budget, notes, tool metadata |
| `bench/scores/v0/<tool>.json` | `avb-score/0` scorer output (per case + aggregate) |
| `bench/scores/v0/diag_anyrank.json` | where each tool's full list touches the key (diagnostic only) |
| `bench/tools/<tool>/adapter.py` | adapters: `pitsense`, `semgrep`, `bandit`; shared `bench/tools/common.py` |
| `bench/tools/fetch_src.py`, `src-manifest.json` | source trees at the vuln SHA |
| `bench/tools/tables.py` | prints the two tables above from the score files |

## Reproduce

```
python -I bench/tools/fetch_src.py                                   # 14 trees -> bench/tools/.cache/src/ (gitignored)
# PitSense rows: produced by the private engine @ 5ae65df (its adapter is not published);
# the committed attempt files re-score with the scorer below
python bench/tools/semgrep/adapter.py --jobs 2                       # rules: bench/tools/.cache/semgrep-rules (SNAPSHOT.json)
#   Windows only: copy langflow-ghsa-rvqx and llama-index-ghsa-wvpx to a short path, then
python bench/tools/semgrep/adapter.py --cases langflow-ghsa-rvqx,llama-index-ghsa-wvpx --src-root C:/avb
uv venv bench/tools/.cache/venv-bandit --python 3.12
uv pip install --python bench/tools/.cache/venv-bandit/Scripts/python.exe bandit==1.9.4
python bench/tools/bandit/adapter.py
# score (locate only; deterministic, needs only the committed attempt files):
for t in pitsense semgrep bandit pitsense-surface; do
  python -I bench/scorer.py score bench/scores/v0/$t.attempt.json --no-docker --out bench/scores/v0/$t.json
done
python -I bench/tools/diag_anyrank.py && python -I bench/tools/tables.py
```

Scoring from the committed attempt files needs no network, Docker or engine. Re-running a tool needs the cached
source trees, and for Semgrep the identical rule snapshot. Registry packs change over time, so a fresh
`--refresh-rules` download is a different tool configuration.
