# Paths to root for AI agents: evidence map

PitSense, Teodor Velický. Evidence frozen 2026-11-25. Companion to [`PAPER.md`](PAPER.md). One row per
factual or numeric claim in the paper, keyed by its `[E<n>]` tag.

**Status.** VERIFIED means the cited file was opened (or the stated command run) on 2026-11-25 and it
says what the claim says. UNVERIFIED means it was not confirmed; every UNVERIFIED row is a
classification judgement, not a fact lookup. "gh API" means a read-only `gh api advisories/<GHSA>` call,
or `gh api repos/modelcontextprotocol/<repo>/security-advisories/<GHSA>` for repository-level
advisories, made on 2026-11-25; its output is summarised in Appendix A. Advisory URLs follow the pattern
`https://github.com/advisories/<GHSA>`. Repository-level MCP advisories are at
`https://github.com/modelcontextprotocol/<servers|inspector>/security/advisories/<GHSA>`.

**Where the sources live.** Files named in this folder (`map_kbc_paths.py`, `reconcile.py`,
`kbc-path-map.csv`, `reconciled-path-map.csv`, `rater2/`, `kbc-snapshot/`, `kbc-e-oos/`) are published
here. `corpus/kbc/batches/*.jsonl` is published as `kbc-snapshot/` (the four snapshot batches; the KBC-E
batch is not published). `bench/` paths refer to the AgentVulnBench repository. Other paths
(`chainlab/`, `eval/`, `docs/`, `ssrfguard/`, `research/`) are files in PitSense's research repository,
which is not public; for those rows this map records the figure and where it came from.

**Count: 108 claim rows, 104 VERIFIED, 4 UNVERIFIED** (E84, E92, E93 and E104; all are classification
judgements). E92 and E93 record the rule-based rater alone; the paper cites the reconciled two-rater map
(E101 to E104) in their place. Appendix A adds 70 advisory-identity checks, all VERIFIED (published,
not withdrawn).

| # | Claim | Source | Status |
|---|---|---|---|
| E1 | KBC holds 121 rows in 4 batches, all `kind: positive`, each with vuln SHA, fix SHA, class, locator, attacker | `corpus/kbc/batches/{backfill-2026-11,fresh-targets,mcp-agents,serving-lowcode}.jsonl` (27+21+33+40 lines). I parsed them with a Python one-liner: 121 rows, Counter kind={'positive': 121}, `kbc` keys include fix_sha, rd_class, attacker | VERIFIED |
| E2 | KBC attacker counts: untrusted-llm-input 29, remote-authed-user 27, remote-unauth 23, untrusted-data-store 17, malicious-web-content 9, malicious-mcp-server 9, library-caller 7 | Same files, `Counter(r['kbc']['attacker'])` | VERIFIED |
| E3 | 21 AgentVulnBench cases, all PROVEN with attack 5/5, control 0/5, fix 0/5 | `bench/results/*.json` (21 files at the scored snapshot), the `arms.*.hits/trials` and `verdict` fields. Fact-check: the directory now holds 23 case results, all PROVEN 5/0/0; the 2 later ones are E107. The 21 are the scored set (E86) | VERIFIED (snapshot) |
| E4 | 5 CHAINLAB cases, all PROVEN at 5/0/0 | `chainlab/results/*/proof_result.json`, the `arms.*.canary_hits/trials` and `verdict` fields; `chainlab/README.md` results table. Fact-check: there are now 6, all PROVEN 5/0/0 with network none; the 6th (Langroid) is E107 | VERIFIED (snapshot) |
| E5 | CHAINLAB runs every arm with `--network none` | `chainlab/README.md` "How to run"; `network: none` in all 5 proof_result.json | VERIFIED |
| E6 | Scripted model = a deterministic fake LLM in the framework's own LLM interface, returns the attacker completion verbatim. A positive shows the framework lacks a guard | `chainlab/README.md` "The scripted model" | VERIFIED |
| E7 | Proposed G1 rule text (model output to a sink with no guard that limits it to the safe shape = attacker-reachable) | `chainlab/`paths-to-root/PAPER.md` section 2.3 section 2 | VERIFIED |
| E8 | locate@10 rule: one of the first 10 findings in `locator.file`, ±25 lines, compatible class. 14 cases scored in the first run | `bench/scores/v0/SCORES.md` header; `bench/SCORING.md` stage rules | VERIFIED |
| E9 | The 7 batch-4 cases (ag2-2h4w, langchain-core-6qv9, langgraph-7p73, litellm-7488, mcp-python-sdk-qx49, mcp-server-git-6hqx, vllm-hjq4) are not in the scored 14 | `bench/scores/v0/SCORES.md` per-case matrix lists 14 cases, none of these 7. `bench/notes/batch-4.md` "PROVEN (7)" | VERIFIED |
| E10 | Miner snapshot: 821 non-duplicate advisories, 2026-06-01 to 2026-11-24. Class numbers may be quoted only in the audit's corrected form | `research/label-audit/RESULTS.md` sections A, F, headline ("Do not cite miner class counts as exact") | VERIFIED |
| E11 | LangChain PALChain CVE-2023-36258: whole program sent to `PythonREPL().run()` with no guard; 0.0.235 → 0.0.247; PROVEN | `chainlab/README.md` results table; `chainlab/`paths-to-root/PAPER.md` section 2.3b; gh API: GHSA-2qmj-7962-cjq8, langchain first patched 0.0.247 | VERIFIED |
| E12 | langchain-experimental CVE-2023-44467: `validate_code` denylist omits `__import__`; 0.0.23 → 0.0.24; follows 36258; PROVEN | `chainlab/`paths-to-root/PAPER.md` section 2.3b; `chainlab/README.md` table; gh API GHSA-gjjr-63x4-v8cq | VERIFIED |
| E13 | PraisonAI CodeAgent CVE-2026-61447: `subprocess.run([python,tmp], env=os.environ.copy())` with `CodeConfig(sandbox=True)` ignored; praisonaiagents 1.6.77 → 1.6.78; PROVEN | `chainlab/`paths-to-root/PAPER.md` section 2.3c; `chainlab/README.md` table; gh API GHSA-2xv2-w8cq-5gxw (praisonaiagents@1.6.78) | VERIFIED |
| E14 | n8n GHSA-9pq8: regex/AST scan of literal format strings vs runtime `str.format`; vuln 5 disagreements, fix 4, current 0 (the fix was incomplete, a later release closed it) | `gatediff/RESULTS.md` per-chain table and "What the disagreements are" | VERIFIED |
| E15 | mcp-atlassian GHSA-6529-c226-h328 (CVE-2026-77261): redirect-blocking SSRF hook only in the header-PAT branch | `corpus/kbc/batches/fresh-targets.jsonl` row reason; gh API summary "SSRF redirect protection missing for basic-auth and OAuth authentication branches" | VERIFIED |
| E16 | LLMMathChain CVE-2023-29374 / GHSA-fprp-p869-w6q2: `_process_llm_result` → `PythonREPL().run()`; 0.0.131 → 0.0.142; PROVEN | `chainlab/README.md` table; `chainlab/results/langchain-llmmathchain-cve-2023-29374/proof_result.json`; gh API (CVE matches) | VERIFIED |
| E17 | Xinference CVE-2026-61539: `eval(model_output, {}, {})` in Llama3ToolParser; 2.5.0 → 2.7.0; fix uses `json.loads` → `ast.literal_eval`; PROVEN | `chainlab/`paths-to-root/PAPER.md` section 2.3c; gh API GHSA-x2rj-828p-hx9m (critical, xinference fixed 2.7.0) | VERIFIED |
| E18 | agno CVE-2026-35002: `eval()` of `field_type` from a `get_user_input` tool call; bench PROVEN | `bench/cases/agno-ghsa-m4w4/case.json` (title, attacker_story); `bench/results/agno-ghsa-m4w4.json`; gh API GHSA-m4w4-3r8h-jw98 | VERIFIED |
| E19 | vLLM CVE-2025-9141: Qwen3-Coder tool parser `eval()`s unknown-type params; KBC row | `corpus/kbc/batches/serving-lowcode.jsonl` (kbc-ghsa-79j6-g2m3-jgfw); gh API (vllm@0.10.1.1) | VERIFIED |
| E20 | Langflow CVE-2026-27966: CSV Agent hard-codes `allow_dangerous_code=True` | `serving-lowcode.jsonl` kbc-ghsa-3645-fxcv-hqr4; gh API "Langflow has Remote Code Execution in CSV Agent" | VERIFIED |
| E21 | langchain CVE-2024-21513: VectorSQLDatabaseChain `eval()`s values returned by LLM-generated SQL | `mcp-agents.jsonl` kbc-ghsa-cgcg-p68q-3w7v; gh API (langchain-experimental@0.0.21) | VERIFIED |
| E22 | agno sink flagged by Semgrep @109, Bandit @72, PitSense surface @32, all > k=10. llama-index: the `eval` at `exec_utils.py:140` (12 lines from the `safe_exec` locator, line 152) flagged by all three (Semgrep `eval-detected`, Bandit `B307`), Bandit nearest at rank 12. Fact-check: an earlier draft called it the `exec`; `bench/scores/v0/diag_anyrank.json` near_finding line 140, rules eval-detected / B307 | `bench/scores/v0/SCORES.md` (21-case) per-case matrix, "flagged @r" cells for agno-ghsa-m4w4 and llama-index-ghsa-wvpx (Semgrep @62, Bandit @12, surface @16); same values in `v0-14case/SCORES-14case.md` | VERIFIED |
| E23 | (14-case run) PitSense stub engine 0/8 on `untrusted-llm-input`. agno sink REJECTed at G1-outsider (reasoning unavailable, stub) | `bench/scores/v0/v0-14case/SCORES-14case.md` lines 28 and 67-72. The 21-case figure (0/9) is E88 | VERIFIED |
| E24 | smolagents CVE-2025-5120: forbidden submodule via indirect getattr; PROVEN | `bench/cases/smolagents-ghsa-6v92/case.json`; `bench/results/smolagents-ghsa-6v92.json`; gh API | VERIFIED |
| E25 | llama-index CVE-2024-3098: `safe_exec` restricted globals lack `__builtins__` removal; PROVEN | `bench/cases/llama-index-ghsa-wvpx/case.json`; results json; gh API | VERIFIED |
| E26 | AG2 CVE-2026-113663: newline passes the `readonly=True`/allowlist prefix check, `sh -c` runs line 2; PROVEN | `bench/cases/ag2-ghsa-2h4w/case.json`; `bench/results/ag2-ghsa-2h4w.json`; KBC reason (denylist omitted newline/CR); gh API summary "Newline injection in SandboxShellTool bypasses allowed=[...] and readonly=True" | VERIFIED |
| E27 | Flowise CVE-2026-69263 is a CVE-2025-8943 patch bypass via `npm_config_*`; GATEDIFF vuln 3 disagreements | `gatediff/RESULTS.md` per-chain table; gh API GHSA-xc48-889x-5qmw summary "CVE-2025-8943 Patch Bypass: npm_config_yes…" | VERIFIED |
| E28 | KBC chains on the same sandbox: Flowise CSVAgent/Pyodide, Flowise NodeVM, n8n expression sandbox | `corpus/kbc/notes/serving-lowcode.md` chain table; `corpus/kbc/notes/backfill-2026-11.md` "Linked chains" | VERIFIED |
| E29 | GATEDIFF: disagreement reachable on 4 of 5 public gates | `gatediff/RESULTS.md` verdict | VERIFIED |
| E30 | No Semgrep rule expresses the OpenClaw shell-flag parser differential | `gatediff/RESULTS.md` per-chain table, Semgrep column for openclaw-inline | VERIFIED |
| E31 | MCP server-filesystem GHSA-hc55-p739-j48w = CVE-2025-53110, bare prefix match; PROVEN | gh API: GHSA-hc55-p739-j48w → CVE-2025-53110, fixed 2025.7.1; `bench/cases/mcp-filesystem-ghsa-hc55/case.json` (cve CVE-2025-53110). The KBC row merges GHSA-hc55 and GHSA-q66q (= CVE-2025-53109, gh API); since commit a03b766 it lists the ids as explicit pairs (E95) | VERIFIED |
| E32 | mcp-server-git CVE-2025-68143 `git_init` ignores `--repository`; PROVEN | bench case.json + results; gh API GHSA-5cgr-j3jf-jw3v | VERIFIED |
| E33 | mcp-server-git CVE-2026-27735 `git_add` stages `../` paths; PROVEN | bench case.json + results; gh API GHSA-vjqx-cfc4-9h6v | VERIFIED |
| E34 | Flowise CVE-2025-61913 WriteFile writes any model-supplied path | `serving-lowcode.jsonl` kbc-ghsa-jv9m-vf54-chjj; gh API summary "arbitrary file write through its WriteFileTool" | VERIFIED |
| E35 | PraisonAI CVE-2026-55540 abspath not realpath, symlink escape | `fresh-targets.jsonl` kbc-ghsa-ch89-h4r2-c8f8; gh API summary "escape the configured workspace via symlinks" | VERIFIED |
| E36 | mcp-server-git CVE-2026-134465 / GHSA-w766 (nested gitdir) followed by GHSA-q74p "Incomplete Fix for GHSA-w766…" | gh API repo advisories (servers): both published, titles as quoted; `corpus/kbc/notes/backfill-2026-11.md` "Linked chains" | VERIFIED |
| E37 | mcp-atlassian GHSA-xjgw-4wvw-rgm4 (CVE-2026-27825) followed by GHSA-6vmq (download guard defaults to CWD, RCE) and the unguarded upload/read twin | `corpus/kbc/notes/fresh-targets.md` chain 1; gh API: xjgw critical CVE-2026-27825; 6vmq "Incomplete path traversal fix allows intra-CWD module overwrite and RCE" | VERIFIED |
| E38 | All 3 MCP path-traversal cases, langflow-rvqx and FastMCP 9h52 are invisible to every tool: no dangerous call at the sink line | `bench/scores/v0/SCORES.md` (21-case) "What the misses say" item 3 (also lists the SQL, token-passthrough and OAuth cases) and per-case matrix; `v0-14case/SCORES-14case.md` item 3 | VERIFIED |
| E39 | mcp-server-git GHSA-6hqx: repo `.git/config` `core.fsmonitor` runs on `git_status`; PROVEN | `bench/cases/mcp-server-git-ghsa-6hqx/case.json`; results json; gh API repo advisory (published, high) | VERIFIED |
| E40 | mcp-server-git GHSA-8wv7: submodule config still runs programs on `git_diff` | KBC backfill row reason; gh API repo advisory title | VERIFIED |
| E41 | vLLM CVE-2026-22807 (auto_map ignores trust_remote_code) and CVE-2026-27893 (hard-coded trust_remote_code=True) | `serving-lowcode.jsonl` rows 2pc9, 7972; gh API summaries | VERIFIED |
| E42 | LiteLLM CVE-2024-2952: Hub `chat_template` rendered in non-sandboxed Jinja2 | `serving-lowcode.jsonl` kbc-ghsa-46cm-pfwv-cgf8; gh API (SSTI, critical) | VERIFIED |
| E43 | LangGraph CVE-2026-27794: BaseCache default `pickle_fallback=True` | `mcp-agents.jsonl` kbc-ghsa-mhr3-j7m5-c7c9; gh API summary "BaseCache Deserialization of Untrusted Data" | VERIFIED |
| E44 | Six mcp-server-git config-exec rows (6hqx, pm7p, 87qg, h2g3, 9vjp, 8wv7), each fix leaving the next | `corpus/kbc/notes/backfill-2026-11.md` "Linked chains" bullet 3; gh API: all six published repo advisories | VERIFIED |
| E45 | vLLM: three separate code paths load remote code despite `trust_remote_code=False` | `corpus/kbc/notes/serving-lowcode.md` chain table | VERIFIED |
| E46 | VARIANT rules from the first vLLM fix HIT both trust_remote_code bypasses (2pc9 strict, 7972 family), alarm at f1 = yes | `variant/RESULTS.md` section 2 table | VERIFIED |
| E47 | vLLM CVE-2025-47277: TCPStore on all interfaces, peer object unpickled; PROVEN | bench case.json + results; gh API GHSA-hjq4-87xh-g4fv (critical, fixed 0.8.5) | VERIFIED |
| E48 | vLLM Mooncake CVE-2025-29783 → CVE-2025-32444: the first fix left `recv_pyobj` on `tcp://*` | `serving-lowcode.md` chain table; gh API x3m8 (0.8.0), hj4w (0.8.5) | VERIFIED |
| E49 | BentoML CVE-2024-2912 pickle by media type (PROVEN) → CVE-2025-27520 comes back in the new server | bench case.json + results (hvj5); `serving-lowcode.md` chain table; gh API both | VERIFIED |
| E50 | langchain-core CVE-2025-68664 and LangChain.js CVE-2025-68665: model-supplied `lc` secret marker revived, env secret read; both PROVEN | bench case.json `attacker_story` for c67j and r399; results jsons; gh API both | VERIFIED |
| E51 | VARIANT HIT on Mooncake (family rule, alarm at f1) and BentoML (HIT, no alarm at f1: later regression) | `variant/RESULTS.md` section 2 table and paragraph after it | VERIFIED |
| E52 | bentoml-hvj5, langchain-core-c67j, langchainjs-r399 missed by all tools | `bench/scores/v0/SCORES.md` (21-case) per-case matrix: miss in all 5 columns | VERIFIED |
| E53 | vLLM FIX arm blocks via `ConnectionRefusedError` because the fix binds loopback | `bench/notes/batch-4.md` lines 99-109 | VERIFIED |
| E54 | Langflow CVE-2025-3248: unauthenticated `/api/v1/validate/code` exec()s definitions; PROVEN | bench case.json + results; gh API "Langflow Unauth RCE" | VERIFIED |
| E55 | MCP Inspector CVE-2025-49596: `/stdio` spawns query command, no auth/Origin check; PROVEN | bench case.json + results; gh API GHSA-7f8r-222p-6f5g | VERIFIED |
| E56 | FastMCP CVE-2025-66416: DNS-rebinding protection off by default; PROVEN | bench case.json + results; gh API summary "does not enable DNS rebinding protection by default" | VERIFIED |
| E57 | LiteLLM CVE-2026-59822: failed key check falls back to anonymous OAuth2-passthrough session; PROVEN | bench case.json + results; gh API "MCP Authentication Bypass via OAuth2 Passthrough Fallback", fixed 1.84.0 | VERIFIED |
| E58 | PraisonAI CVE-2026-55534 (`--api-key` ignored) and CVE-2026-55536 (unanchored `re.match` Origin) | `fresh-targets.jsonl` rows 7ww9, 6g6r; gh API summaries ("--api-key is ignored", "unanchored regex") | VERIFIED |
| E59 | Langflow first fix added auth only; CVE-2026-7873 shows `validate_code` still exec()s | `serving-lowcode.md` chain "The auth-only fix left authenticated RCE"; gh API GHSA-v798-mcc6-2m3m | VERIFIED |
| E60 | MCP Inspector CVE-2025-49596 → GHSA-wmjf (no Origin + auth omitted) → GHSA-vcc9 "Incomplete fix for CVE-2025-49596" | `backfill-2026-11.md` "Linked chains" bullet 1; gh API repo advisories (inspector), vcc9 title quoted | VERIFIED |
| E61 | PraisonAI three fix rounds on the same missing-enforcement class | `corpus/kbc/notes/fresh-targets.md` chain 8 | VERIFIED |
| E62 | PitSense's only locate@10 hit: mcp-inspector-7f8r at rank 2 (in 21 cases the other hit is rankbase's, E86) | `bench/scores/v0/SCORES.md` (21-case) headline bullet "The two hits are different cases" | VERIFIED |
| E63 | authn/authz corrected ≈ 40% (95% CI 36-43%) of 821, the largest class | `research/label-audit/RESULTS.md` headline and V2 | VERIFIED |
| E64 | MCP Python SDK CVE-2026-115563: client_secret sent to an MCP-server-chosen token endpoint; PROVEN | bench case.json + results (qx49); gh API summary | VERIFIED |
| E65 | MCP TypeScript SDK CVE-2026-104850: the same shape | `mcp-agents.jsonl` row 6qxp; gh API summary | VERIFIED |
| E66 | mcp-remote CVE-2025-6514 (`authorization_endpoint` → `open()` → shell) and Inspector GHSA-q978 (code exec via the OAuth authorization URL) | `mcp-agents.jsonl` row 6xpm; `backfill-2026-11.jsonl` row q978; gh API both | VERIFIED |
| E67 | MCP SDK CVE-2026-116684 and CVE-2026-111771: bearer auth accepts tokens for another resource server | `mcp-agents.jsonl` rows w4fh, rvq5; gh API summaries | VERIFIED |
| E68 | FastMCP GHSA-c2jp consent fix, then CVE-2026-27124 GHSA-rww4 consent not verified at callback | `backfill-2026-11.md` "Linked chains" bullet 2; gh API (rww4 "Missing Consent Verification in OAuth Proxy Callback") | VERIFIED |
| E69 | 9 OAuth rules separate 8/8 KBC OAuth/token rows in-sample. Held-out sweep not yet done | `oauth/RESULTS.md` rule × row table, separation count, verdict "B5 follow-ups: a held-out sweep" | VERIFIED |
| E70 | SSRF guard failure order (a)-(f) | `ssrfguard/RESULTS.md` verdict, "hypothesised failure order" | VERIFIED |
| E71 | BentoML CVE-2025-54381: URL file inputs fetched with no destination check; PROVEN | bench case.json + results (mrmq); gh API | VERIFIED |
| E72 | LangChain.js CVE-2026-26019: protocol-relative crawled link reaches an internal address; PROVEN | bench case.json `attacker_story` (gf3v); results json; gh API | VERIFIED |
| E73 | vLLM CVE-2025-6242 redirect → CVE-2026-24779 parser differential | `serving-lowcode.md` chain table; `ssrfguard/RESULTS.md` verdict bullet "vLLM"; gh API both (0.11.0, 0.14.1) | VERIFIED |
| E74 | Flowise CVE-2026-69257: IPv4-mapped IPv6 not unwrapped | `serving-lowcode.jsonl` row c6xh; gh API summary | VERIFIED |
| E75 | Open WebUI CVE-2026-70485 NAT64 → CVE-2026-87996 Playwright DNS rebinding | `serving-lowcode.md` chain table; gh API both | VERIFIED |
| E76 | SSRFGUARD battery at the first fix reached the canary with the later public bypass in 2/2 chains: vLLM 3f6c→qh4c, LangChain.js gf3v→GHSA-mphv (CVE-2026-27795, fixed @langchain/community 1.1.18) | `ssrfguard/RESULTS.md` verdict and "Recall vs Semgrep" row 3; gh API GHSA-mphv-75cg-56wg → CVE-2026-27795, fixed 1.1.18 | VERIFIED |
| E77 | Battery hits the advisory mechanism 7/7. VARIANT Semgrep SSRF rules 2/7 | `ssrfguard/RESULTS.md` "Recall vs Semgrep" table | VERIFIED |
| E78 | gf3v missed by all tools. bentoml-mrmq in the PitSense surface map @15, REJECTed "no untrusted source traced" | `bench/scores/v0/SCORES.md` (21-case) per-case matrix (gf3v miss in all columns; mrmq surface "flagged @15"); reject reason in `v0-14case/SCORES-14case.md` line 69 | VERIFIED |
| E79 | 37 advisories carry bypass wording (exact). An undercount: 3 unflagged incomplete-fix advisories seen in the 150-row sample | `research/label-audit/RESULTS.md` V4 and section F | VERIFIED |
| E80 | VARIANT: 7 of 10 later bypasses flagged (5 of 10 strict) | `variant/RESULTS.md` section 2 "Overall" | VERIFIED |
| E81 | Strict model-mediated ≥ 25 of 821 (lower bound; estimate 37, CI 16-61; about 3-5%). Not concentrated in October (7 of 25). "About 10" / "5 of 10 in October" superseded | `research/label-audit/RESULTS.md` headline, section E, V5, V10 | VERIFIED |
| E82 | (14-case run, historical) locate@10: PitSense 1/14 = 0.071, Semgrep 0/14, Bandit 0/14 | `bench/scores/v0/v0-14case/SCORES-14case.md` headline table; restated in `bench/scores/v0/SCORES.md` "Original 14 cases" footnote | VERIFIED |
| E83 | PitSense row is the deterministic stub with no LLM. PitSense's production engine uses an LLM backend | `bench/scores/v0/SCORES.md` "The PitSense row is a static-only, free run" | VERIFIED |
| E84 | 24 of 26 proven reproductions map onto the eight paths | My mapping of every case in `bench/results/` and `chainlab/results/` to a path (P1: 29374, 36258, x2rj, 2xv2, agno; P2: 44467, ag2, wvpx, 6v92; P3: hc55, 5cgr, vjqx; P4: 6hqx; P5: hvj5, c67j, r399, hjq4; P6: rvqx, 7488, 7f8r, 9h52; P7: qx49; P8: mrmq, gf3v). This is a judgement by one author with no second rater | UNVERIFIED |
| E85 | The two unmapped cases (6qv9, 7p73) use the `library-caller` attacker; 7p73's impact is cross-tenant memory access | `bench/cases/langchain-core-ghsa-6qv9/case.json` and `bench/cases/langgraph-ghsa-7p73/case.json` (`attacker`, `attacker_story`) | VERIFIED |
| E86 | 21-case locate@10: PitSense 1/21 (mcp-inspector-7f8r @2), Semgrep 0/21, Bandit 0/21, rankbase 1/21 (llama-index-wvpx @2), surface diagnostic 1/21. One hit each, so the difference is not meaningful. untrusted-llm-input: 9 cases, rankbase 1, the others 0. | `bench/scores/v0/SCORES.md`: headline table, headline bullets, "Per attacker model" table | VERIFIED |
| E87 | Missed by every tool in the 21-case run: ag2-2h4w, smolagents-6v92, mcp-server-git-6hqx, vllm-hjq4, litellm-7488, mcp-python-sdk-qx49 | `bench/scores/v0/SCORES.md` per-case matrix (miss in all 5 columns for each) | VERIFIED |
| E88 | PitSense surface map holds the key sink in 4 of 21 cases; triage keeps one. PitSense 0/9 on `untrusted-llm-input` | `bench/scores/v0/SCORES.md` "What the misses say" item 2 | VERIFIED |
| E89 | KBC stub-engine recall: surface 21/120 evaluable, QUALIFIES 1, end-to-end 1/120. By class: authz-bypass surface 0/11, path-traversal 1/13, command-injection 0/10, sandbox-escape 1/10, ssrf 4/14 (0 qualified), unsafe-deserialization 4/14 (0 qualified); dns-rebinding, oauth-confused-deputy, token-passthrough all 0 surfaced | `docs/KBC-RECALL.md` headline and "By rd_class" table | VERIFIED |
| E90 | ENGINE-G1 patch 0001 on the stub: KBC surfaced-20 QUALIFIES 1 to 4; 48 negatives of a private evaluation set: 0 false passes before and after, no negative verdict changes | `eval/engine-g1/compare.md`, both tables | VERIFIED |
| E91 | ENGINE-LLM (claude CLI backend): 0/9 outsider-reachable rejects flip; causes 4 caller-not-mapped, 3 G1-auth (logged-in low-privilege user), 2 wrong traced path; KBC QUALIFIES 4 to 2; the private evaluation set's 4 positives: QUALIFIES 1 to 3; 0 false passes on 48 negatives; total $4.77 | `eval/engine-llm/RESULTS.md`: verdict, arm table, cost table, causes A-C | VERIFIED |
| E92 | Rule-based KBC row-to-path map: 111/121 mapped (91.7%); P1 5, P2 16, P3 16, P4 17, P5 9, P6 22, P7 12, P8 14, none 10 (7 library-caller, 3 authenticated-user classic injection or config). 16 overrides and 3 exclusions, each with a reason | `python -I research/paths-to-root/map_kbc_paths.py` output (run 2026-11-25); `research/paths-to-root/kbc-path-map.csv`. The counts are computed; the rules are one author's judgement with no second rater | UNVERIFIED (single rater) |
| E93 | Path x attacker in the map: P2 has 11 of 16 rows `remote-authed-user`; P3 has 14 of 16 `untrusted-llm-input`; the 27 `remote-authed-user` rows fall P2 11, P6 5, P8 5, P7 2, P3 1, none 3 | `kbc-path-map.csv`, Counter over (path, attacker) | UNVERIFIED (single rater, as E92) |
| E94 | Inbound Host/Origin battery, 10 probes of which 8 attacker-shaped: 9h52 vuln 8/8 attacker probes ACCEPT, fix 0/8; vcc9 vuln 8/8, fix 0/5 Host-based probes | `ssrfguard/RESULTS.md` SSRFGUARD-3 table (vuln and fix columns only; later-release columns are not used) | VERIFIED |
| E95 | KBC row kbc-ghsa-hc55-p739-j48w lists GHSA-hc55-p739-j48w/CVE-2025-53110 and GHSA-q66q-fx2p-7w4m/CVE-2025-53109 as pairs; the full validator passes on all 4 batches | commit a03b766; `gh api advisories/GHSA-q66q-fx2p-7w4m` gives CVE-2025-53109 and `gh api advisories/GHSA-hc55-p739-j48w` gives CVE-2025-53110 (2026-11-25); `python corpus/kbc/validate.py corpus/kbc/batches/*.jsonl` printed "121 row(s), 121 passed, 0 failed", rc 0 | VERIFIED |
| E96 | The first 14-case run is kept verbatim; restricted to those 14 cases the current runs give pitsense 1/14, semgrep 0/14, bandit 0/14, rankbase 1/14 | `bench/scores/v0/SCORES.md` "Original 14 cases" footnote; `bench/scores/v0/v0-14case/` | VERIFIED |
| E97 | The 5 CHAINLAB cases are not rows of the 121-row KBC snapshot | `grep -l` for fprp-p869, 2qmj-7962, gjjr-63x4, x2rj-828p, 2xv2-w8cq over the four snapshot batch files matches no file. | VERIFIED |
| E98 | rankbase: LLM-free; ranks sink danger times an entry-reachability proxy; weights written before any case key was read, never tuned | `bench/tools/rankbase/README.md` "Designed WITHOUT the answer keys" and "What it does"; SCORES.md notes | VERIFIED |
| E99 | The CONTROL arm must be a benign in-shape output through the same feature; it is the load-bearing discriminator for this class | `chainlab/`paths-to-root/PAPER.md` section 2.3 "The discriminating test"; `chainlab/README.md` "Limits" | VERIFIED |
| E100 | The scripted model may assume only in-shape output for the feature; it may not assume attacker config, plugin, environment or code on disk, a second bug, or operator-intended use | `chainlab/`paths-to-root/PAPER.md` section 2.3 "MAY assume" and "MAY NOT assume" | VERIFIED |
| E101 | Rater-2 agreement over 121 rows: raw 105/121 = 86.8%; Cohen's kappa 9 labels 0.850 (pe 0.120); same path on 98/101 rows both place on a path = 97.0%; path-vs-none agreement 89.3%, kappa 0.463; rater 1 111 on a path, rater 2 104; agreed none 7. Blinding and limits (shared class/attacker fields, single LLM pass, codebook from the authors' outline) as stated | `python -I research/paths-to-root/rater2/kappa.py` printed raw 0.8678 (105/121), kappa 0.8497, path-vs-none 0.8926 / 0.4626, both-path 0.9703 (98/101) (2026-11-25); `rater2/RESULTS.md` "How blindness was ensured" and "Limits". Note: RESULTS.md says rater 2 pushed 9 path rows to none; its own confusion line sums to 10 (P2 1, P4 1, P6 3, P7 1, P3 4), and the paper uses 10 | VERIFIED |
| E102 | Reconciled map: 105/121 on a path (86.8%), none 16; P1 5, P2 17, P3 14, P4 16, P5 9, P6 17, P7 13, P8 14; bounds 101 (both raters) to 114 (either); flipping the 6 contested calls 102 to 108; adopted rater 1 in 5 of 16 disagreements, rater 2 in 11 | `python -I research/paths-to-root/reconcile.py` output (2026-11-25); `reconciled-path-map.csv`. Counts are computed; the 16 adjudications are one non-blind judgement (E104) | VERIFIED (counts) |
| E103 | Reconciled path x attacker: P1 5 = untrusted-llm-input 5; P5 9 = remote-unauth 7, untrusted-llm-input 2; P2 17 = remote-authed-user 11, untrusted-llm-input 5, untrusted-data-store 1; P3 14 = untrusted-llm-input 12, remote-authed-user 1, malicious-web-content 1; P4 16 = untrusted-data-store 15, library-caller 1; P6 17 has 1 remote-authed-user row; remote-authed-user 27 rows = P2 11, none 7, P8 5, P7 2, P3 1, P6 1 | same command, "reconciled path x attacker" block | VERIFIED (counts) |
| E104 | The 16 adjudications, each with adopted label and one-line reason; 6 marked contested (53gh, 6wvf, c2jp, g3r5, hf3x, wrwr). Each was decided after re-reading the row's `description` and `notes` in `corpus/kbc/batches/*.jsonl` against `rater2/CODEBOOK.md` | `reconcile.py` `ADJUDICATED`/`CONTESTED`; `reconciled-path-map.csv` (basis column); paper Appendix A. A judgement by one adjudicator who saw both raters' labels | UNVERIFIED (judgement) |
| E105 | The KBC has a fifth batch, KBC-E (32 rows), built after the paths were written; the 121-row path maps do not include it, and it is used only for the out-of-sample check (E108) | `python -I paths-to-root/reconcile.py` on the full private corpus printed "corpus rows now 153; mapped snapshot 121; unmapped later rows 32" (2026-11-25). The published `kbc-snapshot/` holds the 121 rows only | VERIFIED |
| E106 | The 16 reconciled none rows: library-caller 6 (6qv9, 7p73, 9rwj, fxc2, gxmw, qh6h); authorization/data-scope 5 (3r68, fvww, jpw9, w66g, w66g-b); authed-user or operator-config injection 4 (7h8w, 53gh, 6wvf, gppg); prototype pollution 1 (wrwr) | `reconciled-path-map.csv`, rows with adopted = none, grouped by hand from each row's reason | VERIFIED (membership); grouping is a judgement |
| E107 | Proofs added after the 21-case score run, same 3-arm bar, not scored or counted: bench `langgraph-ghsa-mhr3` (GHSA-mhr3-j7m5-c7c9, Path 4) and `mcp-remote-ghsa-6xpm` (GHSA-6xpm-ggf7-wc3p / CVE-2025-6514, Path 7, Linux URL-scheme-handler route; the original public write-up's shell route is Windows), and CHAINLAB `langroid-neo4j-cypher-ghsa-2pq5-3q89-j7cc` (LLM-generated Cypher sink). G1 open item (b), whether tool-argument and SQL/Cypher sinks count like code exec, is resolved in the proposal on that case; item (a) stays open; it is not yet adopted in PitSense's production engine | `bench/results/langgraph-ghsa-mhr3.json`, `bench/results/mcp-remote-ghsa-6xpm.json`, `chainlab/results/langroid-neo4j-cypher-ghsa-2pq5-3q89-j7cc/proof_result.json` (all verdict PROVEN, 5/5, 0/5, 0/5); `bench/notes/batch-5.md` (path labels, Linux route, lines 27-38); `bench/cases/mcp-remote-ghsa-6xpm/case.json` title; `chainlab/`paths-to-root/PAPER.md` section 2.3 and line 250; `bench/scores/v0/SCORES.md` covers 21 cases only. Added by the fact-check (2026-11-25) | VERIFIED |
| E108 | Out-of-sample check on KBC-E, same method, definitions unchanged. 2 of the 32 rows excluded (two sinks of one advisory that the paper uses as a Path 1 worked example and reproduction; every KBC-E advisory id was matched against the drafts, outline, evidence map, bench cases and CHAINLAB proofs, no other hit), leaving 30. Rater 1 (frozen rule table, no new cells or overrides; no rule for 9 rows, 8 of them in class x attacker cells absent from the snapshot) 16 on a path; rater 2 (fresh blind LLM pass, same codebook) 27; reconciled 20/30 = 66.7%; both 16, either 27; 8 contested, contested range 19-26; 24 if the 4 shell/package-manager rows count as Path 1; raw agreement 18/30, kappa 0.486, same path 15/16 where both place one; reconciled per path P1 1, P2 3, P3 0, P4 1, P5 3, P6 1, P7 1, P8 10, none 10; the 10 none rows: 4 model-chosen argument into a shell/package-manager command (contested), 1 CLI option injection, 3 library-caller SSRF (2 contested), 1 library-caller option injection, 1 authed SQL injection; batch drawn by class keyword (14 of 30 SSRF) | `kbc-e-oos/RESULTS.md`; per-row map and script in PitSense's research repository (not published, because KBC-E is also a held-out engine-evaluation set) | VERIFIED (counts, by script, re-derived independently); the 12 adjudications are a judgement |

## Notes on the evidence

- The UNVERIFIED rows (E84, E92, E93, E104) are classification judgements, not fact lookups. E92 and E93 have a blind second rater (E101) and a reconciliation (E102 to E104); E84, the mapping of the 26 proofs, still has one rater.
- Severity labels in Appendix A are GitHub's. The paper does not rank paths by severity.
- Advisory summaries in Appendix A are quoted from the GitHub Advisory Database (CC-BY 4.0) for
  identity checking only.

## Appendix A. Advisory identity checks (gh API, 2026-11-25)

Every advisory id cited in the paper and its earlier outline. "live" = global advisory, `withdrawn_at` null. "published (repo
advisory)" = a repository security advisory in `modelcontextprotocol/servers` or
`modelcontextprotocol/inspector`, which has no global record.

| GHSA | CVE | severity | state | summary (first 90 chars, GitHub Advisory Database, CC-BY 4.0) | first patched |
|---|---|---|---|---|---|
| GHSA-2h4w-29cv-2cmv | CVE-2026-113663 | high | live | AG2: Newline injection in SandboxShellTool bypasses allowed=[...] and readonly=True, enabl | ag2@1.1.1;autogen@? |
| GHSA-2pc9-4j83-qjmr | CVE-2026-22807 | high | live | vLLM affected by RCE via auto_map dynamic module loading during model initialization | vllm@0.14.0 |
| GHSA-2qmj-7962-cjq8 | CVE-2023-36258 | critical | live | langchain arbitrary code execution vulnerability | langchain@0.0.247 |
| GHSA-2xv2-w8cq-5gxw | CVE-2026-61447 | critical | live | PraisonAI: CodeAgent Executes LLM-Generated Code Without Sandboxing and Leaks All Environm | praisonaiagents@1.6.78 |
| GHSA-33xw-247w-6hmc | CVE-2025-27520 | critical | live | BentoML Allows Remote Code Execution (RCE) via Insecure Deserialization | bentoml@1.4.3 |
| GHSA-3645-fxcv-hqr4 | CVE-2026-27966 | critical | live | Langflow has Remote Code Execution in CSV Agent | langflow@? |
| GHSA-3f6c-7fw2-ppm4 | CVE-2025-6242 | high | live | vLLM is vulnerable to Server-Side Request Forgery (SSRF) through `MediaConnector` class | vllm@0.11.0 |
| GHSA-46cm-pfwv-cgf8 | CVE-2024-2952 | critical | live | LiteLLM has Server-Side Template Injection vulnerability in /completions endpoint | litellm@1.34.42 |
| GHSA-4v28-j6q3-5m4r | CVE-2026-87996 | high | live | Open WebUI: SSRF into internal services via DNS rebinding in the Playwright web loader | open-webui@0.11.1 |
| GHSA-5cgr-j3jf-jw3v | CVE-2025-68143 | medium | live | mcp-server-git's unrestricted git_init tool allows repository creation at arbitrary filesy | mcp-server-git@2025.9.25 |
| GHSA-5r34-2g38-6569 | CVE-2026-55525 | high | live | praisonaiagents web_crawl vulnerable to SSRF via redirect-following | praisonaiagents@1.6.58 |
| GHSA-6529-c226-h328 | CVE-2026-77261 | high | live | MCP Atlassian: SSRF redirect protection missing for basic-auth and OAuth authentication br | mcp-atlassian@0.22.0 |
| GHSA-6g6r-q6gw-w8fg | CVE-2026-55536 | critical | live | PraisonAI has a Browser Server WebSocket origin validation bypass via unanchored regex (pa | PraisonAI@4.6.58 |
| GHSA-6hqx-gqrx-c5r2 | - | high | published (repo advisory) | mcp-server-git: arbitrary command execution via a repository's own Git configuration (core | - |
| GHSA-6qxp-vccf-f47h | CVE-2026-104850 | high | live | MCP TypeScript SDK: OAuth client could send credentials to an authorization server chosen  | @modelcontextprotocol/sdk@1.31.0;@modelcontextprotocol/client@2.2.0 |
| GHSA-6v92-r5mx-h5fx | CVE-2025-5120 | critical | live | smolagents has Sandbox Escape Vulnerability in the local_python_executor.py Module | smolagents@1.17.0 |
| GHSA-6vmq-24h2-pj7j | CVE-2026-77271 | high | live | MCP Atlassian: Incomplete path traversal fix allows intra-CWD module overwrite and RCE (by | mcp-atlassian@0.22.0 |
| GHSA-6xpm-ggf7-wc3p | CVE-2025-6514 | critical | live | mcp-remote exposed to OS command injection via untrusted MCP server connections | mcp-remote@0.1.16 |
| GHSA-7488-6r32-c95q | CVE-2026-59822 | high | live | LiteLLM: MCP Authentication Bypass via OAuth2 Passthrough Fallback | litellm@1.84.0 |
| GHSA-7972-pg2x-xr59 | CVE-2026-27893 | high | live | vLLM has Hardcoded Trust Override in Model Files Enables RCE Despite Explicit User Opt-Out | vllm@0.18.0 |
| GHSA-79j6-g2m3-jgfw | CVE-2025-9141 | high | live | vLLM has remote code execution vulnerability in the tool call parser for Qwen3-Coder | vllm@0.10.1.1 |
| GHSA-7f8r-222p-6f5g | CVE-2025-49596 | critical | live | MCP Inspector proxy server lacks authentication between the Inspector client and proxy | @modelcontextprotocol/inspector@0.14.1 |
| GHSA-7ww9-85pg-cv4x | CVE-2026-55534 | high | live | PraisonAI serve agents --api-key is ignored, allowing unauthenticated remote agent executi | PraisonAI@4.6.58 |
| GHSA-87qg-cmw8-jc5m | - | high | published (repo advisory) | mcp-server-git: a repository's promisor configuration runs a program during a lazy fetch | - |
| GHSA-8wv7-r664-7594 | - | high | published (repo advisory) | mcp-server-git: a submodule's own configuration still runs programs on `git_diff` (with `d | - |
| GHSA-8x5v-cpv7-8jjp | CVE-2026-70485 | high | live | Open WebUI: Any authenticated user can reach internal services and cloud metadata via NAT6 | open-webui@0.11.0 |
| GHSA-9h52-p55h-vw2f | CVE-2025-66416 | high | live | Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection by defaul | mcp@1.23.0 |
| GHSA-9pq8-m8gp-4p53 | CVE-2026-49444 | high | live | n8n: Python sandbox escape | n8n@1.123.48;n8n@2.22.4;n8n@2.21.8 |
| GHSA-9vjp-x34c-xg6v | - | high | published (repo advisory) | mcp-server-git: a config include created by the merged branch runs a command during git_me | - |
| GHSA-c2jp-c369-7pvx | - | high | live | FastMCP Auth Integration Allows for Confused Deputy Account Takeover | fastmcp@2.13.0 |
| GHSA-c67j-w6g6-q2cm | CVE-2025-68664 | critical | live | LangChain serialization injection vulnerability enables secret extraction in dumps/loads A | langchain-core@1.2.5;langchain-core@0.3.81 |
| GHSA-c6xh-wv4j-ppv5 | CVE-2026-69257 | high | live | Flowise: SSRF Protection Bypass via IPv4-Mapped IPv6 Addresses | flowise@3.1.3 |
| GHSA-cc5h-2pwp-pvcc | CVE-2026-77248 | high | live | MCP Atlassian: Unauthenticated arbitrary local file read via upload_attachment file_path,  | mcp-atlassian@0.22.0 |
| GHSA-cgcg-p68q-3w7v | CVE-2024-21513 | critical | live | langchain-experimental vulnerable to Arbitrary Code Execution | langchain-experimental@0.0.21 |
| GHSA-ch89-h4r2-c8f8 | CVE-2026-55540 | high | live | PraisonAI: [Path Traversal] agent tools escape the configured workspace via symlinks | PraisonAI@4.6.58 |
| GHSA-fprp-p869-w6q2 | CVE-2023-29374 | critical | live | LangChain vulnerable to code injection | langchain@? |
| GHSA-gf3v-fwqg-4vh7 | CVE-2026-26019 | medium | live | @langchain/community affected by SSRF Bypass in RecursiveUrlLoader via insufficient URL or | @langchain/community@1.1.14 |
| GHSA-gjjr-63x4-v8cq | CVE-2023-44467 | critical | live | langchain_experimental vulnerable to arbitrary code execution via PALChain in the python e | langchain-experimental@? |
| GHSA-h2g3-rwxm-xfm3 | - | high | published (repo advisory) | mcp-server-git 2026.11.11: git_merge runs gc.recentObjectsHook from the repository's own c | - |
| GHSA-hc55-p739-j48w | CVE-2025-53110 | high | live | @modelcontextprotocol/server-filesystem vulnerability allows for path validation bypass vi | @modelcontextprotocol/server-filesystem@?;@modelcontextprotocol/server-filesystem@2025.7.1 |
| GHSA-hj4w-hm2g-p6w5 | CVE-2025-32444 | critical | live | vLLM Vulnerable to Remote Code Execution via Mooncake Integration | vllm@0.8.5 |
| GHSA-hjq4-87xh-g4fv | CVE-2025-47277 | critical | live | vLLM Allows Remote Code Execution via PyNcclPipe Communication Service | vllm@0.8.5 |
| GHSA-hvj5-mvw9-93j3 | CVE-2024-2912 | critical | live | Insecure deserialization in BentoML | bentoml@1.2.5 |
| GHSA-jv9m-vf54-chjj | CVE-2025-61913 | critical | live | Flowise is vulnerable to arbitrary file write through its WriteFileTool  | flowise@3.0.8;flowise-components@3.0.8;Flowise@3.0.8 |
| GHSA-m4w4-3r8h-jw98 | CVE-2026-35002 | critical | live | Agno: Arbitrary code execution via `eval()` on `field_type` in `FunctionCall` | agno@2.3.24 |
| GHSA-mhr3-j7m5-c7c9 | CVE-2026-27794 | medium | live | LangGraph: BaseCache Deserialization of Untrusted Data may lead to Remote Code Execution  | langgraph-checkpoint@4.0.0 |
| GHSA-mphv-75cg-56wg | CVE-2026-27795 | medium | live | LangChain Community: redirect chaining can lead to SSRF bypass via RecursiveUrlLoader | @langchain/community@1.1.18 |
| GHSA-mrmq-3q62-6cc8 | CVE-2025-54381 | critical | live | BentoML SSRF Vulnerability in File Upload Processing   | bentoml@1.4.19 |
| GHSA-pm7p-vphh-2cg7 | - | high | published (repo advisory) | mcp-server-git: a repository's own config runs a command, because the hardening misses an  | - |
| GHSA-q74p-4wrc-q7w6 | - | medium | published (repo advisory) | mcp-server-git: Incomplete Fix for GHSA-w766-5x43-whvw in validate_opened_repo() Allows -- | - |
| GHSA-q978-78c7-phqw | - | high | published (repo advisory) | A remote MCP server can execute arbitrary code on the user's machine through the OAuth aut | - |
| GHSA-qh4c-xf7m-gxfc | CVE-2026-24779 | high | live | vLLM vulnerable to Server-Side Request Forgery (SSRF) through MediaConnector | vllm@0.14.1 |
| GHSA-qx49-fqc8-xw99 | CVE-2026-115563 | high | live | Model Context Protocol Python SDK: OAuth client could send credentials to an authorization | mcp@2.2.0;mcp@1.30.0 |
| GHSA-r399-636x-v7f6 | CVE-2025-68665 | high | live | LangChain serialization injection vulnerability enables secret extraction | @langchain/core@1.1.8;@langchain/core@0.3.80;langchain@1.2.3;langchain@0.3.37 |
| GHSA-rvq5-wwqv-78pq | CVE-2026-111771 | medium | live | MCP TypeScript SDK: Server bearer authentication accepted tokens issued for another servic | @modelcontextprotocol/sdk@1.32.0;@modelcontextprotocol/server@2.3.0;@modelcontextprotocol/express@2.0.2;@modelcontextprot |
| GHSA-rvqx-wpfh-mfx7 | CVE-2025-3248 | critical | live | Langflow Unauth RCE | langflow@1.3.0;langflow-base@0.3.0 |
| GHSA-rww4-4w9c-7733 | CVE-2026-27124 | high | live | FastMCP: Missing Consent Verification in OAuth Proxy Callback Facilitates Confused Deputy  | fastmcp@3.2.0 |
| GHSA-v798-mcc6-2m3m | CVE-2026-7873 | critical | live | Langflow: Code Injection Vulnerability in Code Validation Endpoint | langflow@1.10.1.rc0 |
| GHSA-vcc9-3xgm-p9v4 | - | high | published (repo advisory) | Incomplete fix for CVE-2025-49596: DNS-rebinding info disclosure (API token + stored OAuth | - |
| GHSA-vjqx-cfc4-9h6v | CVE-2026-27735 | medium | live | mcp-server-git : Path traversal in git_add allows staging files outside repository boundar | mcp-server-git@2026.1.14 |
| GHSA-w4fh-qvv9-3v23 | CVE-2026-116684 | medium | live | Model Context Protocol Python SDK: Server bearer-token authentication accepts tokens issue | mcp@2.2.0;mcp@1.30.0 |
| GHSA-w766-5x43-whvw | CVE-2026-134465 | medium | published (repo advisory) | mcp-server-git: nested gitdir file bypasses --repository confinement | - |
| GHSA-wmjf-2m46-2352 | - | high | published (repo advisory) | Missing Authentication for Critical Function in @modelcontextprotocol/inspector | - |
| GHSA-wvpx-g427-q9wc | CVE-2024-3098 | critical | live | llama-index-core Prompt Injection vulnerability leading to Arbitrary Code Execution | llama-index-core@0.10.24 |
| GHSA-x2rj-828p-hx9m | CVE-2026-61539 | critical | live | Xinference vulnerable to remote code execution via unsafe `eval()` in Llama3 tool-call par | xinference@2.7.0 |
| GHSA-x3m8-f7g5-qhm7 | CVE-2025-29783 | critical | live | vLLM Allows Remote Code Execution via Mooncake Integration | vllm@0.8.0 |
| GHSA-xc48-889x-5qmw | CVE-2026-69263 | high | live | Flowise: CVE-2025-8943 Patch Bypass: npm_config_yes bypasses MCP environment variable bloc | flowise@3.1.3;flowise-components@3.1.3 |
| GHSA-xjgw-4wvw-rgm4 | CVE-2026-27825 | critical | live | MCP Atlassian has an arbitrary file write leading to arbitrary code execution via unconstr | mcp-atlassian@0.17.0 |
| GHSA-6qv9-48xg-fc7f | CVE-2025-65106 | high | live | LangChain Vulnerable to Template Injection via Attribute Access in Prompt Templates | langchain-core@1.0.7;langchain-core@0.3.80 |
| GHSA-7p73-8jqx-23r8 | CVE-2025-64104 | high | live | LangGraph SQLite Checkpoint Filter Key SQL Injection POC for SqliteStore | langgraph-checkpoint-sqlite@2.0.11 |
