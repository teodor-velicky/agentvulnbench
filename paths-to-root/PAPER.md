# Paths to root for AI agents: eight recurring routes from untrusted input to host impact

PitSense, Teodor Velický. Version 1.0, evidence frozen 2026-11-25.
Canonical page: https://pitsense.io/research/paths-to-root/. Evidence, scripts and data:
[`paths-to-root/` in the AgentVulnBench repository](https://github.com/teodor-velicky/agentvulnbench/tree/main/paths-to-root/).

Every factual or numeric claim carries a tag `[E<n>]`. Each tag is a row in the evidence map,
[`EVIDENCE.md`](https://github.com/teodor-velicky/agentvulnbench/blob/main/paths-to-root/EVIDENCE.md), which names the file or command behind the claim and says whether it
was verified. The only sources are public, already-fixed advisories and PitSense reproductions of them.

---

## Abstract

Agent frameworks, MCP servers and SDKs, and model-serving stacks now draw a steady stream of security
advisories: 821 non-duplicate ones in their packages between June and November 2026 `[E10]`. We asked a narrow question of the public, already-fixed ones: is there
a small set of recurring routes from attacker-controlled input to host-level impact, does each route come
down to one missing guard, and are the fixes for that guard often incomplete?

Our material is a Known-Bug Corpus of 121 fixed advisories, each pinned to a vulnerable and a fixed
commit `[E1]`, and 26 hermetic three-arm reproductions (ATTACK 5/5, CONTROL 0/5, FIX 0/5) `[E3]` `[E4]`.
From it we name eight paths. For each we give the attacker position, the guard that was absent,
incomplete, ignored, misplaced or parsed differently from the executor, the sink, and worked advisories.
Two raters, one rule-based and one blind, then a reconciliation of their 16 disagreements, place 105 of
the 121 corpus rows on one of the eight paths. Flipping the six contested calls gives 102 to 108, and
the outer bounds are 101 (rows both raters place on a path) and 114 (rows either places) `[E102]`. The raters apply the path definitions consistently (Cohen's kappa 0.850;
97.0% same-path agreement when both name a path), but they separate "on a path" from "on no path" much
less reliably (kappa 0.463) `[E101]`. On 30 held-out rows that played no part in naming the paths, the same
method places 20 (66.7%) on a path, within a range of 16 to 27. Half of the rows on no path share one
shape the paths do not cover: a model-chosen tool argument that reaches a shell or CLI command line
(Section 2.8) `[E108]`. The eight paths also cover 24 of the 26 reproductions, a
single-rater figure `[E84]`. Seven of the eight paths have a documented public chain of later bypasses of
the first fix, six under a stricter reading of Path 7 (Section 4) `[E36]` `[E44]` `[E60]` `[E76]` `[E104]`.

Detection is the sobering part. On the 21 benchmark cases, <!-- tool-scores -->PitSense's static stub engine, Semgrep OSS
and Bandit together locate one bug in their top ten findings<!-- /tool-scores -->, and a deliberately naive LLM-free ranker
locates another `[E86]`. The misses fall into two groups: the sink is found but ranked too low or
discarded by triage, or there is no dangerous call to match at all `[E88]` `[E38]`. For the
model-mediated paths we use a scripted model, a deterministic fake LLM inside the framework's own LLM
interface, to show that the framework rather than the model is at fault `[E6]`.

---

## 1. Why paths, and why now

Security writing about AI agents tends to sit at one of two altitudes. One is the model: jailbreaks,
prompt injection success rates, how often a model can be talked into something. The other is the
individual bug: one advisory, one CVE, one patch. Between them there is a gap that matters to the people
who write frameworks and to the people who hunt bugs in them. A framework author wants to know which
guard they are most likely to be missing. A hunter wants to know where the next bug of a known shape is
hiding. Neither question is answered by a model benchmark or by a single advisory.

A *path* is our name for the middle altitude. It is a route that recurs across unrelated codebases: an
attacker position, an entry point, one guard that should stand between them and a dangerous sink, the
sink itself, and the impact. "Root" is shorthand for host-level impact: code execution as the agent or
server process, file write outside the granted root, secrets read from the process environment, or
requests into the internal network.

Two things make the path view useful for agent code specifically. First, much of the attacker's input
arrives *through the model*. A web page, document, tool result or chat message steers the model, and
the framework routes the model's output to an interpreter, a file tool or a query. Prior work often
treats this as a model-safety question. We treat it as a framework question, and we prove it that way
(Section 2.3). Second, agent and MCP code is young and copy-pasted. The same guard is hand-written many
times, and the same mistake recurs, which is exactly what a path captures.

## 2. Method

### 2.1 The Known-Bug Corpus

The Known-Bug Corpus (KBC) holds 121 rows in four batches, all positives. Every row pins a vulnerable
SHA and a fix SHA, a vulnerability class, a file and line locator, and a label for the attacker's
position `[E1]`. The attacker labels split as follows: untrusted-llm-input 29, remote-authed-user 27,
remote-unauth 23, untrusted-data-store 17, malicious-web-content 9, malicious-mcp-server 9,
library-caller 7 `[E2]`. A validator checks every row against the GitHub API and the fix diff; it passes
on all 121 rows after a one-row correction (Section 9) `[E95]`. The corpus has since grown by a fifth,
blind held-out batch of 32 rows (KBC-E). Every count in this paper uses the 121-row snapshot, except
Section 2.8, which uses 30 of the 32 held-out rows as an out-of-sample test of the paths `[E105]` `[E108]`.

### 2.2 Three-arm proofs

A claim in this paper is "proven" only when a hermetic reproduction passes three arms. ATTACK runs the
attacker's input against the vulnerable version and must hit a per-trial canary 5 times out of 5.
CONTROL runs a benign input that exercises the same feature on the vulnerable version and must hit 0 of
5. FIX runs the attacker's input against the fixed version and must hit 0 of 5. Two sets of proofs meet
this bar: 21 AgentVulnBench cases `[E3]` and 5 CHAINLAB cases `[E4]`. CHAINLAB runs every arm with
`--network none`, so nothing reaches outside the container `[E5]`. The five CHAINLAB cases are not rows
of the 121-row KBC snapshot; they were reproduced separately from released package versions `[E97]`.

These 26 are the proofs that existed when the 21-case score run and the path mapping were made, and
every count in this paper uses them. Three more have since passed the same bar and are not yet scored
or folded into the counts: LangGraph's pickle-fallback cache (GHSA-mhr3-j7m5-c7c9, Path 4) and
mcp-remote's authorization-URL bug (GHSA-6xpm-ggf7-wc3p, CVE-2025-6514, Path 7, reproduced on Linux
through the URL-scheme handler) in AgentVulnBench, and Langroid's model-generated Cypher query
(GHSA-2pq5-3q89-j7cc) in CHAINLAB `[E107]`.

### 2.3 The scripted model and the G1 rule

Model-mediated bugs invite an objection: "a real model would never emit that." We remove the question.
For each model-mediated case, CHAINLAB plugs a deterministic fake LLM into the framework's own LLM
interface. It ignores the prompt and returns the attacker-chosen output word for word. If the framework
then reaches the sink, the framework lacks a guard, whatever any real model would do `[E6]`.

The scripted model is allowed one assumption: that some untrusted content could make a real model emit
output of the shape the feature is built to receive, such as a code block from a math chain or a tool
call from a tool-calling agent. It may not assume an attacker-controlled config, plugin, environment or
file on disk, a second bug, or an operator deliberately asking for the dangerous action `[E100]`. The
CONTROL arm carries the weight here: it must be a benign output of the same shape through the same
feature, so a positive result cannot just be the feature working as designed `[E99]`.

From this we propose a gate rule for triage, which PitSense calls G1: *a model-mediated path is
attacker-reachable when the framework routes model output to a dangerous sink with no guard that limits
it to the intended safe shape* `[E7]`. The finding is the missing guard, not the model's behaviour.

### 2.4 Detection measurement

We score tools on AgentVulnBench's locate stage. A case counts as located when one of the tool's first
ten findings is in the right file, within 25 lines of the key line, with a compatible class `[E8]`. All
21 cases have now been scored by five rows: PitSense with its deterministic stub backend (no LLM),
<!-- tool-scores -->Semgrep OSS 1.184.0 with the registry packs p/python, p/javascript and p/security-audit, Bandit 1.9.4
(`bandit -r . -f json -q`; Python only), <!-- /tool-scores -->an LLM-free ranking baseline called rankbase, and PitSense's
surface map before triage as a diagnostic `[E86]`. rankbase ranks candidate sinks by danger times a
crude entry-reachability proxy; its weights were written before any case's answer key was read and were
never tuned `[E98]`. An earlier run on the first 14 cases is kept as a dated footnote `[E96]`.

We also measured the PitSense engine on the whole KBC (Section 6.2), which tests the surface map and the
triage gates rather than ranking `[E89]`.

### 2.5 The advisory stream

For context on volume we use a snapshot of GitHub advisories in agent, MCP and serving packages: 821
non-duplicate advisories from 2026-06-01 to 2026-11-24. An independent label audit found that the
snapshot's class labels are not exact, so we quote only the audit's corrected figures `[E10]`.

### 2.6 Mapping rows to paths

Every KBC row was labelled twice. Rater 1 is a script that applies a default per (class, attacker) cell,
then 16 per-row overrides, each with a written reason, plus 3 per-row exclusions `[E92]`. Rater 2 is a
separate LLM pass that was given only a codebook condensed from the path definitions and a blinded copy
of the rows: no path column, no rater-1 reasons, rows sorted by id so batch order is hidden. The
restriction to those two files was by instruction, not a technical sandbox `[E101]`. Where the
two agree, we take the shared label. Where they disagree, a third pass, which saw both labels and so is
not blind, re-read each row's description and notes against the codebook and adopted one label with a
one-line reason (Appendix A) `[E104]`. All per-path counts in this paper are from the reconciled map
`[E102]` `[E103]`. The earlier mapping of the 26 proofs `[E84]` has not had a second rater and remains
one author's judgement.

### 2.7 Reliability of the path labelling

The question a reader should ask of any taxonomy is whether someone else, given the same definitions,
would sort the same bugs the same way. We measured that, and the answer has two parts.

| Measure (121 rows) | Value |
|---|---|
| Raw agreement, 9 labels (P1 to P8, none) | 105/121 = 86.8% |
| Cohen's kappa, 9 labels | **0.850** (chance agreement 0.120) |
| Same path, on the 101 rows both raters place on a path | 98/101 = **97.0%** |
| Agreement, collapsed to path vs none | 89.3% |
| Cohen's kappa, collapsed to path vs none | **0.463** |
| Rows on a path: rater 1 / rater 2 / reconciled | 111 / 104 / 105 |

Source: `[E101]` (`python -I paths-to-root/rater2/kappa.py`) and `[E102]`
(`python -I paths-to-root/reconcile.py`).

**The paths are well defined.** Once both raters decide a bug is on some path, they pick the same one 97
times in 100. Paths 1, 5 and 8 drew full agreement. Only three rows split between two paths, and each
sits on a boundary we can name: a gate applied to the wrong string inside a loaded expression (Path 4 or
2), an MCP server's OAuth redirect that reaches a stdio spawn (Path 6 or 7), and an authenticated user
whose code passes a "validator" that executes it (Path 6 or 2) `[E101]`.

**The edge of the taxonomy is not.** Whether a bug is on a path at all is where the raters part. Rater 2
sent to "none" ten rows that rater 1 had placed on a path, and rater 1 had sent to "none" three rows
that rater 2 placed on Path 4; they agreed on "none" for only 7 rows. On that binary question kappa is
0.463, conventionally "moderate" `[E101]`. Half of rater 2's ten have one cause. Rater 1 assigned rows by a default for
their (class, attacker) cell, and that default stretched Paths 3 and 6 over authorization bugs that have
no host impact: a tool filter applied when listing tools but not when calling them, an auth decorator
registered for every action, a session served to the wrong user, and a Jira or Confluence query filter a
caller can override `[E104]`. These are real, fixed, agent-specific bugs. They are not routes to root,
and we place them outside the eight paths.

**What we claim and what we do not.** We claim that the eight definitions can be applied reproducibly to
a bug once it is agreed to be a host-impact path. We do not claim a sharp coverage figure: 105 of 121 is
our reconciled answer, but six of the sixteen adjudications are judgement calls we mark as contested.
Flipping all six in either direction gives 102 to 108, and the outer bounds are 101 (on a path for both
raters) and 114 (for either) `[E102]`. Three further limits apply `[E101]`. Rater 2 saw the same
`class` and `attacker` fields that rater 1's script keys on, so the two are not fully independent;
rater 1's per-row overrides were also written by someone who had read the rows. Rater 2 is one LLM pass, not an
independent human. And because the codebook is condensed from our own path definitions, agreement shows
the definitions are usable, not that eight is the right partition.

### 2.8 Out-of-sample check on 30 held-out rows

The paths were named from the same 121 rows they are scored on, so 105 of 121 measures fit, not
prediction. To test prediction we took KBC-E, a batch of 32 fixed advisories built after the paths were
written, and applied the identical three-step method with the path definitions unchanged. Two of its
rows are sinks of one advisory that this paper already uses as a Path 1 worked example, so we excluded
them, leaving 30. Rater 1 was the frozen rule table, with no new cells and no new overrides. It has no
rule for 9 of the 30 rows, 8 of them in class and attacker combinations that never occur in the
snapshot. Rater 2 was a fresh blind LLM pass with the same codebook. A non-blind third pass settled their
12 disagreements and marked 8 of them contested `[E108]`.

**20 of 30 held-out rows (66.7%) fall on a path**, against 105 of 121 (86.8%) in sample. With the two
excluded rows, both on Path 1, it would be 22 of all 32 KBC-E rows; we report 20 of 30. Both raters
place 16 rows on a path and either rater places 27; flipping the contested calls gives 19 to 26. Where
both raters place a row on a path, they choose the same one for 15 of 16, close to the in-sample 98 of
101 `[E108]`. The reconciled per-path counts are P1 1, P2 3, P3 0, P4 1, P5 3, P6 1, P7 1 and P8 10.
They mostly reflect how the batch was drawn: from advisories with command-injection, SSRF,
code-execution and deserialization keywords. The test therefore says little about Paths 3, 6 and 7
`[E108]`.

Half of the ten rows on no path share one shape the eight paths do not have: a model-chosen tool
argument spliced into a shell or CLI command line. In four of the five, it reaches a shell or a
package-manager command. In the fifth, a leading `-` turns it into an option flag. The shape does not
occur in the 121-row snapshot. Path 1 as written stops at Python interpreters, Path 2 needs a gate, and
Path 3 is about file confinement. Under a broad reading of "interpreter", Path 1 would take the four
shell and package-manager rows, and coverage would be 24 of 30. We did not widen any definition to
absorb them. We report the shape as the first candidate for a ninth path or a wider Path 1. The other
five rows on no path have attacker positions that also fall outside the paths in sample: three
`library-caller` SSRF rows (two contested), one `library-caller` option injection and one authenticated
SQL injection `[E108]`. Aggregate results are in [`kbc-e-oos/RESULTS.md`](https://github.com/teodor-velicky/agentvulnbench/blob/main/paths-to-root/kbc-e-oos/RESULTS.md). The
KBC-E rows themselves stay unpublished, because they are also a held-out set for engine evaluation.

## 3. Five guard shapes

The eight paths differ in attacker and sink, but the guard failures repeat. We use five shapes
throughout.

| Shape | Meaning | Example |
|---|---|---|
| **absent** | Nothing stands between the input and the sink | PALChain sends the program to `PythonREPL().run()` `[E11]` |
| **incomplete** | A denylist or check misses one form of the input | `__import__` missing from the PAL denylist `[E12]` |
| **ignored** | The guard is configured but never wired to the sink | `CodeConfig(sandbox=True)` ignored `[E13]` |
| **differential** | The gate parses the input differently from the executor | n8n's format-string scan vs the real `str.format` `[E14]` |
| **misplaced** | The guard sits on one branch, direction or default only | SSRF hook attached only in the PAT auth branch `[E15]` |

"Ignored" deserves a note. It is the shape most easily missed in review, because the code *looks*
hardened: there is a sandbox flag or an API-key option, and documentation that describes it. We see it
in Path 1 (PraisonAI CodeAgent) and Path 6 (PraisonAI `serve --api-key`) `[E13]` `[E58]`.

---

## Path 1. Model output into an interpreter

**Attacker.** Someone who controls content the agent reads: a document, web page, tool result or
message. They never type into the application. **Entry.** A completion or tool-call string produced by
the model. **Missing guard.** A parser that limits model output to the feature's safe shape; absent or
ignored. **Sink.** `exec`, `eval`, or a subprocess running Python. **Impact.** Code execution as the
agent or server process, with its environment and credentials.

This is the oldest and simplest agent path, and it is still being shipped. LangChain's `LLMMathChain`
asked the model for a math expression and, when the reply started with a Python code fence, ran it
through `PythonREPL().run()`; the bug is CVE-2023-29374, fixed between langchain 0.0.131 and 0.0.142
`[E16]`. `PALChain` did the same with a whole generated program and no guard at all (CVE-2023-36258,
fixed in 0.0.247) `[E11]`. Both are proven in CHAINLAB. In the LLMMathChain proof the scripted model
returns a code block that writes the nonce to a canary file; the CONTROL arm returns `print(2+2)`
through the same path and writes nothing; the fixed release deletes the Python branch, so the same
block raises an error `[E16]`.

The path is not a 2023 artefact. In 2026, Xinference's Llama3 tool-call parser, in the *serving* layer
rather than an agent framework, ran `eval(model_output, {}, {})` on the model's completion
(CVE-2026-61539, fixed in 2.7.0, which parses with `json.loads` and then `ast.literal_eval`) `[E17]`.
PraisonAI's CodeAgent ran model-written Python with `subprocess.run` and a full copy of the process
environment, even when the operator had set `CodeConfig(sandbox=True)` (CVE-2026-61447, fixed in
praisonaiagents 1.6.78) `[E13]`. Both are CHAINLAB-proven. agno `eval()`ed the `field_type` string of a
model-emitted `get_user_input` tool call (CVE-2026-35002), proven in AgentVulnBench `[E18]`.

The corpus holds more rows of the same shape without a reproduction yet: vLLM's Qwen3-Coder tool parser
converted parameters of unknown type with `eval()` (CVE-2025-9141) `[E19]`; Langflow's CSV Agent
hard-coded `allow_dangerous_code=True` (CVE-2026-27966) `[E20]`; and LangChain's
`VectorSQLDatabaseChain` `eval()`ed every value returned by the model-generated SQL (CVE-2024-21513)
`[E21]`.

**How fixes went wrong.** When a vendor responds by adding a filter instead of removing the `exec`, the
bug moves to Path 2: PALChain's CVE-2023-36258 was followed by CVE-2023-44467, a bypass of the new
denylist `[E12]`. PraisonAI adds a third shape, a safe setting that is accepted and silently not applied
`[E13]`.

**What detection saw.** <!-- tool-scores -->Pattern tools do find these sinks; they rank them too low.<!-- /tool-scores --> On agno, <!-- tool-scores -->Semgrep's
`eval-detected`, Bandit's B307 and <!-- /tool-scores -->PitSense's surface map <!-- tool-scores -->all <!-- /tool-scores -->flagged the key line, at <!-- tool-scores -->ranks 109, 72 and
<!-- /tool-scores -->rank 32 `[E22]`. In the 14-case run, PitSense's stub triage then rejected the agno sink at its G1 outsider
gate `[E23]`. Across all 21 cases, the nine `untrusted-llm-input` cases score 0 of 9 for PitSense<!-- tool-scores -->,
Semgrep and Bandit<!-- /tool-scores -->; only rankbase gets one, by putting the llama-index `eval` at rank 2 `[E88]` `[E86]`.
In the reconciled KBC row map, Path 1 holds 5 rows, with both raters agreeing on all five `[E102]`, but the class it represents is larger than that count
suggests: the strict model-mediated share of the 2026 advisory stream is at least 25 of 821 `[E81]`.

**Guard checklist for framework authors.** Never route model output to `exec` or `eval`; parse it
with a grammar for the safe shape (a JSON schema, `ast.literal_eval`, a numeric-expression evaluator).
If code execution is the feature, make it a separate, explicit, off-by-default capability, and test that
every "safe mode" flag is actually read by the code path that executes.

## Path 2. The hand-rolled gate parses differently from the executor

**Attacker.** Usually model-mediated: the agent's code or shell tool. Often an authenticated,
low-privilege user who writes a flow, an expression or a config (n8n, Flowise). **Entry.** Code, a
shell command, or an environment map that passes through a framework-written filter. **Missing guard.**
A gate that agrees with the executor. The gate is a denylist, regex, AST check or prefix allowlist that
reads the input differently from the real interpreter, shell or package manager; incomplete or
differential. **Sink.** The real executor: Python `exec`, `sh -c`, `npm`/`npx`, `str.format`.
**Impact.** Sandbox escape to code execution on the host.

Path 2 is what Path 1 becomes after a partial fix. The framework keeps the interpreter and puts a
hand-written gate in front of it. The gate then has to model the executor's grammar exactly, and it
rarely does. smolagents' `LocalPythonExecutor` allowed a forbidden submodule to be reached through
indirect `getattr` on an allowed module (CVE-2025-5120) `[E24]`. llama-index's `safe_exec` built
restricted globals for `PandasQueryEngine` but still exposed the real builtins (CVE-2024-3098) `[E25]`.
AG2's `SandboxShellTool` checked commands against an operator denylist that omitted the newline, so
`ls` followed by a newline and a second command passed `readonly=True`, and `sh -c` ran line two
(CVE-2026-113663) `[E26]`. langchain-experimental's PAL `validate_code` omitted `__import__` from its
list of blocked calls (CVE-2023-44467, fixed in 0.0.24) `[E12]`. All four are proven.

Two more were reproduced at the gate level by GATEDIFF, PitSense's differential battery that feeds the same
inputs to the gate and the real executor and records disagreements. n8n's Python sandbox scanned literal
format strings with a regex and an AST check, while the runtime `str.format` accepts forms the scan
never sees (GHSA-9pq8-m8gp-4p53, CVE-2026-49444) `[E14]`. Flowise's MCP environment denylist missed
`npm_config_*` variables, which real npm reads, a bypass of the CVE-2025-8943 patch (CVE-2026-69263)
`[E27]`.

**How fixes went wrong.** This is the strongest chain shape in the corpus. In GATEDIFF's n8n run, the
vulnerable gate disagreed with the executor on 5 variants, the fix commit still let 4 through, and a
later release closed them `[E14]`. The corpus records further chains on the same sandboxes: Flowise's
CSV Agent and Pyodide, Flowise's NodeVM, and n8n's expression sandbox `[E28]`. Across the five public
gates GATEDIFF fuzzed, it reached a real gate/executor disagreement on four `[E29]`.

Two rows joined Path 2 in reconciliation. AG2's `ContextExpression` ran its AST allow-list on the
expression template, then substituted variable values with a raw f-string and `eval()`ed the result, so
a quote in a value escaped the checked shape (GHSA-35w5-fv47-8956) `[E104]`. And Langflow's
`validate_code`, after its first fix added authentication, still `exec()`ed the definitions it was
asked to validate (GHSA-v798-mcc6-2m3m, CVE-2026-7873) `[E59]` `[E104]`: a "gate" that is itself the
executor. One row left: n8n's XML node validated a string-coerced copy of an option but passed the
original value on (GHSA-wrwr-h859-xh2r). Its guard is a textbook differential, but the row documents
prototype pollution and no executor sink, so we no longer count it as a route to root `[E104]`.

**Who the attacker is.** Of the 17 reconciled KBC rows on Path 2, 11 carry the `remote-authed-user`
label `[E103]`. That is the attacker position the original thesis left out: a logged-in user with low
privileges who can write a workflow and get host code execution through the sandbox.

**What detection saw.** On llama-index, <!-- tool-scores -->Semgrep, Bandit and <!-- /tool-scores -->PitSense's surface map <!-- tool-scores -->all flag<!-- /tool-scores --> the `eval`
call in `exec_utils.py`, 12 lines above the `safe_exec` key line<!-- tool-scores -->, with Bandit closest at rank 12<!-- /tool-scores -->
`[E22]`; rankbase ranks it 2 `[E86]`. No tool reports the hole in the gate
itself, and the AG2 and smolagents cases are missed by every tool `[E87]`. None of our VARIANT Semgrep rules
expresses a shell-flag parser differential `[E30]`. A differential battery, gate against real executor, is the
method that finds these; sink rules are not.

**Guard checklist.** Do not write a denylist for a language you do not control. If a gate is
unavoidable, test it differentially against the real executor on every release, include newline, CR,
encoding and indirect-attribute variants, and treat the interpreter as untrusted anyway (a process or
container boundary, no inherited environment).

## Path 3. A model-chosen tool argument escapes file or repository confinement

**Attacker.** A prompt-injected model picks the arguments of a file or repository tool; the MCP host
forwards the call as is. **Entry.** A `path`, `file_path` or `repo_path` argument. **Missing guard.**
Containment against the granted root: absent, a bare prefix match, `abspath` where `realpath` is
needed, or a check in one direction only. **Sink.** Filesystem read or write, or a `git` operation,
outside the root. **Impact.** Arbitrary file write and from there code execution, or file and secret
read.

MCP made this path common, because the reference servers expose filesystem and git tools to whatever
model is driving them. The official filesystem server checked allowed directories with a bare
`startsWith()`, so `/allowed_evil` passed for `/allowed` (GHSA-hc55-p739-j48w, CVE-2025-53110)
`[E31]`. The official git server's `git_init` created repositories at any path, ignoring its
`--repository` confinement (CVE-2025-68143) `[E32]`, and its `git_add` staged `../` paths outside the
repository (CVE-2026-27735) `[E33]`. All three are proven. Beyond MCP, Flowise's WriteFile tool wrote
wherever the model said (CVE-2025-61913) `[E34]`, and PraisonAI's workspace check used `abspath`
instead of `realpath`, so a symlink inside the workspace escaped it (CVE-2026-55540) `[E35]`.

Path 3 holds 14 reconciled KBC rows, 12 of them labelled `untrusted-llm-input`: still the most
model-mediated path in the corpus by row count `[E103]`. The rule-based rater alone counted 16; the second rater removed
mcp-atlassian's Jira and Confluence query filters (GHSA-w66g-j6c4-hcfc), which a caller could override
by naming a forbidden project or space in its own query. That is confinement of data scope, not of a
filesystem root, and the impact is reading excluded records, not host impact; we leave it off the
path `[E104]`. Two rows stay on Path 3 against the second rater, and they widen its attacker: AG2's
skill installer joined tar member names onto its staging directory unchecked (GHSA-hf3x-42qp-4rq6),
and n8n's Git node checked a clone target and cloned into it later, so a symlink swapped in between
planted code in the community-nodes directory (GHSA-g3r5-9h93-4j2c). Entry, guard, sink and impact are
Path 3's; the attacker is an archive author or a logged-in workflow author rather than a model. We mark
both as contested `[E104]`.

**How fixes went wrong.** The git server's fix for a nested-gitdir escape, GHSA-w766-5x43-whvw
(CVE-2026-134465), was followed by GHSA-q74p-4wrc-q7w6, titled "Incomplete Fix for GHSA-w766" `[E36]`.
mcp-atlassian's path traversal fix GHSA-xjgw-4wvw-rgm4 (CVE-2026-27825) was followed by
GHSA-6vmq-24h2-pj7j: the new download guard defaulted its base directory to the current working
directory, which still allowed a module overwrite and code execution, and the upload/read twin was left
unguarded `[E37]`.

**What detection saw.** All three proven MCP path cases are missed by every tool. None has a dangerous
call at the key line, so pattern rules have nothing to match `[E38]`. The KBC engine run tells the same
story at corpus scale: 1 of 13 evaluable path-traversal rows surfaced `[E89]`. Containment bugs are
logic bugs; they need a semantic or dynamic check, such as a tool-argument fuzzer run against the
granted root.

**Guard checklist.** Resolve the real path (`realpath`, after symlinks) and compare path *components*
against the resolved root, never string prefixes. Apply the same check to every tool that takes a path,
including upload and read twins, and to every path a tool derives (a nested gitdir, an archive member).

## Path 4. A repository or artefact at rest is trusted as code

**Attacker.** Whoever authored a repository, model repository, dataset shard, checkpoint store or
prompt template that the agent or server later opens; mostly the `untrusted-data-store` label, which
covers 15 of Path 4's 16 reconciled rows `[E103]`. **Entry.** `.git/config`, a model's `auto_map` or config, a pickled cache entry, a Jinja chat
template. **Missing guard.** The loader treats the artefact's own configuration as trusted: no
`trust_remote_code` check, no config hardening, pickle as the default. **Sink.** `git` running a
configured program, a dynamic module import, `pickle.load` or `torch.load`, unsandboxed Jinja.
**Impact.** Code execution as the server user, often during an operation the user believes is
read-only.

The mcp-server-git case shows how quietly this path triggers. A repository's own `core.fsmonitor`
setting names a program, and git runs it on the first `git_status` call; the server opened
repositories with their config fully trusted (GHSA-6hqx-gqrx-c5r2, proven) `[E39]`. On the serving
side, vLLM loaded `auto_map` dynamic modules without honouring `trust_remote_code` (CVE-2026-22807), and
its NemotronVL path hard-coded `trust_remote_code=True` despite the user's opt-out (CVE-2026-27893)
`[E41]`. LiteLLM rendered a model's Hub `chat_template` in a non-sandboxed Jinja2 environment
(CVE-2024-2952) `[E42]`, and LangGraph's `BaseCache` defaulted to a serializer with `pickle_fallback=True`,
so cache entries were unpickled on read (CVE-2026-27794) `[E43]`.

**How fixes went wrong.** This path has the longest single chain we found. mcp-server-git has six
repository-config execution advisories (6hqx, pm7p, 87qg, h2g3, 9vjp, 8wv7), and each hardening left
the next config-driven sink in place `[E44]`; the last, GHSA-8wv7, is a submodule's own config still
running programs on `git_diff` after the top-level hardening `[E40]`. vLLM had three separate code paths
that loaded remote code despite `trust_remote_code=False` `[E45]`.

Path 4 has 16 reconciled KBC rows, one fewer than Paths 2 and 6 `[E102]`. Reconciliation moved three
rows. It added PraisonAI's workflow `include`, which `exec_module()`d a recipe directory's `tools.py`
without the opt-in that guarded the other autoload paths (GHSA-hxmv-c4g6-5fqc), a misplaced guard on a
third-party artefact. It removed LiteLLM's `get_secret`, which `eval()`ed a decrypted secret
(GHSA-gppg-gqw8-wh9g), because the attacker must already control the proxy's own secrets, and AG2's
`ContextExpression`, which is a gate differential and went to Path 2 `[E104]`. The second rater would
also have put two LiteLLM rows here: a proxy config that names a module to import (GHSA-53gh-p8jc-7rg8)
and a dotprompt template rendered unsandboxed at `/prompts/test` (GHSA-6wvf-77m9-58rm). We keep both
off the path, because the attacker writes the server's own config or sends the template in the request
rather than leaving an artefact for the server to open. Both are contested; on a broader reading of
"artefact", Path 4 has 18 rows `[E104]`.

**What detection saw.** Here sink-plus-guard rules work. VARIANT, PitSense's rule-writing method, turned the
first vLLM fix into rules that flagged both later `trust_remote_code` bypasses, and the rules already
alarmed at the first fix's SHA `[E46]`. The one proven case among the 21 scored, mcp-server-git-6hqx, is
missed by every tool `[E87]`; the later LangGraph proof (Section 2.2) is not yet scored `[E107]`.

**Guard checklist.** Treat every artefact the user did not author as data. Run git with a hardened
config (no hooks, no fsmonitor, no drivers, no lazy fetch, applied to submodules too), honour
`trust_remote_code` on every load path, use safe loaders (`weights_only`, JSON, safetensors) by default,
and render third-party templates only in a sandboxed environment.

## Path 5. A serialized object crosses a trust boundary

**Attacker.** Mainly a network peer that can reach a serving data-plane or API port. A second variant
is model output that carries a serializer marker. **Entry.** Bytes on a KV-transfer, ZMQ or HTTP
socket, a client-chosen media type, or an `lc` dictionary in model-produced message fields. **Missing
guard.** Authentication on the channel and a binding no wider than intended, before any object is
deserialized; or escaping of user-controlled serializer markers. **Sink.** `pickle.loads`,
`recv_pyobj`, `torch.load`, or a reviver that reads `os.environ`. **Impact.** Remote code execution on
serving nodes, or theft of environment secrets.

Distributed inference moves tensors between processes, and the convenient way to move Python objects
is pickle. vLLM's `PyNcclPipe` started a TCPStore listening on all interfaces, and rank 0 unpickled an
object from any peer that connected (CVE-2025-47277, proven) `[E47]`. A detail from the proof matters
for anyone reproducing such fixes: the vLLM fix binds to loopback, so the FIX arm has to fail on a plain
TCP connect, with `ConnectionRefusedError`, rather than on a crash; that makes the block attributable to
the fix `[E53]`. BentoML picked the request deserializer from the client's media type, including
pickle (CVE-2024-2912, proven) `[E49]`.

The second variant needs no open port. langchain-core's `dumps()` did not escape user dictionaries
with `lc` keys, so model-influenced fields round-tripped through `loads()` as a secret reference, and
the reviver printed an environment secret (CVE-2025-68664); LangChain.js had the same bug in `load()`,
reading `process.env` (CVE-2025-68665) `[E50]`. Both are proven.

**How fixes went wrong.** In both Mooncake and BentoML, the pickle came back. vLLM's first Mooncake fix
(CVE-2025-29783) removed the tensor pickle but left `recv_pyobj` on a `tcp://*` socket, fixed later as
CVE-2025-32444 `[E48]`. BentoML's media-type pickle returned in the rewritten server as CVE-2025-27520
`[E49]`. VARIANT rules re-flagged both later bypasses; the BentoML one raised no alarm at the first
fix's SHA, because it was a later regression rather than a leftover `[E51]`.

**What detection saw.** bentoml-hvj5, langchain-core-c67j and langchainjs-r399 were missed by every
tool `[E52]`, and so was the network-peer case vllm-hjq4 in the 21-case run `[E87]`. In the KBC engine
run, 4 of 14 evaluable unsafe-deserialization rows surfaced and none passed triage `[E89]`.

**Guard checklist.** Do not deserialize objects from a socket; send typed data. Bind data-plane
sockets to the interfaces the deployment needs, authenticate peers, and never let the client choose the
deserializer. If a serializer has a "revive" marker, escape user data on the way in and refuse secret
references on the way out unless explicitly allowed.

## Path 6. The control plane trusts its network position

**Attacker.** An outsider who can reach the port; for loopback-bound developer tools, a web page the
developer visits, using a cross-origin request or DNS rebinding. **Entry.** An HTTP or WebSocket
request to an agent server, an MCP transport or a gateway. **Missing guard.** Authentication, or
Origin and Host binding: absent, off by default, fail-open, configured but not enforced, or an
unanchored or prefix Origin match. **Sink.** Whatever the control plane exposes: code validation, flow
builds, stdio command spawn, MCP tool calls. **Impact.** Unauthenticated remote code or tool execution.

Agent tools ship servers: a flow builder, an inspector, a local MCP transport, a proxy. Many of them
assumed that being on localhost, or behind a key option, meant being safe. Langflow's
`/api/v1/validate/code` had no authentication and `exec()`ed the function definitions it was asked to
validate (CVE-2025-3248) `[E54]`. The MCP Inspector's proxy spawned the `command` and `args` from the
query string of `/stdio` with no authentication or Origin check (CVE-2025-49596) `[E55]`. The MCP
Python SDK's FastMCP shipped DNS-rebinding protection off by default for localhost HTTP servers
(CVE-2025-66416) `[E56]`. LiteLLM's MCP gateway fell back to an anonymous "OAuth2 passthrough" session
when the key check failed (CVE-2026-59822) `[E57]`. All four are proven. PraisonAI stored the
`serve --api-key` value and never installed middleware to enforce it (CVE-2026-55534), and checked
Browser Server WebSocket Origins with an unanchored `re.match` (CVE-2026-55536) `[E58]`.

PitSense's inbound battery re-ran public DNS-rebinding advisories as real servers on loopback, each
sent ten Host/Origin probes, eight of them attacker-shaped. At the vulnerable commits, FastMCP (9h52)
and the Inspector web server (vcc9) each accepted 8 of 8 attacker probes. At the fix commits, 9h52 accepted 0 of 8 and vcc9 accepted 0 of its 5 Host-based probes
`[E94]`.

**How fixes went wrong.** Langflow's first fix added authentication only; CVE-2026-7873 later showed
that `validate_code` still `exec()`s for any authenticated user `[E59]`. With authentication in place
the remaining bug is no longer Path 6's, so the reconciled map files the second link under Path 2: the
chain crosses paths, as Path 1's chains cross into Path 2 `[E104]`. The Inspector's CVE-2025-49596
had two later bypasses: GHSA-wmjf-2m46-2352, where a request with no Origin header passed when
authentication was disabled, and GHSA-vcc9-3xgm-p9v4, "Incomplete fix for CVE-2025-49596", via DNS
rebinding `[E60]`. PraisonAI went through three fix rounds on the same missing-enforcement class `[E61]`.

**What detection saw.** Path 6 holds the only PitSense hit in the benchmark: mcp-inspector-7f8r at rank
2 `[E62]`. langflow-rvqx and mcp-python-sdk-9h52 are invisible to every tool, because there is no
dangerous call at the key line, only a missing check `[E38]`; litellm-7488 is missed too `[E87]`. In the
KBC engine run, the authz-bypass class surfaced 0 of 11 rows `[E89]`. That class is wider than Path 6:
on the reconciled map, three of its rows (a call-time tool filter, an auth decorator, session ownership)
are authorization logic between logged-in principals and sit outside the eight paths `[E104]`. The same
caution applies to volume. After the audit's correction, authentication and authorization bugs are
about 40% (95% CI 36 to 43%) of the 821 advisories in the 2026 window `[E63]`, but that figure counts a
class, not this path, and we have not measured what share of it is network-position trust. In the
reconciled KBC map Path 6 has 17 rows, tied with Path 2 for the most; the rule-based rater's figure of 22
included the five rows that reconciliation moved off it `[E102]`.

**Guard checklist.** Authenticate every control-plane route by default, including "validation" and
"preview" endpoints. Fail closed when a key is configured but cannot be checked. For loopback tools,
validate Host and Origin by exact match on every route and every transport, WebSocket included, with
protection on by default. Test that each configured option is enforced by a request that omits it.

## Path 7. A malicious MCP server turns the client into a confused deputy

**Attacker.** An MCP server, or its OAuth metadata, that the user's client connects to. **Entry.**
Authorization-server metadata, an `authorization_endpoint` URL, a resource or audience value, or a
server-supplied schema. **Missing guard.** Issuer and resource binding (RFC 8707 audience), URL scheme
validation before `open()`, and consent bound to the browser. **Sink.** Credentials sent to the
attacker's token endpoint, or an OS command via the system URL opener. **Impact.** Client-secret theft,
token reuse across servers, or command execution on the client host.

This is the most protocol-specific path, and it inverts the usual direction: the server attacks the
client. The MCP Python SDK's OAuth client accepted authorization-server metadata without validating its
issuer, so a malicious MCP server could name its own token endpoint and receive the client's
`client_secret` (CVE-2026-115563, proven) `[E64]`. The TypeScript SDK had the same shape
(CVE-2026-104850) `[E65]`. mcp-remote passed the `authorization_endpoint` from a server's metadata to
`open()`, which shells out (CVE-2025-6514), and the Inspector opened a server-chosen authorization URL in
a way that ran code on the user's machine (GHSA-q978-78c7-phqw) `[E66]`. Two SDK bearer-auth
implementations accepted tokens issued for another resource server (CVE-2026-116684, CVE-2026-111771)
`[E67]`. Reconciliation added one row: the Inspector read its transport and server command from the URL
on every route, including `/oauth/callback`, so a malicious server's OAuth redirect to the callback with
`transport=stdio&serverCommand=...` ran a local command (GHSA-4fc4-wcmh-4g86). Rater 1 had it under
Path 6, since any web page could navigate there; we follow the advisory, which frames the attacker as
the server `[E104]`. Path 7 has 13 reconciled rows `[E102]`.

**How fixes went wrong.** FastMCP's confused-deputy fix GHSA-c2jp-c369-7pvx added a consent step;
CVE-2026-27124 (GHSA-rww4-4w9c-7733) later found that the callback never checked the consent binding
`[E68]`. One caveat, raised by the second rater: in this chain the attacker is a malicious OAuth
*client* riding the victim's session at FastMCP's OAuth proxy, and the impact is account takeover, not
a malicious server attacking its client. Both raters put the later row (rww4) on Path 7, whose guard list
names browser-bound consent, and we keep its predecessor with it for consistency. A stricter definition
of Path 7 would move both rows, and with them Path 7's only fix chain, to a proxy-side
confused-deputy class outside the paths `[E104]`.

**What detection saw.** The one proven case in the score run, mcp-python-sdk-qx49, is missed by every
tool in the 21-case run `[E87]` (the later mcp-remote proof is not yet scored `[E107]`), and the KBC engine run surfaced none of the oauth-confused-deputy or
token-passthrough rows `[E89]`. Hand-written mechanism rules do better in-sample: nine OAuth rules
separate the vulnerable from the fixed code on 8 of 8 KBC OAuth and token rows. That is not a held-out
result `[E69]`.

**Guard checklist.** Validate the issuer of authorization-server metadata against the resource server
that pointed to it; send credentials only to that issuer. Check the audience or resource of every
bearer token. Never pass a server-supplied URL to a system opener without checking that its scheme is
`https`. Bind consent to the browser session and verify the binding at the callback.

## Path 8. A fetch guard lets an attacker URL into the internal network

**Attacker.** An outsider or low-privilege user who supplies a URL, or a web page that the agent's
crawler or a model-chosen fetch follows. **Entry.** A URL in a file-typed input, a media URL, a crawled
link, a webhook or a tool argument. **Missing guard.** Resolve-and-check on every hop. **Sink.** A
server-side HTTP client. **Impact.** Server-side request forgery into cluster services and cloud
metadata.

Agents fetch. Loaders crawl, multimodal servers download images, tools call webhooks. Each needs a
guard that resolves the destination and rejects internal addresses, on every redirect, and the guards
fail in a repeated order: (a) no check, (b) no DNS resolution, (c) redirects not re-checked, (d) address
encodings such as IPv4-mapped IPv6 and NAT64, (e) rebinding between check and use, (f) a URL-parser
differential between the guard and the fetcher `[E70]`. BentoML downloaded file-typed inputs given as
URLs with no destination check (CVE-2025-54381) `[E71]`. LangChain.js's `RecursiveUrlLoader` followed a
protocol-relative link on a crawled page to an internal address (CVE-2026-26019) `[E72]`. Both are
proven. vLLM's `MediaConnector` had a redirect bypass (CVE-2025-6242) and, after that fix, a
`urlparse`-versus-fetcher differential on its domain allowlist (CVE-2026-24779) `[E73]`. Flowise
compared addresses against its deny list without unwrapping IPv4-mapped IPv6 such as
`::ffff:127.0.0.1` (CVE-2026-69257) `[E74]`. mcp-atlassian attached its redirect-blocking hook only in
the header-PAT authentication branch (CVE-2026-77261) `[E15]`. Open WebUI fixed a NAT64 gap in
`is_global` (CVE-2026-70485) and then DNS rebinding in its Playwright loader (CVE-2026-87996) `[E75]`.

**How fixes went wrong.** SSRFGUARD, PitSense's hermetic SSRF battery, was run at each chain's first fix
without using knowledge of the later advisory. In both measured chains it reached the canary with
exactly the later public bypass: vLLM 3f6c to qh4c, and LangChain.js gf3v to GHSA-mphv-75cg-56wg
(CVE-2026-27795, redirect chaining, fixed in @langchain/community 1.1.18) `[E76]`. Some SSRFGUARD rows
measure extracted or emulated code rather than a full application, which we list as a limit (Section 8).

**What detection saw.** The battery hit each advisory's own mechanism on 7 of 7 vulnerable SHAs; the
VARIANT Semgrep SSRF rules hit 2 of 7 `[E77]`. In the benchmark, langchainjs-gf3v was missed by every
tool, and for bentoml-mrmq the PitSense surface map had the sink at rank 15 before stub triage dropped it
with "no untrusted source traced" `[E78]`. Of 14 evaluable SSRF rows in the KBC engine run, 4 surfaced
and none passed triage `[E89]`.

**Guard checklist.** Resolve the hostname, check every resolved address after unwrapping mapped and
translated forms, connect to the address you checked, disable automatic redirects and re-check each hop
yourself, and parse the URL once with the same parser the fetcher uses. Attach the guard on every
authentication branch and every code path that fetches.

---

## 4. Incomplete fixes are a first-class result

The thesis has three legs. The third, that fixes are often incomplete, is the one most useful to a
hunter, because it says where to look next: at the fixed version.

Seven of the eight paths have at least one documented public chain in which a later advisory bypassed
or completed the first fix: Path 2 (PAL, n8n, Flowise) `[E12]` `[E14]` `[E27]`, Path 3 (mcp-server-git,
mcp-atlassian) `[E36]` `[E37]`, Path 4 (mcp-server-git, vLLM) `[E44]` `[E45]`, Path 5 (Mooncake,
BentoML) `[E48]` `[E49]`, Path 6 (Inspector, PraisonAI) `[E60]` `[E61]`, Path 7 (FastMCP) `[E68]` and
Path 8 (vLLM, Open WebUI, LangChain.js) `[E73]` `[E75]` `[E76]`. Path 1 is the exception only in form:
its follow-on bypasses moved to Path 2 `[E12]`, and so did the second link of Langflow's chain, which
began on Path 6 `[E59]` `[E104]`. Path 7's count rests on its one chain, FastMCP, which carries the
direction caveat in the Path 7 section; under a stricter Path 7 the claim would be six of eight `[E104]`.

We do not yet have a corpus-wide rate. In the 821-advisory stream, 37 advisories carry bypass wording,
and the label audit found this undercounts: in a 150-row sample it saw 3 incomplete-fix advisories with
no such wording `[E79]`. A "percentage of fixes later bypassed" figure needs a denominator we have not
built.

What we can measure is whether the next bypass is predictable from the first fix. Three PitSense methods
answer yes, each for its own path:

- **VARIANT** writes rules from the first fix. Across ten later public bypasses, its rules flagged 7
  (5 with strict rules) `[E80]`.
- **GATEDIFF** fuzzes the gate against the real executor. It found a disagreement on 4 of 5 public
  gates, including the residual left by n8n's fix commit `[E29]` `[E14]`.
- **SSRFGUARD** runs a fixed probe battery at the first fix. It reached the canary with the later public
  bypass in 2 of 2 measured chains `[E76]`.

The practical lesson for vendors is that the fix review should test the *class*, not the reported
input. For hunters, a fixed advisory in one of these paths is a lead, not a closed case.

## 5. The model-mediated attacker, and what the scripted model settles

Path 1, most of Path 3 and part of Paths 2 and 5 depend on input that reaches the sink through the
model (`untrusted-llm-input` is 5 of 5, 12 of 14, 5 of 17 and 2 of 9 of their reconciled rows) `[E103]`. Two
numbers frame its size. In the KBC, `untrusted-llm-input` is the largest attacker label, 29 of 121 rows
`[E2]`. In the advisory stream, the strict model-mediated share is at least 25 of 821, an estimated 37
with a confidence interval of 16 to 61, about 3 to 5%, and it is not concentrated in October
(7 of the 25) `[E81]`.

The five CHAINLAB proofs span three guard shapes: no guard (PALChain, Xinference), an incomplete guard
(the PAL `__import__` omission) and an ignored guard (PraisonAI) `[E11]` `[E17]` `[E12]` `[E13]`. They
also span both the agent-framework and the serving layer `[E17]`. In every case the scripted model
assumed only the feature's own output shape `[E100]`.

The G1 rule changes engine behaviour measurably. Applied as an engine patch to PitSense's stub triage,
it moved the KBC rows that the surface map finds from 1 QUALIFIES to 4 (of 20 surfaced) with no change
on the 48 negatives of a private evaluation set and no new false pass `[E90]`. With a real LLM backend the picture is
more cautious: the LLM was stricter on the KBC rows (QUALIFIES 4 to 2) and none of the nine outsider-
reachable rejects flipped, but it found 3 of that set's 4 positives instead of 1 and still gave 0 false
passes on the 48 negatives, for about $4.77 of total spend `[E91]`. One open question remains: how close
to the feature's grammar the scripted output must be `[E7]`. A second, whether tool-argument and SQL or
Cypher sinks count like code execution, has since been answered in the rule proposal (they do; a sink is
judged by its effect) on the strength of the Langroid Cypher proof. That amendment is a proposal and
has not yet been adopted in PitSense's production engine `[E107]`.

## 6. What detection misses

### 6.1 The benchmark

On all 21 AgentVulnBench cases, at locate@10:

| Tool | Located |
|---|---|
| PitSense (deterministic stub, no LLM) | 1/21 (mcp-inspector-7f8r, rank 2) |
<!-- tool-scores -->| Semgrep OSS 1.184.0 (registry packs p/python, p/javascript, p/security-audit) | 0/21 |
| Bandit 1.9.4 (default rules; Python cases only) | 0/21 |
<!-- /tool-scores -->| rankbase (LLM-free baseline) | 1/21 (llama-index-wvpx, rank 2) |

Source: `[E86]`. With one hit each, the difference between PitSense and rankbase is not meaningful
`[E86]`. On the first 14 cases, the earlier run gave PitSense 1/14<!-- tool-scores --> and Semgrep and Bandit 0/14<!-- /tool-scores --> `[E96]`
`[E82]`. The PitSense row is a static, free, stub-backend run and is not the configuration of
PitSense's production engine, which uses an LLM backend `[E83]`.
<!-- tool-scores -->Each third-party tool ran once per case with the
configuration shown and no tuning to the benchmark (Semgrep: `semgrep scan --metrics=off --json
--no-git-ignore --timeout 30 --config <pack> .`; Bandit: `bandit -r . -f json -q`). Bandit reads only Python,
so the four TypeScript cases are misses by construction. The scores measure one stage, locate@10, on
n=21 cases built around paths that pattern tools are not designed for. They are not a general ranking
of these tools. Per-case results and the scoring script are in the AgentVulnBench repository `[E86]`.
<!-- /tool-scores -->

The misses are not random. They split cleanly by path:

- **Ranked too low or discarded (Paths 1, 2, 8).**<!-- tool-scores --> Semgrep and Bandit each flag the key sink in two
  cases, at ranks 12 to 109 `[E22]`.<!-- /tool-scores --> PitSense's surface map holds the key sink in 4 of 21 cases, but
  stub triage keeps only one `[E88]`. A trivial reachability-aware ranker lifts one of these to rank 2
  `[E86]`. The fix is ranking by attacker reachability, which is what the G1 rule supplies for the
  model-mediated cases.
- **Nothing to match (Paths 3, 6, 7).** Path traversal in the MCP servers, the missing-auth route, the
  rebinding default, token passthrough and the OAuth confused deputy have no dangerous call at the sink
  line `[E38]` `[E87]`.

### 6.2 The corpus

Run over the whole KBC, the PitSense stub engine's surface map found 21 of 120 evaluable rows, and
triage qualified 1, an end-to-end recall of 1 of 120 `[E89]`. By class the gaps follow the paths:
authorization bypass surfaced 0 of 11, path traversal 1 of 13, command injection 0 of 10, sandbox
escape 1 of 10, and every dns-rebinding, OAuth and token-passthrough row surfaced 0 `[E89]`. The real
LLM backend did not change this for the rows that matter most: of nine outsider-reachable rejects, four
failed because no caller was mapped statically, three because the route correctly needs a login and the
engine's gate treats a low-privilege user as out of scope, and two because the engine traced the wrong
path `[E91]`. The first is a call-graph problem, the second a policy question about Path 2's
authenticated attacker, and the third a candidate-selection problem. None is about the model.

## 7. Does the thesis hold?

1. **A small set of recurring paths: supported, with a softer coverage figure and one addition.** On
   the reconciled two-rater map the eight paths cover 105 of the 121 KBC rows, within a range of 101 to
   114 `[E102]`, and 24 of the 26 proven reproductions, the latter still a single-rater figure `[E84]`.
   The paths are applied reproducibly (kappa 0.850, 97.0% same-path agreement), but the line between a
   path and no path is only moderately reliable (kappa 0.463) `[E101]`. The 16 rows on no path fall
   into four groups `[E106]`: six `library-caller` rows, which need the application to pass
   tenant-authored input to a library API; five authorization or data-scope bugs with no host impact
   (tool filter, auth decorator, session ownership, and the two query-filter halves); four
   authenticated-user or operator-config rows with no agent-specific guard (a shell injection, a
   config-named module import, an unsandboxed request template, an `eval`ed secret); and one
   prototype pollution with no documented executor. The second group is the one to watch: it is
   agent-specific and recurring, and a later version may give it its own, non-root path. The two
   unmapped proofs are both `library-caller` cases, and one of them, langgraph-7p73, has cross-tenant
   data access rather than host impact `[E85]`. The addition is an attacker position the thesis left
   out: the authenticated low-privilege user, 27 of 121 rows `[E2]`. On the reconciled map it feeds
   Path 2 above all (11 rows) and Path 8 (5), and 7 of its 27 rows sit on no path `[E103]`. Path 6
   holds only one such row `[E103]`.
2. **One missing guard per path: supported, on our reading.** We describe each worked example in the
   eight path sections with one of the five guard shapes; the table's examples are sourced
   `[E11]` `[E12]` `[E13]` `[E14]` `[E15]`, but assigning a shape to every example is our own
   classification and has had no second rater.
3. **Fixes are often incomplete: supported for seven of eight paths**, with documented public chains,
   and predictable from the first fix in measured cases `[E80]` `[E29]` `[E76]`. A corpus-wide rate is
   still missing `[E79]`.
4. **Detection: tools miss these paths for structural reasons.** One bug in 21 located by any real
   tool, with failures explained by ranking and by guard logic that has no sink `[E86]` `[E88]` `[E38]`.
   This rests on a stub backend for PitSense `[E83]`.
5. **Out of sample: weaker.** On 30 held-out rows the paths cover 20 (range 16 to 27), against 105 of 121
   in sample. Five of the ten rows on no path are one missing shape: a model-chosen argument into a shell
   or CLI command line `[E108]`.

## 8. Limits

- **Two raters, one of them blind, neither human.** KBC rows have a rule-script rater and a blind LLM
  rater; their 16 disagreements were settled by a third, non-blind pass, six of them contested `[E101]`
  `[E104]`. The weakest number is the path-vs-none boundary, kappa 0.463, so the coverage figure is a
  range (101 to 114 of 121), not a point `[E102]`. The two raters share the `class` and `attacker`
  fields, so they are not fully independent. An independent human rater, at least on the 16 disputed
  rows and the 16 reconciled "none" rows, is the next step.
- **Proof mapping is single-rater.** The mapping of the 26 reproductions to paths has had no second
  rater `[E84]`.
- **In-sample coverage.** The eight paths were named from this same corpus and its proofs, so 105 of 121
  measures how well the paths fit the data they came from.
- **Out-of-sample coverage is lower and rests on 30 rows.** On the held-out KBC-E batch the paths cover
  20 of 30 (66.7%; range 16 to 27). The batch was drawn by class keyword, so it barely tests Paths 3, 6
  and 7. Two KBC-E rows were excluded because their advisory is a worked example here. Its rows are not published, because they are also a held-out set for engine evaluation; only
  the aggregate result is `[E108]`.
- **Uneven proof depth.** In the counts used here, Paths 4 and 7 rest on one proof each (6hqx, qx49)
  `[E39]` `[E64]`. Each has since gained a second proof, not yet scored or counted: LangGraph mhr3, and
  mcp-remote CVE-2025-6514, reproduced on Linux through the URL-scheme handler rather than the Windows
  shell route of the original public write-up `[E107]`. The Inspector's GHSA-q978 is still not reproduced `[E66]`.
- **Detection is static and free.** No tool attempted the prove or fix stage, and the PitSense row has
  no LLM `[E83]`. LLM-backend numbers exist only for engine triage on KBC, not for benchmark locate
  `[E91]`.
- **Some SSRF chains are measured on extracted or emulated code** `[E76]`.
- **No A2A path.** The thesis names peer agents as an attacker, but the corpus has no public, fixed A2A
  card-trust advisory, so we make no claim about A2A here.
- **No code excerpts.** This version links each advisory and its pinned vulnerable and fixed commits
  rather than showing vuln-versus-fix code.
- **Scope of sources.** The paper discusses only public, already-fixed advisories and PitSense
  reproductions of them.

## 9. Reproducing this paper

All paths below are relative to the [`paths-to-root/`](https://github.com/teodor-velicky/agentvulnbench/tree/main/paths-to-root/) folder of the AgentVulnBench repository.
The scripts use only the Python standard library.

- Corpus: the 121-row KBC snapshot is in [`kbc-snapshot/`](https://github.com/teodor-velicky/agentvulnbench/tree/main/paths-to-root/kbc-snapshot) (four JSONL batches) `[E1]`.
  One row was corrected before mapping: `kbc-ghsa-hc55-p739-j48w` merges two advisories, and its ids are
  listed as explicit pairs, GHSA-hc55-p739-j48w with CVE-2025-53110 (the row's locator) and
  GHSA-q66q-fx2p-7w4m with CVE-2025-53109 `[E95]`.
- Row-to-path map: rater 1 `python -I paths-to-root/map_kbc_paths.py` `[E92]`; rater 2 agreement
  `python -I paths-to-root/rater2/kappa.py --disagreements` `[E101]`; reconciled map
  `python -I paths-to-root/reconcile.py` (writes `reconciled-path-map.csv` with `--write`) `[E102]`.
  The blind rater's codebook and input are in [`rater2/`](https://github.com/teodor-velicky/agentvulnbench/tree/main/paths-to-root/rater2).
- Out-of-sample check: aggregate results in [`kbc-e-oos/RESULTS.md`](https://github.com/teodor-velicky/agentvulnbench/blob/main/paths-to-root/kbc-e-oos/RESULTS.md) `[E108]`.
- Proofs and tool scores: the 21 AgentVulnBench cases, their three-arm results and the locate@10 scores
  are in the [AgentVulnBench repository](https://github.com/teodor-velicky/agentvulnbench) `[E3]` `[E86]`. The CHAINLAB harness (5 proofs) and the
  engine runs on the KBC and the private evaluation set (Sections 5 and 6.2) are not published; the
  evidence map records each figure and its source `[E4]` `[E89]` `[E90]` `[E91]`.

Advisory summaries are quoted from the GitHub Advisory Database (CC BY 4.0). Every advisory id
cited here, and every advisory behind the out-of-sample check, was re-checked against the GitHub API on
2026-11-25: none was withdrawn or missing.

## Licence

The text of this paper and its evidence tables are licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The scripts in `paths-to-root/` are licensed
under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). Advisory text quoted from
the GitHub Advisory Database remains under its own CC BY 4.0 licence.

---

## Appendix A. Reconciling the two raters

Each row below is one on which rater 1 (rule script, `kbc-path-map.csv`) and rater 2 (blind LLM,
`rater2/labels.csv`) chose different labels. The adopted label is the one used in this paper and in
`reconciled-path-map.csv`; it was chosen after re-reading the row's description and notes in
`kbc-snapshot/*.jsonl` against `rater2/CODEBOOK.md`. "Contested" marks the six calls that could
reasonably go the other way; flipping them moves coverage between 102 and 108 of 121 `[E102]` `[E104]`. The advisory
link is the row's own `advisory_url`. Adopted: rater 1 in 5 rows, rater 2 in 11.

| # | KBC row | Advisory (source) | Repo | R1 | R2 | Adopted | Why |
|---|---|---|---|---|---|---|---|
| 1 | `kbc-ghsa-35w5-fv47-8956` | [GHSA-35w5-fv47-8956](https://github.com/ag2ai/ag2/security/advisories/GHSA-35w5-fv47-8956) | ag2ai/ag2 | P4 | P2 | **P2** | AST allow-list checked the template, eval ran the substituted string: a gate/executor differential; nothing at rest is loaded as code |
| 2 | `kbc-ghsa-3r68-hf9h-887v` | [GHSA-3r68-hf9h-887v](https://github.com/advisories/GHSA-3r68-hf9h-887v) | sooperset/mcp-atlassian | P6 | none | **none** | authenticated client calls operator-disabled tools; missing guard is per-tool authorization at dispatch, not authentication or Origin binding; no host impact in the row |
| 3 | `kbc-ghsa-4fc4-wcmh-4g86` | [GHSA-4fc4-wcmh-4g86](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-4fc4-wcmh-4g86) | modelcontextprotocol/inspector | P6 | P7 | **P7** | row's entry is a malicious MCP server's OAuth redirect to /oauth/callback; impact is command exec on the client host (P7 sink). A web page could also navigate there (P6 reading), but the advisory frames the server |
| 4 | `kbc-ghsa-53gh-p8jc-7rg8` | [GHSA-53gh-p8jc-7rg8](https://github.com/advisories/GHSA-53gh-p8jc-7rg8) | BerriAI/litellm | none | P4 | **none** (contested) | attacker writes the proxy's own config; P4 is about third-party artefacts the server opens. Counting it would widen P4 to any config-driven import. Contested: P4 under a broad reading |
| 5 | `kbc-ghsa-6wvf-77m9-58rm` | [GHSA-6wvf-77m9-58rm](https://github.com/advisories/GHSA-6wvf-77m9-58rm) | BerriAI/litellm | none | P4 | **none** (contested) | template arrives in the request body and is rendered at once: request-time SSTI by an authed user, not an artefact at rest. Contested: P4 under a broad reading |
| 6 | `kbc-ghsa-c2jp-c369-7pvx` | [GHSA-c2jp-c369-7pvx](https://github.com/advisories/GHSA-c2jp-c369-7pvx) | PrefectHQ/fastmcp | P7 | none | **P7** (contested) | kept on P7 for consistency with its chain successor rww4, which both raters put on P7; P7's guard list names browser-bound consent. Caveat: attacker is a malicious OAuth client at the proxy, not a malicious server |
| 7 | `kbc-ghsa-fvww-7h3r-vfhp` | [GHSA-fvww-7h3r-vfhp](https://github.com/advisories/GHSA-fvww-7h3r-vfhp) | langchain-ai/langgraph | P6 | none | **none** | auth decorator registered for '*' so an ownership check never ran: authorization logic between authenticated principals, no host impact |
| 8 | `kbc-ghsa-g3r5-9h93-4j2c` | [GHSA-g3r5-9h93-4j2c](https://github.com/advisories/GHSA-g3r5-9h93-4j2c) | n8n-io/n8n | P3 | none | **P3** (contested) | entry, guard (containment checked then used: TOCTOU), sink (write outside root) and impact (code load on restart) match P3; only the attacker differs: an authed workflow author, not a model |
| 9 | `kbc-ghsa-gppg-gqw8-wh9g` | [GHSA-gppg-gqw8-wh9g](https://github.com/advisories/GHSA-gppg-gqw8-wh9g) | BerriAI/litellm | P4 | none | **none** | attacker must control the proxy's own secret value (environment/config), which the G1 rule and P4 both exclude; no third-party artefact |
| 10 | `kbc-ghsa-hf3x-42qp-4rq6` | [GHSA-hf3x-42qp-4rq6](https://github.com/ag2ai/ag2/security/advisories/GHSA-hf3x-42qp-4rq6) | ag2ai/ag2 | P3 | none | **P3** (contested) | archive member names escape the staging root: P3's containment guard, file write sink; the paper's own Path 3 checklist names archive members. Attacker is the archive author, not a model |
| 11 | `kbc-ghsa-hxmv-c4g6-5fqc` | [GHSA-hxmv-c4g6-5fqc](https://github.com/advisories/GHSA-hxmv-c4g6-5fqc) | MervinPraison/PraisonAI | none | P4 | **P4** | a crafted recipe directory's tools.py is exec_module()d at load without the opt-in that guards sibling autoload paths: third-party artefact trusted as code, misplaced guard |
| 12 | `kbc-ghsa-jpw9-pfvf-9f58` | [GHSA-jpw9-pfvf-9f58](https://github.com/advisories/GHSA-jpw9-pfvf-9f58) | modelcontextprotocol/python-sdk | P6 | none | **none** | session id served without checking the owning principal: cross-user session use among authenticated users, not network-position trust; no host impact |
| 13 | `kbc-ghsa-v798-mcc6-2m3m` | [GHSA-v798-mcc6-2m3m](https://github.com/advisories/GHSA-v798-mcc6-2m3m) | langflow-ai/langflow | P6 | P2 | **P2** | authentication exists (P6's guard is present); the missing guard is a validator that itself execs the code it validates: P2's authed-user position. The Langflow chain therefore crosses P6 -> P2 |
| 14 | `kbc-ghsa-w66g-j6c4-hcfc` | [GHSA-w66g-j6c4-hcfc](https://github.com/advisories/GHSA-w66g-j6c4-hcfc) | sooperset/mcp-atlassian | P3 | none | **none** | JQL project allowlist skipped: data-scope confinement in a SaaS query, not a filesystem root; impact is reading excluded data, not host impact |
| 15 | `kbc-ghsa-w66g-j6c4-hcfc-b` | [GHSA-w66g-j6c4-hcfc](https://github.com/advisories/GHSA-w66g-j6c4-hcfc) | sooperset/mcp-atlassian | P3 | none | **none** | CQL space allowlist skipped: same as the Jira half (data-scope, no host impact) |
| 16 | `kbc-ghsa-wrwr-h859-xh2r` | [GHSA-wrwr-h859-xh2r](https://github.com/advisories/GHSA-wrwr-h859-xh2r) | n8n-io/n8n | P2 | none | **none** (contested) | guard shape is a clean differential (validated a coerced copy, used the original), but the row documents prototype pollution only, no executor sink; would move to P2 if a pollution->exec gadget is shown |
