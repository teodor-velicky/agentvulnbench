# AgentVulnBench v0: methodology

Status: **v0** (2026-11-25). Author: Teodor Velický (PitSense). Licence: text CC BY 4.0 (`LICENSE-DATA`),
code Apache-2.0 (`LICENSE`); see `NOTICE`.

This document is the scoring rulebook of the benchmark. The normative detail lives in `bench/SPEC.md`
(case format, harness) and `bench/SCORING.md` (scorer); this file explains the choices and states the
limits. Where they disagree, SPEC and the scorer code win, and the disagreement is a bug in this file.

## 1. What the benchmark measures

AgentVulnBench asks one question: **given the source of an AI-agent, MCP or model-serving project at a
vulnerable commit, can a tool find the bug, prove it and fix it?** It is a "proof, not flags" benchmark.
Every case is a public, already-fixed vulnerability with a hermetic exploit oracle, so a claimed proof
or fix is checked by running it, not by matching text.

AgentVulnBench measures tools that find vulnerabilities *in the code of* agent frameworks, MCP servers
and SDKs, and model servers. The vulnerability-finding benchmarks we reviewed (CyberGym, CyberGym-E2E,
BountyBench, CVE-Bench, SEC-bench; reviewed on 2026-11-24)
cover general open-source bugs, and we found none with exploit-verified ground truth for agent, MCP or
serving code. That is an absence-of-evidence finding from one review, not a proof that none exists. The per-stage reporting follows CyberGym-E2E, whose end-to-end numbers are far
below its single-stage numbers.

## 2. Threat model and attacker positions

Each case carries one `attacker` label: the position from which the attacker reaches the sink. A tool
under test is told this one-line threat statement and nothing else about the bug.

| attacker | Position | Cases |
|---|---|---|
| `untrusted-llm-input` | Attacker-controlled content (a document, web page, tool result, chat message) steers the agent's model, which then emits the dangerous tool call or code. The attacker never touches the app directly. | 9 |
| `remote-unauth` | A network client with no credentials reaches a server endpoint. | 5 |
| `malicious-web-content` | A page the victim's browser or crawler loads (cross-site request, DNS rebinding, crawled link). | 3 |
| `library-caller` | The application developer passes caller-controlled data into a library API. **Tagged.** | 2 |
| `malicious-mcp-server` | An MCP server the client connects to is hostile (for example it advertises an attacker's OAuth server). | 1 |
| `untrusted-data-store` | Attacker-written data at rest (a git repository, a file) is later processed by the tool. **Tagged.** | 1 |

**Model-mediated attackers (scripted model).** For `untrusted-llm-input` cases no real LLM runs. A
deterministic driver plays the model and emits the attacker-chosen tool call or code verbatim, through the
framework's own interface. A positive result therefore shows that the *framework* lacks a guard between
model output and the sink, independent of how gullible any model is. The case's `attacker_story` names the
untrusted content that would put that output in the model's mouth. This follows the G1 rule (`paths-to-root/PAPER.md`,
section 2.3): a model-mediated path is attacker-reachable when model output flows to a
dangerous sink with no guard that limits it to the feature's intended safe shape.

**Tagged positions.** `library-caller` and `untrusted-data-store` cases are real, fixed advisories, but a
tool with a strict threat model may rightly decline them (the caller is trusted, or the data store is
assumed owner-written). They are included and tagged, and every headline table also reports the score
without them (18 cases).

## 3. Case inclusion and exclusion

A case is included only if **all** of these hold (SPEC s8):

1. It is a row of PitSense's Known-Bug Corpus (KBC): a **public** GHSA or CVE, published, **fixed
   upstream**, with the vulnerable and the fix commit known.
2. The fix is in the advisory's own repository, and both commits build from source in a CPU-only container
   in about 15 minutes.
3. The three-arm proof (section 4) passes deterministically in the harness.
4. The attacker position is labelled.

A case is excluded when any of these holds:

- The advisory is unfixed, disputed, withdrawn, or closed as "won't fix" / "by design", or it is only a
  hardening note. These never count as true positives.
- The bug is new or unpublished, **including PitSense's own findings that are not yet public**. A leak check
  against PitSense's private lists verified this before release.
- The case needs a GPU, model weights, a paid API, or any network service outside the case network.
- The only oracle is an LLM's behaviour (no deterministic side effect).
- The fix commit bundles unrelated changes, unless the sink-specific change can be isolated and is noted.

Status of the 21 v0 cases, checked against GitHub's advisory database on 2026-11-25
(`advisory-status.json`): 21 published, 0 withdrawn, 21 with a first patched version. 20 have a CVE id;
`mcp-server-git-ghsa-6hqx` is a repository advisory without one.

## 4. Ground truth: the three-arm oracle

Each case ships a Dockerfile that builds the target at a commit passed as `REPO_SHA`. The same Dockerfile
builds the **vuln** image (vulnerable commit) and the **fix** image (fix commit), so the only difference
between them is the upstream fix. Three arms run, 5 trials each:

| Arm | Image | Input | Expected hits |
|---|---|---|---|
| ATTACK | vuln | the exploit (`inputs/attack.*`) | **5/5** |
| CONTROL | vuln | a benign input that exercises the same feature (`inputs/control.*`) | **0/5** |
| FIX | fix | the byte-identical exploit | **0/5** |

A case is **PROVEN** only at ATTACK 5/5, CONTROL 0/5, FIX 0/5, with both image SHAs verified (the image
writes `REPO_SHA` to `/opt/bench/sha` and the harness refuses a mismatch), no harness error and no
hermeticity violation. This is PitSense's three-arm standard. CONTROL rules out an oracle that fires on normal
use; FIX shows the effect is caused by the advisory's sink and nothing else.

Oracle rules:

1. The oracle reads a **side effect** (a file written, a secret read back, a callback received by an
   in-network listener, process state), never the exploit's own output.
2. It keys on a fresh per-trial **nonce** (`PSB<16 hex>`), so a stale artifact cannot cause a hit.
3. Read-back oracles use a secret the input never contains (for example env `sk-<nonce>-live`).

All 21 committed result files (`bench/results/<case>.json`) have verdict PROVEN at 5/5 · 0/5 · 0/5.
A case's own reference exploit is ground truth only. It is never a tool score.

## 5. Hermeticity

- Build time may download base images (pinned by digest), the source tarball for the exact commit from
  GitHub codeload, and packages (lockfile, or resolved as of a date just after the fix).
- **Run time has no egress.** Exec-mode cases run with `--network none`. Client-mode cases (remote
  attackers) run on a per-case Docker network created `--internal`; the harness checks that it reports
  `Internal: true` and records each container's network mode. Any other mode fails the case.
  In the committed results: 16 cases ran `none`, 5 ran on a verified internal network.
- Every trial gets a fresh container; containers and networks are removed afterwards. Upstream code runs
  only inside containers, never on the host. Exploits target only the local containers.

## 6. Scoring a tool, per stage

A tool gets the repository tree at the vulnerable commit (no `.git`, no history, no advisory text, no fix
diff) and the attacker statement. Its output is an attempt file (`avb-attempt/0`, see `SCORING.md`). Four
numbers are reported side by side; a headline may be one named stage or end-to-end, **never a blend**.

| Stage | Solved when |
|---|---|
| **locate@10** | One of the tool's first 10 findings is in `locator.file`, within ±25 lines of `locator.line`, with a class compatible with `rd_class` (same class or same family). Only the first 10 count, so spraying flags does not help. |
| **prove** | The tool's own exploit, placed in the case's attack slot, passes the full three-arm check (ATTACK 5/5 on vuln, CONTROL 0/5 with the case's control, FIX 0/5 on the fix image). |
| **fix** | The tool's patch applied to the vulnerable tree builds, keeps the vulnerable SHA, drops ATTACK to 0/5 with the reference exploit (and the tool's own exploit if any), and CONTROL still delivers. |
| **e2e** | locate, prove and fix all solved on the same case. |

Noise is reported next to recall, never subtracted from it: **flags per case** (findings outside the
answer key) and **precision@10**. As published, both are computed per located case, over each tool's first 10 findings per case: flags/case = (findings considered − located cases) / N and precision@10 = located cases / findings considered. This differs from a per-finding count only for rankbase, which has two key-matching findings in its top 10 on llama-index-ghsa-wvpx (per finding: 8.905 and 0.0106, instead of the published 8.952 and 0.0053). Located counts and ranking are unaffected. Budget (wall-clock seconds, tokens, dollars per case) is recorded for
every tool. A missing stage counts as not solved.

Class families used by locate: code / command / template injection, MCP stdio command exec, sandbox
escape and prompt-injection-to-tool; path traversal and allowlist bypass; authz bypass, OAuth confused
deputy and token passthrough; SSRF and DNS rebinding. Adapters map each tool's own labels (CWE, rule id)
to these classes without reading the answer key (`bench/tools/common.py`).

## 7. Tools scored in v0

Only tools that run locally under their own licence were scored. No commercial or hosted tools. CodeQL is
excluded until it is clear whether a company may publish benchmark scores under its licence.

| Tool | Configuration |
|---|---|
| PitSense | PitSense engine `5ae65df` (`pitsense` 0.1.0, not open source), static pipeline with the **deterministic stub backend, no LLM**. This is not how PitSense's real hunts run. Only its attempt and score files are published. |
| Semgrep OSS 1.184.0 | registry packs p/python, p/javascript, p/security-audit (snapshot hash in `bench/tools/semgrep/SNAPSHOT.json`) |
| Bandit 1.9.4 | default plugins; Python only, so the 4 TypeScript cases are misses by construction |
| rankbase 0 | LLM-free baseline: rank candidate sinks by danger × entry reachability; regexes and weights written before any answer key was read, never tuned |

`pitsense-surface` (all engine candidates before triage) is a diagnostic, not a leaderboard row.

## 8. v0 results (locate stage)

From `bench/scores/v0/SCORES.md` (2026-11-25), N = 21:

| Tool | locate@10 | without tagged (N = 18) | prove | fix | e2e | flags/case | precision@10 |
|---|---|---|---|---|---|---|---|
| PitSense (stub) | 1/21 | 1/18 | 0/21 | 0/21 | 0/21 | 1.81 | 0.0256 |
| rankbase | 1/21 | 1/18 | 0/21 | 0/21 | 0/21 | 8.952 | 0.0053 |
| Semgrep | 0/21 | 0/18 | 0/21 | 0/21 | 0/21 | 5.857 | 0.0 |
| Bandit | 0/21 | 0/18 | 0/21 | 0/21 | 0/21 | 8.095 | 0.0 |

The two hits are different cases (PitSense: `mcp-inspector-ghsa-7f8r`, rank 2; rankbase:
`llama-index-ghsa-wvpx`, rank 2). With one hit each, the difference between tools is not meaningful.

## 9. Limitations, stated plainly

- **21 cases is small.** One case moves a score by 4.8 points. Many classes have one case. No confidence
  intervals are claimed, and tool rankings in v0 are not statistically meaningful.
- **Only locate was measured.** prove, fix and e2e are **0 for every tool by construction**: none of the
  four tools emits an exploit in the case's input format or a patch, so under the "missing stage = not
  solved" rule they score 0. The scorer ran with `--no-docker`; nothing was executed in Docker for any tool.
  The harness can score prove and fix (`bench/scorer.py`, self-test passes), but no tool attempted them.
- **PitSense was scored without its LLM.** The stub backend is free and deterministic; PitSense's real hunts
  use an LLM backend and hand-quality review. The row is a floor for the static pipeline, not the product.
- **Pattern tools are disadvantaged by design.** Many cases have no dangerous call at the sink line
  (missing auth, DNS-rebinding default, token passthrough, OAuth confused deputy). That is the point of
  the benchmark, but it means 0 for Semgrep and Bandit says "these bug shapes are invisible to pattern
  rules", not "the tool is broken".
- **Locate tolerance.** ±25 lines and family-level class matching are generous for one-line sinks and may
  be strict for bugs spread across files (one locator per case).
- **Same-budget rule not exercised.** SPEC asks for one budget cap across tools; every tool finished in
  minutes for $0, so no cap was set.
- **Selection bias.** Cases were picked from KBC rows that build on CPU in about 15 minutes and have a
  deterministic oracle. Large monorepo builds, GPU servers and hosted-OAuth cases are absent.
- **Answer-key exposure.** The cases are public advisories. A tool or model trained after the advisory may
  have seen the fix. v0 does not control for training-data contamination.
- **Registry drift.** Semgrep registry packs change; a re-download is a different configuration. The
  snapshot hash is recorded, but the rule YAML is not redistributed (Semgrep Rules License).
- **Windows path limit.** Two trees were re-scanned from short paths because semgrep-core could not open
  paths over 260 characters (SCORES.md, "Inputs, pins, caveats").

## 10. Reproduce

```
python bench/run.py --all                                   # ground truth: rebuild and re-prove all 21 cases (Docker)
python -I bench/scorer.py score bench/scores/v0/<tool>.attempt.json --no-docker --out <tool>.json
python -I bench/tools/tables.py                             # headline + matrix from the score files
python -I bench/scorer.py selftest --no-docker              # scorer self-test (reference / garbage / empty)
```

The full tool-run recipe (fetching trees, Semgrep/Bandit environments) is in
`bench/scores/v0/SCORES.md`, "Reproduce". Scoring from the committed attempt files needs no network
or Docker.

## What ships

This repository ships `bench/cases`, `bench/results`, `bench/scores`, `bench/selftest`, the Semgrep, Bandit and rankbase adapters in `bench/tools`, `bench/run.py`, `bench/scorer.py`, `bench/SPEC.md`, `bench/SCORING.md`, this file and `docs/MANIFEST.md`, plus `chainlab/` and `paths-to-root/`. The PitSense engine and its adapter are private; internal working notes are not included. Two cases in `bench/cases` (`langgraph-ghsa-mhr3`, `mcp-remote-ghsa-6xpm`) were added after the v0 scoring run; they are PROVEN but not in the 21-case v0 scores.
