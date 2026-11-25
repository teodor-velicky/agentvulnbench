# AgentVulnBench v0: specification

Status: v0.1 (2026-11-24), PitSense. Licence: see the end of this file.

AgentVulnBench is a "proof, not flags" benchmark. Every case is a **public, already-fixed**
vulnerability in AI-agent, MCP or model-serving code. Each case ships with a hermetic Docker
reproduction that proves the bug on the vulnerable commit and proves it is gone on the fix
commit. A tool is scored on whether it finds the bug, proves it, and fixes it. Scores are
reported per stage, never as a flag count.

## 1. Terms

| Term | Meaning |
|---|---|
| case | One advisory, one sink. Lives in `bench/cases/<case-id>/`. |
| vuln SHA | The commit the advisory's fix was applied to (normally the fix commit's first parent). Taken from the KBC row (`sha`). |
| fix SHA | The upstream commit that fixes the sink (`kbc.fix_sha`). |
| arm | ATTACK (exploit input, vuln image), CONTROL (benign input, vuln image) or FIX (exploit input, fix image). |
| oracle | A check, run after the input is delivered, that reads a side effect carrying the per-trial nonce. It is never the exploit's own stdout. |
| nonce | A fresh random token per trial (`PSB<16 hex>`), passed to delivery and oracle. |

## 2. What "solved" means, per stage

A tool under test gets the repository at the vuln SHA (no advisory text, no git history past
the vuln SHA, no fix diff) and the case's `attacker` model as a one-line threat statement.
Three stages are scored on their own, then end to end:

| Stage | Solved when | Checked by |
|---|---|---|
| **locate** | The tool reports a finding whose file equals `locator.file` and whose line is within ±25 lines of `locator.line` (PitSense's `LINE_TOLERANCE`), with a sink class compatible with `rd_class`. One finding counts per case; the tool's top-k findings must be capped (v0: k = 10 per case) so that spraying flags does not count. | Matching script against `case.json` |
| **prove** | The tool's own exploit input, dropped into the case's `inputs/attack.*` slot (same delivery and oracle), passes the 3-arm check: ATTACK 5/5, CONTROL 0/5 with the case's control input, FIX 0/5 on the fix image. A proof against a different sink in the same file does not count. | `python bench/run.py <case>` with the tool's input |
| **fix** | The tool's patch applied to the vuln SHA builds and makes ATTACK 0/5 with the reference exploit, and also with the tool's own exploit if it produced one. In v0, CONTROL must still deliver successfully (the patch must not just break the feature). Functional regression tests per case are v1. | Harness with a patched image (v1 feature; v0 defines the rule) |
| **end-to-end** | locate + prove + fix all solved on the same case in one run. | Conjunction |

Per-stage scores are reported side by side, following CyberGym-E2E's finding that end-to-end
success is far below single-stage success. A headline number may only be end-to-end or one
named stage, never a blend.

A case's own reference proof (this repository's `inputs/attack.*`) is the **ground truth** only.
It is not a tool score.

## 3. Case format

```
bench/cases/<case-id>/
  case.json        metadata + how to build, deliver and judge (below)
  Dockerfile       builds the target at the SHA passed as build arg REPO_SHA
  inputs/attack.*  exploit input (may contain {{NONCE}})
  inputs/control.* benign input that exercises the same feature/path ({{NONCE}} required)
  driver/oracle/... small scripts the case needs (mounted read-only at /case)
  README.md        5 lines max: bug, exploit, oracle, control, fix
```

`<case-id>` = `<project>-ghsa-<first 4 chars of the GHSA middle part>` (example
`bentoml-ghsa-hvj5`). It must equal `case.json:id`. The harness finds cases by globbing
`bench/cases/*/case.json`; there is **no central index**, so adding a case means adding a folder.

`case.json` fields:

| Field | Required | Meaning |
|---|---|---|
| `schema` | yes | `"avb-case/0"` |
| `id` | yes | the directory name |
| `version` | yes | case revision, a string; bump it whenever inputs, oracle or Dockerfile change |
| `kbc_id`, `ghsa`, `cve`, `advisory_url`, `repo` | yes (cve may be null) | provenance; `kbc_id` must exist in `corpus/kbc/batches/*.jsonl` |
| `vuln_sha`, `fix_sha` | yes | 40-hex; must equal the KBC row's `sha` / `kbc.fix_sha` |
| `locator` | yes | `{file, line, symbol}` from the KBC row (the stage-1 answer key) |
| `rd_class`, `attacker`, `attacker_story` | yes | KBC class enum; KBC attacker enum; one sentence on how the attacker reaches the sink |
| `language` | yes | `python`, `typescript`, ... |
| `build` | no | `{dockerfile: "Dockerfile", sha_arg: "REPO_SHA", context: ".", args: {...}}` |
| `target` | yes | `{network: "none" | "internal", command?: [...], entrypoint?, env?: {K: "...{nonce}..."}, ready?: [...], ready_timeout?: s}`; default command `sleep infinity` |
| `deliver` | yes | `{mode: "exec" | "client", command: [...], timeout?: s}`; placeholders `{input}` (`attack`/`control`), `{nonce}`, `{target}` (the target's network alias, `target`) |
| `oracle` | yes | `{kind, command: [...], description}`; run with `docker exec` in the target after delivery; exit 0 = HIT |
| `expect` | no | override expected hits, default `{attack: 5, control: 0, fix: 0}`. v0 cases must not override. |

Delivery modes:

- `exec`: the input is delivered inside the target container (`docker exec`). Use it for
  library and stdio cases: a scripted MCP host, a scripted model feeding an agent executor,
  an app calling a library API.
- `client`: a second container from the same image joins an internal network and attacks the
  target over the network at host `target`. Use it for remote attackers (HTTP/WebSocket/RPC).
  The server binds to its own internal-network address (`--host "$(hostname -i)"` or the `target` alias), never to all interfaces.

**Scripted model.** When `attacker` is `untrusted-llm-input` (model-mediated), no real LLM runs.
The driver plays the model and emits the attacker-chosen tool call or code verbatim. That
proves the *framework* lacks a guard, independent of how gullible any model is (CHAINLAB
rule). The `attacker_story` must say which untrusted content would put that output there.

## 4. Pinning and versioning

- Source: `ADD https://codeload.github.com/<owner>/<repo>/tar.gz/${REPO_SHA}`, so the tree is the
  exact commit. The image writes `REPO_SHA` to `/opt/bench/sha`, and the harness refuses to run
  an image whose file does not equal the expected SHA (vuln for ATTACK/CONTROL, fix for FIX).
- Base images are pinned by digest (`python:3.11-slim@sha256:...`, `node:20-slim@sha256:...`).
- Dependencies: use the repo's lockfile when there is one (`npm ci`). Otherwise resolve as of a
  date just after the fix commit (`uv pip install --exclude-newer <date>`), so old trees keep
  building. Record the date in the Dockerfile comment.
- Both images come from the **same Dockerfile**, differing only in `REPO_SHA`. ATTACK and FIX
  send byte-identical input, so the only difference between them is the upstream fix.
- Benchmark version = `bench-v0.<n>`; harness version = `run.py:HARNESS_VERSION`; each result
  file records both plus the case `version` and both image IDs.

## 5. Hermeticity

- **Build time** may download base images, the source tarball and packages.
- **Run time has no egress.** Every target container runs with `--network none` (exec mode) or
  on a per-case Docker network created with `--internal` (client mode). The harness checks
  that the network reports `Internal: true` and records each container's `NetworkMode` in the
  result. Any other mode fails the case (`hermeticity_violation`).
- Every trial gets a fresh target container (no state carries over between trials or arms).
  Containers and networks are removed after each trial or case. All Docker objects are prefixed
  `pitsense_rd_bench_`.
- Containers run as a non-root user unless the bug needs root (say so in the README).
- Exploits target only the local containers. Upstream source is untrusted: it is only unpacked
  and run inside the build/run containers, never on the host.

## 6. Proof rule and result files

A case is **PROVEN** when, with 5 trials per arm: ATTACK 5/5, CONTROL 0/5, FIX 0/5, both image
SHAs verified, no harness errors and no hermeticity violation. This is PitSense's 3-arm standard.
Oracles must:

1. observe a side effect (file written, secret read back, callback received by an in-network
   listener, process state), not the exploit's own printout;
2. key on the per-trial nonce, so a stale artifact cannot cause a hit;
3. use a secret the input never contains for read-back oracles (e.g. env secret `sk-<nonce>-live`);
4. use a control that exercises the same feature, so CONTROL 0/5 shows the oracle is not
   triggered by normal use.

`python bench/run.py <case-id>|--all` writes `bench/results/<case-id>.json`: start/finish UTC
timestamps, harness and case version, image IDs and verified SHAs, network name/internal flag,
and per arm the hits, the expectation and every trial record (nonce, container network mode,
delivery exit code and tail, oracle output). It exits non-zero if any case is not PROVEN.

## 7. Scoring a tool (v0 rule; scorer script is follow-on work)

For a tool T over the N released cases:

- `locate@10(T)` = cases where stage 1 is solved / N
- `prove(T)` = cases where stage 2 is solved / N
- `fix(T)` = cases where stage 3 is solved / N
- `e2e(T)` = cases solved end to end / N
- Report all four with a per-`rd_class` and per-`attacker` breakdown, plus the tool's
  budget (wall-clock, tokens or $ per case). Same budget cap for every tool in a table.
- False positives: count findings outside the answer key, per case. Do not subtract them from
  recall. Report them as `flags per case` next to precision@10, so flag-spraying is visible.

## 8. Inclusion and exclusion

Included only if **all** hold:

- The case is a KBC row (public GHSA/CVE, published, fixed upstream, vuln and fix SHA known).
- The fix is in the advisory's repo and builds from source at both SHAs in a CPU-only container
  in under about 15 minutes.
- The 3-arm proof passes deterministically (5/0/0) in the harness.
- Attacker models are reported. `library-caller` and `untrusted-data-store` cases may be
  included but are tagged, and the headline table also shows the score without them, because a
  tool may rightly reject them under a strict threat model (PitSense's G1).

Excluded:

- Unfixed, disputed, withdrawn, or "won't fix"/"by design" advisories, and anything only
  documented as a hardening note. These **never count as true positives**.
- Any new or unpublished bug, including PitSense findings not yet public.
- Cases that need a GPU, model weights, a paid API, or a network service outside the case
  network (vLLM full builds, SGLang, hosted OAuth providers).
- Cases whose only oracle is the LLM's behaviour (no deterministic side effect).
- Advisories whose fix commit bundles many unrelated fixes, unless the sink-specific change can
  be isolated and is noted in the README.

## 9. Licence and release

Licence: case data, results, scores and documentation are CC BY 4.0 (`LICENSE-DATA`); code (harness,
scorer, adapters, Dockerfiles, drivers, oracles, exploit inputs) is Apache-2.0 (`LICENSE`). Case
Dockerfiles fetch upstream code at build time; it is not redistributed (`NOTICE`).
