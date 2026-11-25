# AgentVulnBench

A "proof, not flags" benchmark for tools that find vulnerabilities **in the code of** AI agent frameworks,
MCP servers and SDKs, and model servers.

Every case is a **public, already-fixed** advisory (GitHub Security Advisory, most with a CVE), pinned to the
vulnerable commit and the fix commit, with a hermetic Docker exploit oracle. A tool is scored on whether it
**locates** the bug, **proves** it with its own exploit, and **fixes** it, stage by stage. A claimed proof or fix
is checked by running it, not by matching text.

v0 has 21 scored cases across 15 vulnerability classes and 6 attacker positions (`docs/MANIFEST.md`), plus two
cases added after the v0 scoring run. Every case is PROVEN in its committed result file.

## The three-arm oracle

Each case builds two images from one Dockerfile: the upstream repository at the **vulnerable** SHA and at the
**fix** SHA. The harness then runs three arms, 5 trials each, with a fresh container and a fresh random nonce per
trial:

| Arm | Image | Input | PROVEN requires |
|---|---|---|---|
| ATTACK | vulnerable | the exploit | **5/5** |
| CONTROL | vulnerable | a benign input that uses the same feature | **0/5** |
| FIX | fix | the byte-identical exploit | **0/5** |

The oracle reads a side effect that carries the trial's nonce (a file written, a secret read back, a request
received by an in-network listener), never the exploit's own output. CONTROL rules out an oracle that fires on
normal use; FIX shows the effect comes from the advisory's sink. Containers run with `--network none` or on a
per-case `--internal` network; both image SHAs are verified inside the image.

## Run one case

Requires Python 3.11+ (standard library only) and Docker. Case images are **deliberately vulnerable**: run them
only through the harness, which isolates them.

```
python bench/run.py --list                       # discover cases
python bench/run.py mcp-server-git-ghsa-vjqx     # build both images, run 3 arms x 5 trials
python bench/run.py --all                        # every case; exits non-zero if any case is not PROVEN
```

The result is written to `bench/results/<case>.json`. Images are tagged `pitsense_rd_bench_<case>:*`; images
download upstream source from GitHub at build time.

## Leaderboard (v0, locate stage, N = 21)

| Tool | Configuration | locate@10 | prove | fix | e2e | flags/case | precision@10 |
|---|---|---|---|---|---|---|---|
| PitSense (stub) | private engine `5ae65df`, static pipeline, deterministic stub backend, no LLM | 1/21 | 0/21 | 0/21 | 0/21 | 1.81 | 0.0256 |
| rankbase | LLM-free baseline: sink danger × entry reachability, never tuned | 1/21 | 0/21 | 0/21 | 0/21 | 8.952 | 0.0053 |
| Semgrep OSS 1.184.0 | registry packs p/python, p/javascript, p/security-audit (snapshot hash in `bench/tools/semgrep/SNAPSHOT.json`) | 0/21 | 0/21 | 0/21 | 0/21 | 5.857 | 0.0 |
| Bandit 1.9.4 | default plugins; Python only (4 TypeScript cases are misses by construction) | 0/21 | 0/21 | 0/21 | 0/21 | 8.095 | 0.0 |

Read it with the limits in mind (`docs/METHODOLOGY.md` section 9): 21 cases is small, one case moves a score by
4.8 points, and with one hit each the difference between PitSense and rankbase is not meaningful. prove, fix and
e2e are 0 for every tool by construction, because none of these tools emits an exploit or a patch. The PitSense
row is a free, LLM-free floor of its static pipeline, not the product. Pattern tools score 0 largely because many
of these bugs have no dangerous call at the sink line (missing auth, DNS-rebinding defaults, token passthrough,
OAuth confused deputy). Per-case hits, misses and exact commands: `bench/scores/v0/SCORES.md`.

Re-score any committed attempt without Docker. The v0 scores cover the 21 cases listed in
`bench/scores/v0/cases-v0.txt`; pass that list, or the scorer also counts the two later cases as misses:

```
python -I bench/scorer.py score bench/scores/v0/semgrep.attempt.json --no-docker --cases "$(cat bench/scores/v0/cases-v0.txt)" --out semgrep.json
python -I bench/tools/tables.py
python -I bench/scorer.py selftest --no-docker
```

(PowerShell: `--cases (Get-Content bench/scores/v0/cases-v0.txt)`.)

## Submit a tool's scores

1. Run your tool on each case's source tree at the vuln SHA (`python -I bench/tools/fetch_src.py` downloads
   them). Give it only the code and the case's one-line `attacker` threat statement, never `case.json`'s
   `locator` (the answer key), the advisory or the fix.
2. Write an `avb-attempt/0` file: up to 10 ranked findings per case, optionally an exploit input (`prove`) and a
   patch (`fix`). Format: `bench/SCORING.md`.
3. Score it: `python -I bench/scorer.py score my-tool.attempt.json --out my-tool.json` (add `--no-docker` for
   locate only).
4. Open a pull request adding both files under `bench/scores/v0/` with the tool version, configuration, exact
   command and budget. See `CONTRIBUTING.md`.

## What is in this repository

| Path | What |
|---|---|
| `bench/cases/` | one folder per case: `case.json` (provenance, SHAs, answer key), Dockerfile, driver, oracle, attack and control inputs |
| `bench/run.py`, `bench/scorer.py` | the 3-arm harness and the stage scorer (standard library only) |
| `bench/results/` | the committed 3-arm proof for every case |
| `bench/scores/v0/` | attempt and score files for every tool on the leaderboard |
| `bench/tools/` | adapters for Semgrep, Bandit and rankbase; source fetcher and table printer |
| `bench/SPEC.md`, `bench/SCORING.md`, `docs/METHODOLOGY.md`, `docs/MANIFEST.md` | rules, scoring, rationale and limits, case list |
| `chainlab/` | scripted-model reproductions of six public model-mediated agent bugs (the model is replaced by a deterministic fake that emits the attacker's output) |
| `paths-to-root/` | evidence, data and scripts for the paper "Paths to root for AI agents" |

The PitSense engine is not open source; only its committed attempt and score files are here.

## Citation

```bibtex
@misc{agentvulnbench2026,
  title        = {AgentVulnBench v0: a proof-based benchmark for finding vulnerabilities in AI agent, MCP and model-serving code},
  author       = {Velick{\'y}, Teodor},
  organization = {PitSense},
  year         = {2026},
  note         = {Version 0},
  howpublished = {\url{https://github.com/teodor-velicky/agentvulnbench}}
}
```

`CITATION.cff` has the same metadata for GitHub's "Cite this repository" button.

## Licence

- Code (harness, scorer, adapters, scripts, Dockerfiles, drivers, oracles and exploit inputs): Apache-2.0,
  `LICENSE`.
- Data and text (case metadata, results, scores, documentation, the paths-to-root paper and evidence): CC BY 4.0,
  `LICENSE-DATA`.
- Third-party material: `NOTICE`. Case images fetch upstream projects at build time; that code is not
  redistributed here and stays under its own licence.

Security issues with this repository: `SECURITY.md`.
