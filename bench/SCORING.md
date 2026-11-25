# AgentVulnBench v0: scoring a tool

`bench/scorer.py` implements `SPEC.md` section 2 (stages) and section 7 (aggregation). Stdlib only, run it
with `python -I`. It imports `bench/run.py` unchanged for image builds and the nonce/side-effect oracle.
Docker policy: images are `pitsense_rd_bench_*`; the scorer refuses to build with < 80 GB free on C:.

## Attempt file (`avb-attempt/0`)

```json
{"schema": "avb-attempt/0", "tool": "my-tool",
 "cases": {"<case-id>": {
   "locate": [{"file": "repo/relative/path.py", "line": 123, "class": "code-injection"}],
   "prove":  {"input": "<exploit; may contain {{NONCE}}>"},
   "fix":    {"patch": "<unified diff, repo-relative paths, a/ b/ prefixes optional>"},
   "budget": {"seconds": 0, "tokens": 0, "usd": 0}}}}
```

- `locate`: ordered findings (best first); only the first 10 count (SPEC k = 10).
- `prove.input` (or `prove.input_file`): replaces the case's `inputs/attack.*` slot, so it must be in that
  case's input format (see the case's reference input). Delivery, oracle and control are the case's own.
- `fix.patch`: unified diff against the vuln-SHA tree (paths like `libs/agno/agno/models/base.py`).
  Alternative `fix.files`: `{"path": "full new content"}`. Only files under `/src` of the image can be patched;
  deleting files is not supported in v0.
- Missing stage or case = not solved. `budget` is recorded, never scored.

## Stage rules (as implemented)

| Stage | Solved when |
|---|---|
| locate | one of the first 10 findings has `file == locator.file`, `abs(line - locator.line) <= 25`, and a class compatible with `rd_class` (equal, or same family: code/command/template injection, stdio-cmd-exec, sandbox-escape, prompt-injection-to-tool; path-traversal + allowlist-bypass; authz-bypass, oauth-confused-deputy, token-passthrough; ssrf + dns-rebinding) |
| prove | with the tool's input in the attack slot: ATTACK n/n on the vuln image, CONTROL 0/n (case control), FIX 0/n on the fix image, no harness error, no hermeticity violation (n = `--trials`, default 5) |
| fix | patched image builds, `/opt/bench/sha` still equals the vuln SHA, ATTACK 0/n with the reference exploit (and with the tool's own `prove.input` if present), CONTROL still delivers (exit 0, no error, oracle 0 hits) |
| e2e | locate and prove and fix |

## Patched-image mode

`python -I bench/scorer.py fix <case-id> --patch FILE.diff [--own-exploit FILE] [--keep]` (or `--files JSON`).
The patch is resolved into full file contents by applying it to the vuln-image's `/src` copy; those files are
overlaid into `/src` right after the case Dockerfile unpacks the tarball (one inserted `COPY` plus
`cp -a /avb_overlay/. /src/`), so the case's own install/build steps run on the patched tree. The tag is
`pitsense_rd_bench_<case>:patched_<hash>`, removed afterwards unless `--keep`. Result:
`bench/results/scorer/<case-id>.fix.json`. Exit status 0 = fix stage solved. The case Dockerfile must follow the
SPEC s4 pattern (`ADD ... /tmp/src.tgz`, `rm /tmp/src.tgz`), as all current cases do.

## Commands

```
python -I bench/scorer.py score ATTEMPT.json [--cases a,b] [--no-docker] [--out score.json]
python -I bench/scorer.py fix agno-ghsa-m4w4 --patch bench/selftest/fixes/agno-ghsa-m4w4.diff
python -I bench/scorer.py selftest [--cases a,b] [--no-docker]     # ~10-15 min with docker, seconds with --no-docker
```

`--no-docker` scores locate only; prove/fix/e2e are reported as `null` (not scored), never as failures.

## Output (`avb-score/0`)

`per_case[]`: `locate{solved, matching_ranks, findings_considered, flags_outside_key}`, `prove{solved, arms}`,
`fix{solved, checks, arms}`, `e2e`, `case_score`. `aggregate`: `overall`, `by_rd_class`, `by_attacker`, each with
`locate@10 / prove / fix / e2e` as fractions of the cases scored, plus `noise{flags_per_case, precision@10}`
reported beside recall, never subtracted from it (SPEC s7). As computed: flags_per_case = (findings considered − located cases) / N and precision@10 = located cases / findings considered (per located case, first 10 findings per case). A rate is `null` if any case in the group was not scored.

## Self-test

`selftest` runs three attempts over all cases: **reference** (answer-key locate + the case's reference exploit +
hand-written patches in `bench/selftest/fixes/<case>.diff`; this is ground truth, not a tool score), **garbage**
(wrong file, junk findings, a benign "exploit", a non-diff patch) and **empty**. It passes when the reference
solves locate+prove on >= 2 cases and at least one fix, and garbage/empty solve nothing. Output:
`bench/selftest/selftest-result.json` (+ `.detail.json`).
