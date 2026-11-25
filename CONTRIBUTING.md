# Contributing

Two kinds of contribution are welcome: new cases, and scores for a tool. Open a pull request; keep one case or
one tool per pull request.

## Ground rules

- **Public, already-fixed advisories only.** A case must be a published advisory (GHSA, with a CVE if one was
  assigned) whose fix is in a released version. No unfixed, disputed, withdrawn, "won't fix" or embargoed bugs,
  and no new findings: report those to the upstream project first (`SECURITY.md`).
- **Proof, not flags.** A case is accepted only when the three-arm oracle passes deterministically:
  ATTACK 5/5, CONTROL 0/5, FIX 0/5, both image SHAs verified, no harness error.
- No secrets, personal data or machine-specific paths in committed files. Per-trial secrets are generated at run
  time from the nonce.

## Adding a case

The full format is `bench/SPEC.md` (sections 3 to 8). In short:

1. Pick a public fixed advisory in AI agent, MCP or model-serving code. Find the fix commit and its parent (the
   vuln SHA). The fix should isolate the sink; the build must run on CPU in about 15 minutes, with no GPU, model
   weights, paid API or outside network service.
2. Create `bench/cases/<project>-ghsa-<first4>/` with:
   - `case.json` (`avb-case/0`): provenance (`ghsa`, `cve`, `advisory_url`, `repo`, `vuln_sha`, `fix_sha`),
     `locator` (file, line, symbol of the sink), `rd_class`, `attacker`, `attacker_story`, `build`, `target`,
     `deliver`, `oracle`. Copy an existing case as the template.
   - `Dockerfile`: base image pinned by digest; `ADD https://codeload.github.com/<owner>/<repo>/tar.gz/${REPO_SHA}`,
     unpack to `/src`, install, and write the SHA to `/opt/bench/sha`. One Dockerfile builds both SHAs.
   - a driver that delivers `inputs/<arm>.*` the way the attacker would, and an `oracle` that checks a side effect
     carrying the nonce (never the exploit's own output).
   - `inputs/attack.*` and `inputs/control.*` (control = benign use of the same feature).
   - `README.md`: one paragraph on what the exploit does and what the oracle observes. Describe only the fixed bug.
3. Run `python bench/run.py <case-id>` and commit `bench/results/<case-id>.json`. It must say `PROVEN`.
4. Bump the case's `version` on any change to inputs, Dockerfile, driver or oracle, and re-run.

New cases are not part of the v0 scores; they enter the next versioned score set.

## Scoring a tool

1. `python -I bench/tools/fetch_src.py` downloads each case's tree at the vuln SHA into `bench/tools/.cache/src/`.
2. Run the tool on those trees. It may see the code and the case's one-line `attacker` statement; it must not see
   `case.json` `locator` (the answer key), the advisory, git history past the vuln SHA or the fix.
3. Write `bench/scores/v0/<tool>.attempt.json` in the `avb-attempt/0` format (`bench/SCORING.md`): up to 10 ranked
   findings per case; optional `prove` input and `fix` patch; the budget used.
4. Score: `python -I bench/scorer.py score bench/scores/v0/<tool>.attempt.json --out bench/scores/v0/<tool>.json`
   (Docker needed for prove and fix; `--no-docker` scores locate only and reports prove/fix as not scored).
5. In the pull request, state the tool name and version, its configuration, the exact commands, whether an LLM was
   used (model and version), and the budget. If you add an adapter under `bench/tools/<tool>/`, it must never read
   `case.json`.

Score files are accepted as submitted; we re-run the scorer on the attempt file and may re-run the tool where it
is freely available.

## Licence of contributions

By contributing you agree that code is licensed under Apache-2.0 (`LICENSE`) and data and text under CC BY 4.0
(`LICENSE-DATA`).
