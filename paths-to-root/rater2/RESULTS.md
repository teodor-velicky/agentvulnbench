# Blind second rater for the KBC path map

2026-11-25. Rater 1 = rule script `map_kbc_paths.py` -> `../kbc-path-map.csv`. Rater 2 = an LLM subagent labelling by reading each row against the codebook. Method: independent second labelling, then agreement statistics, on all 121 rows.

## Headline (reproduce: `python -I paths-to-root/rater2/kappa.py --disagreements`)

- Raw agreement **105/121 = 86.8%**.
- Cohen's kappa over 9 labels (P1-P8, none): **0.850** (chance agreement 0.120).
- Both raters place a row on a named path for 101 rows; on those they pick the **same path 98/101 = 97.0%**.
- The weak spot is the path-vs-`none` boundary: collapsed to path / none, agreement is 89.3% but **kappa is only 0.463**. Rater 1 has 10 `none`, rater 2 has 17; they agree on 7.
- Rater 2 therefore places **104 of 121** rows on a path (rater 1: 111).

## How blindness was ensured

1. `make_blind.py` reads only the KBC batch files (published here as `../kbc-snapshot/*.jsonl`) and writes `blind.jsonl` (id, repo, advisory URL, class, attacker, sink_class, file, symbol, description, notes). It never opens `kbc-path-map.csv` (`grep -c path-map make_blind.py` -> 0) and has no path/why column. Rows are sorted by id so batch order is hidden.
2. `CODEBOOK.md` is condensed from the path definitions in the authors' outline of the paper (attacker position, entry, missing guard, sink, impact) plus `none`. No row assignments, no counts.
3. A fresh subagent was given only the codebook and `blind.jsonl` and told to open nothing else (not the csv, script, paper draft or other files). That restriction is instruction-based: the subagent had general file tools, so it is enforced by the brief, not technically sandboxed.

Limits: (a) the `class` and `attacker` fields are in the blind input and are the same fields rater 1's script keys on, so the two raters are not fully independent evidence; the row descriptions are, though. (b) Rater 2 is a single LLM pass, no repeat. (c) The codebook text is derived from the same OUTLINE the thesis comes from, so agreement tests whether the definitions are applicable consistently, not whether the 8 paths are the right partition. (d) Kappa on 9 labels is inflated by the large agreeing P-classes; the `none` boundary is where the information is.

## Per-path coverage and confusion

| path | rater 1 | rater 2 | agree |
|---|---|---|---|
| P1 | 5 | 5 | 5 |
| P2 | 16 | 17 | 15 |
| P3 | 16 | 12 | 12 |
| P4 | 17 | 18 | 15 |
| P5 | 9 | 9 | 9 |
| P6 | 22 | 17 | 17 |
| P7 | 12 | 12 | 11 |
| P8 | 14 | 14 | 14 |
| none | 10 | 17 | 7 |

Confusion (rows rater 1, cols rater 2; only non-zero off-diagonal): P2->none 1; P4->P2 1; P4->none 1; P6->P2 1; P6->P7 1; P6->none 3; P7->none 1; P3->none 4; none->P4 3. Full matrix in `kappa.py` output.

## Disagreements (16)

| id | r1 | r2 | class | rater 2 reason |
|---|---|---|---|---|
| 35w5-fv47-8956 | P4 | P2 | code-injection | AST gate checks template not substituted expression; eval executes differently |
| 3r68-hf9h-887v | P6 | none | authz-bypass | tool filter only on listing not call; no host-level path |
| 4fc4-wcmh-4g86 | P6 | P7 | mcp-stdio-cmd-exec | malicious MCP server OAuth redirect drives client stdio command |
| 53gh-p8jc-7rg8 | none | P4 | code-injection | config-named module imported and executed; config trusted as code |
| 6wvf-77m9-58rm | none | P4 | template-injection | caller-supplied dotprompt rendered in unsandboxed Jinja |
| c2jp-c369-7pvx | P7 | none | oauth-confused-deputy | OAuth proxy missing consent; account takeover, no matching sink |
| fvww-7h3r-vfhp | P6 | none | authz-bypass | decorator misregistration; no host-level impact |
| g3r5-9h93-4j2c | P3 | none | command-injection | authed TOCTOU symlink in Git node clone |
| gppg-gqw8-wh9g | P4 | none | code-injection | eval of secret value from config; no model/network path |
| hf3x-42qp-4rq6 | P3 | none | path-traversal | tar member names escape staging dir; extraction not a listed path |
| hxmv-c4g6-5fqc | none | P4 | code-injection | recipe tools.py executed without opt-in; artefact trusted as code |
| jpw9-pfvf-9f58 | P6 | none | authz-bypass | session ownership authz; no host-level impact |
| v798-mcc6-2m3m | P6 | P2 | code-injection | authed user code passes validate_code which still execs |
| w66g-j6c4-hcfc | P3 | none | allowlist-bypass | project filter bypass is data-access control |
| w66g-j6c4-hcfc-b | P3 | none | allowlist-bypass | space filter bypass, same |
| wrwr-h859-xh2r | P2 | none | sandbox-escape | prototype pollution via validated-copy mismatch |

(IDs abbreviated; prefix `kbc-ghsa-`.)

## What this means for the "small set of recurring paths" thesis

- **The paths themselves are applied consistently.** When both raters place a row, they pick the same path 97% of the time. P1, P5 and P8 are unambiguous (100% agreement); P2, P4, P7 lose at most 2 rows each. The three path-to-path splits are P4/P2 (35w5), P6/P7 (4fc4) and P6/P2 (v798): a gate-vs-executor row on a loaded artefact, an MCP-server OAuth row that also reaches stdio spawn, and an authenticated user whose code passes a weak gate. Those are fuzzy boundaries on P2 (gate differential vs attacker position) and P6/P7 (network position vs malicious server).
- **The claim "111 of 121 fit" is the soft part.** Rater 2 gives 104, and the two raters agree on `none` for only 7 rows. Disagreement is not symmetric: rater 2 pushes 9 rows rater 1 put on a path to `none` (mostly P3: 4, P6: 3) and rater 1 pushes 3 rows to `none` that rater 2 puts on P4.
- **Rows rater 2 rejects fall into two groups.** (1) Authorization-logic bugs with no host-level impact (3r68, fvww, jpw9, w66g, w66g-b, and arguably c2jp): the rule script's "cell default" assignment to P6 and P3 stretched those paths beyond their definitions (P6 is about network-position trust yielding RCE/tool execution; P3 is model-chosen path args escaping a root). If rater 2 is right, the thesis's host-impact paths cover about 104 rows or fewer, and an authz/data-access cluster (about 6 rows) sits outside them. (2) Non-model-mediated path/archive/TOCTOU bugs (g3r5, hf3x) and secret-eval/prototype-pollution (gppg, wrwr), where the attacker position or sink is not in the codebook.
- **P4 boundary.** Three rows rater 1 left as `none` (53gh, 6wvf, hxmv) fit P4 under the codebook wording (artefact/config/template trusted as code); this suggests the rule script's `none` list undercounts P4 and the P4 definition is broader than "repository at rest".
- **Reading for the paper**: report kappa 0.85 and 97% same-path agreement as support that the eight definitions are applied reproducibly; replace a single-rater "111 of 121" with a range, and flag that the authz/data-access cluster and non-model-mediated archive/TOCTOU rows are the honest "none" set, with path-vs-none kappa 0.46. This is still a single LLM second rater, not independent humans. (The paper uses the reconciled figure, 105 of 121 within 101 to 114; see `../reconcile.py`.)

## Files

`make_blind.py`, `blind.jsonl`, `CODEBOOK.md`, `labels.csv` (id,path,reason), `kappa.py`.
