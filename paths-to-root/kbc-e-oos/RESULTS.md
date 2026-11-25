# Out-of-sample check: the eight paths on 30 held-out rows

Date: 2026-11-25. The eight paths were named from the 121-row Known-Bug Corpus (KBC) snapshot, so the
in-sample coverage of 105 of 121 (86.8%) measures how well the paths fit the data they came from. This
folder reports the out-of-sample test. The same mapping method is applied, with the path definitions
unchanged, to KBC-E, a fifth batch of 32 rows built after the paths were written.

Two of the 32 rows are **excluded**. Both are sinks of one advisory that the paper already uses as a Path
1 worked example and reproduction, so they are not out of sample. We matched every KBC-E advisory id
against the paper's drafts, outline, evidence map, benchmark cases and reproductions, and no other row
matched. The test set is therefore **30 rows**.

## Headline

**20 of 30 held-out rows (66.7%) fall on one of the eight paths** after reconciliation, against 105 of
121 (86.8%) in sample. Counting the two excluded rows, both of which land on Path 1, the figure on
all 32 KBC-E rows would be 22 of 32 (68.8%); we do not use it, because those two rows are in sample.

| Bound | Rows on a path |
|---|---|
| Both raters place the row on a path | 16 |
| Reconciled | **20** |
| Flipping all 8 contested calls the other way | 19 to 26 |
| Either rater places the row on a path | 27 |
| The four contested shell / package-manager rows counted as Path 1 | 24 |

## Method (same three steps as the 121-row map)

1. **Rater 1, rules, frozen.** We used the (class, attacker) cell table and the library-caller exclusion
   of `../map_kbc_paths.py` exactly as committed for the 121-row map, with no new cells and no new
   per-row overrides. A row whose cell has no rule is recorded as on no path. This happened for 9 of the
   30 rows. Eight of those 9 are in (class, attacker) cells that never occur in the 121-row snapshot: 7
   command injection (6 of them by a model-mediated attacker) and 1 SQL injection.
2. **Rater 2, blind.** A fresh LLM pass was given only `../rater2/CODEBOOK.md` and a blinded copy of the
   32 rows (id, repository, advisory, class, attacker, sink class, file, symbol, description; no path
   column; sorted by id). As in sample, it was restricted to those two files by instruction, not by a
   technical sandbox. The two excluded rows were dropped after labelling.
3. **Reconciliation.** For the 12 rows on which the raters differ, a third pass adopted one label. This
   pass saw both labels, so it is not blind. It applied the path definitions as written in the paper and
   followed the in-sample reconciliation where the same question had come up before. Eight of the 12
   calls are marked contested.

## Per-path counts (30 rows)

| Path | Rater 1 (frozen rules) | Rater 2 (blind) | Reconciled |
|---|---|---|---|
| P1 Model output into an interpreter | 1 | 5 | 1 |
| P2 Hand-rolled gate parses differently from the executor | 1 | 3 | 3 |
| P3 Model-chosen tool argument escapes confinement | 0 | 0 | 0 |
| P4 Repository or artefact at rest trusted as code | 0 | 1 | 1 |
| P5 Serialized object crosses a trust boundary | 3 | 3 | 3 |
| P6 Control plane trusts its network position | 0 | 1 | 1 |
| P7 Malicious MCP server makes the client a confused deputy | 1 | 0 | 1 |
| P8 Fetch guard lets an attacker URL into the internal network | 10 | 14 | 10 |
| none | 14 | 3 | 10 |
| **On a path** | **16** | **27** | **20** |

Agreement: the raters give the same label to 18 of 30 rows. Where both place a row on a path, they pick
the same path for 15 of 16; the one split is between P7 (entry) and P8 (guard and sink). Cohen's kappa
over the 9 labels is 0.486. That is not comparable to the in-sample 0.850, because the frozen rule table
has no cell for 9 of the rows.

## The 10 rows on no path

| Group | Rows | Shape |
|---|---|---|
| Model-chosen tool argument into a shell or package-manager command (contested) | 4 | Tool parameters spliced into a shell command line (3), or into a package-manager command (1). Path 1's written sink is `exec`, `eval` or a subprocess running Python, so a shell command is outside it. Under a broad reading of "interpreter" all four would be Path 1 |
| Option (flag) injection into a CLI by a model-chosen argument | 1 | A tool argument becomes a CLI argument without rejecting a leading `-`, so it is read as an option. No interpreter, gate or confinement sink in any path |
| `library-caller` SSRF | 3 | A URL fetch inside a library, reached only through the embedding application's own arguments or configuration. Two are contested (P8 if the application passes an attacker URL through) |
| `library-caller` option injection | 1 | A caller-supplied value passed as a separate CLI argument, so a leading `-` becomes an option. Both raters: no path |
| SQL injection by an authenticated user | 1 | Both raters: no path |

## Reading

- **The held-out rows fit worse than the corpus the paths came from:** 20 of 30 (66.7%) against 105 of
  121 (86.8%). Some drop is expected for any taxonomy that was named in sample. Much of the rest is one
  shape.
- **Half of the 10 rows on no path share one shape.** In five rows, a model-chosen tool argument reaches
  a shell or CLI command line, either as shell syntax or as an option flag. Counting the library-caller
  option injection, six of the ten rows inject into a command line. This shape does not occur in the
  121-row snapshot. The eight paths, as written, have no place for it: Path 1 stops at Python
  interpreters, Path 2 needs a gate, and Path 3 is about file and repository confinement. It is a
  candidate for a widened Path 1 or a ninth path. We report it as a gap and did not change any definition
  to absorb it.
- **Where both raters place a row on a path, they almost always pick the same path** (15 of 16). This
  matches the in-sample result (98 of 101).
- **The batch is not a random sample.** KBC-E rows were drawn from advisories with command-injection,
  SSRF, code-execution and deserialization keywords, so the per-path counts reflect that selection (14
  of the 30 rows are SSRF). Paths 3, 6 and 7 are under-represented by construction, and this test says
  little about them.

## Files

The per-row map, the blind input and the rater-2 labels are kept private, together with the KBC-E rows
themselves. KBC-E is also the held-out set for engine evaluation, and publishing it would spoil that use.
This page gives the aggregate result only. The method and scripts are the same as for the public 121-row
map in this folder's parent (`../map_kbc_paths.py`, `../rater2/`, `../reconcile.py`).
