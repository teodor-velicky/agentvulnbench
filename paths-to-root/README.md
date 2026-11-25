# paths-to-root

Evidence, data and reproduction scripts for **"Paths to root for AI agents: eight recurring routes from
untrusted input to host impact"** (PitSense, Teodor Velický). Canonical page:
https://pitsense.io/research/paths-to-root/.

| File | What it is |
|---|---|
| `PAPER.md` | The paper |
| `EVIDENCE.md` | One row per factual or numeric claim, keyed by the paper's `[E<n>]` tags |
| `kbc-snapshot/` | The 121-row Known-Bug Corpus snapshot (four JSONL batches of public, fixed advisories, each pinned to a vulnerable and a fixed commit) |
| `map_kbc_paths.py`, `kbc-path-map.csv` | Rater 1: rule-based row-to-path map |
| `rater2/` | Rater 2: codebook, blinded input, labels, agreement script and notes |
| `reconcile.py`, `reconciled-path-map.csv` | Reconciled two-rater map used for every per-path count |
| `kbc-e-oos/RESULTS.md` | Out-of-sample check on 32 held-out rows (aggregate only) |

Reproduce from the folder that contains `paths-to-root/` (Python 3, standard library only):

```
python -I paths-to-root/map_kbc_paths.py
python -I paths-to-root/rater2/kappa.py --disagreements
python -I paths-to-root/reconcile.py
```

Licence: text and evidence tables CC BY 4.0; scripts Apache-2.0. Advisory summaries quoted from the
GitHub Advisory Database remain under its CC BY 4.0 licence.
