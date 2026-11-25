#!/usr/bin/env python
"""Print the SCORES.md tables from bench/scores/v0/<tool>.json (scorer output) and diag_anyrank.json.

  python -I bench/tools/tables.py
"""
import json, sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
V0 = Path(sys.argv[1]) if len(sys.argv) > 1 else BENCH / "scores/v0"  # arg: dir holding the 14-case copies
TOOLS = ["pitsense", "semgrep", "bandit", "rankbase", "pitsense-surface"]


def pct(n, d):
    return f"{n}/{d} = {n / d:.3f}" if d else "n/a"


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sc = {t: json.loads((V0 / f"{t}.json").read_text(encoding="utf-8")) for t in TOOLS}
    at = {t: json.loads((V0 / f"{t}.attempt.json").read_text(encoding="utf-8")) for t in TOOLS}
    diag = json.loads((V0 / "diag_anyrank.json").read_text(encoding="utf-8"))
    cases = {json.loads(p.read_text(encoding="utf-8"))["id"]: json.loads(p.read_text(encoding="utf-8"))
             for p in sorted((BENCH / "cases").glob("*/case.json"))}
    cases = {k: v for k, v in cases.items() if k in diag}  # v0 scored set (see bench/scores/v0/cases-v0.txt)
    n = len(cases)
    print("| Tool | locate@10 | prove | fix | e2e | flags/case | precision@10 | sink anywhere in full list | wall s/case (median) | $ |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for t in TOOLS:
        s = sc[t]
        solved = sum(p["locate"]["solved"] for p in s["per_case"])
        anyr = sum(1 for c in cases if diag[c].get(t, {}).get("rank"))
        secs = sorted(c["budget"]["seconds"] for c in at[t]["cases"].values())
        med = secs[len(secs) // 2] if secs else 0
        no = s["aggregate"]["noise"]
        print(f"| {t} | {pct(solved, n)} | 0/{n} (n/a) | 0/{n} (n/a) | 0/{n} | {no['flags_per_case']} | "
              f"{no['precision@10']} | {anyr}/{n} | {med:.0f} | 0 |")
    old = V0 / "v0-14case/pitsense.attempt.json"
    if old.exists():
        b14 = set(json.loads(old.read_text(encoding="utf-8"))["cases"])
        print()
        print(f"Original {len(b14)} cases only (same scorer, current tool runs): " + "; ".join(
            f"{t} {sum(p['locate']['solved'] for p in sc[t]['per_case'] if p['case'] in b14)}/{len(b14)}" for t in TOOLS))
    print()
    print("| Case | lang | rd_class | " + " | ".join(TOOLS) + " |")
    print("|---|---|---|" + "---|" * len(TOOLS))
    for cid, case in cases.items():
        cells = []
        for t in TOOLS:
            p = next(x for x in sc[t]["per_case"] if x["case"] == cid)
            d = diag[cid].get(t, {})
            tot = at[t]["cases"].get(cid, {}).get("n_findings_total", 0)
            if p["locate"]["solved"]:
                cells.append(f"**HIT** @{p['locate']['matching_ranks'][0] + 1} ({tot})")
            elif d.get("rank"):
                cells.append(f"miss, flagged @{d['rank']} ({tot})")
            elif d.get("near"):
                cells.append(f"miss, near @{d['near']} wrong class ({tot})")
            else:
                cells.append(f"miss ({tot})")
        print(f"| {cid} | {case['language']} | {case['rd_class']} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
