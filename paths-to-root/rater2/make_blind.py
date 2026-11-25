"""Build the blinded rater-2 input from KBC rows only (no path / why columns).

Reads ../kbc-snapshot/*.jsonl (the 121-row KBC snapshot). Reads no first-rater mapping.
Output: rater2/blind.jsonl, sorted by id (batch order hidden).
Run: python -I paths-to-root/rater2/make_blind.py
"""
import glob, json, os, sys

here = os.path.dirname(os.path.abspath(__file__))
rows = []
for f in sorted(glob.glob(os.path.join(here, "..", "kbc-snapshot", "*.jsonl"))):
    for line in open(f, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if r.get("kind") != "positive":
            continue
        k = r.get("kbc", {})
        loc = r.get("locator", {})
        rows.append({
            "id": r["id"],
            "repo": r.get("repo"),
            "advisory_url": k.get("advisory_url") or r.get("source"),
            "class": k.get("rd_class"),
            "attacker": k.get("attacker"),
            "sink_class": loc.get("sink_class"),
            "file": loc.get("file"),
            "symbol": loc.get("symbol"),
            "description": r.get("reason"),
            "notes": k.get("notes"),
        })
rows.sort(key=lambda x: x["id"])
out = os.path.join(here, "blind.jsonl")
with open(out, "w", encoding="utf-8", newline="\n") as fh:
    for r in rows:
        fh.write(json.dumps(r, ensure_ascii=False) + "\n")
print(len(rows), "rows ->", out)
