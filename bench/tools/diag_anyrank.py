#!/usr/bin/env python
"""Diagnostic, NOT a score: where (if anywhere) does each tool's FULL ranked list touch the answer key?

  python -I bench/tools/diag_anyrank.py            # needs the cached raw outputs from the adapters

For every case and tool it re-ranks the cached raw tool output with the adapter's own rank_raw() and reports
  rank   1-based rank of the first finding the scorer's locate rule accepts (file, +-25 lines, class family);
         a rank > 10 means the tool did flag the sink but below the k=10 cap
  near   1-based rank of the first finding in the right file within +-25 lines, ANY class (class-map sensitivity)
  total  number of findings the tool produced for the case
Writes bench/scores/v0/diag_anyrank.json. Uses scorer.class_compatible / LINE_TOLERANCE so the rule is identical.
"""
import importlib.util, json, sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
BENCH = TOOLS.parent
sys.path.insert(0, str(BENCH))
sys.path.insert(0, str(TOOLS))
import scorer  # noqa: E402
from common import CACHE, SCORES  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(f"adapter_{name}", TOOLS / name / "adapter.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def full_lists(cid):
    out = {}
    raw = CACHE / "raw/pitsense" / cid
    if (raw / "surface_map.json").exists():
        sm = json.loads((raw / "surface_map.json").read_text(encoding="utf-8"))
        led = json.loads((raw / "triage_ledger.json").read_text(encoding="utf-8"))
        out["pitsense-surface"], out["pitsense"] = load("pitsense").rank_raw(sm, led)
    for t in ("semgrep", "bandit"):
        p = CACHE / f"raw/{t}" / f"{cid}.json"
        out[t] = load(t).rank_raw(json.loads(p.read_text(encoding="utf-8"))) if p.exists() else None
    from common import tool_cases
    c = tool_cases()[cid]  # rankbase has no raw file: it is stdlib-fast, so re-run its scan() for the full list
    out["rankbase"] = load("rankbase").scan(c["src"], c["language"])
    return out


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    rows = {}
    for cdir in sorted((BENCH / "cases").glob("*/case.json")):
        case = json.loads(cdir.read_text(encoding="utf-8"))
        loc = case["locator"]
        rows[case["id"]] = r = {}
        for tool, lst in full_lists(case["id"]).items():
            if lst is None:
                r[tool] = {"rank": None, "near": None, "total": 0, "note": "no raw output (tool not applicable)"}
                continue
            rank = near = None
            near_f = None
            for i, f in enumerate(lst, 1):
                if f["file"] == loc["file"] and abs(int(f["line"]) - int(loc["line"])) <= scorer.LINE_TOLERANCE:
                    if near is None:
                        near, near_f = i, f
                    if rank is None and scorer.class_compatible(f["class"], case["rd_class"]):
                        rank = i
            r[tool] = {"rank": rank, "near": near, "total": len(lst),
                       "near_finding": {k: near_f.get(k) for k in ("line", "class", "rule", "engine_class", "verdict")
                                        if k in near_f} if near_f else None}
    (SCORES / "diag_anyrank.json").write_text(json.dumps(rows, indent=1) + "\n", encoding="utf-8")
    tools = ["pitsense", "pitsense-surface", "semgrep", "bandit", "rankbase"]
    print("case | " + " | ".join(f"{t} rank/near/total" for t in tools))
    for cid, r in rows.items():
        print(cid + " | " + " | ".join(
            f"{r.get(t, {}).get('rank')}/{r.get(t, {}).get('near')}/{r.get(t, {}).get('total')}" for t in tools))


if __name__ == "__main__":
    main()
