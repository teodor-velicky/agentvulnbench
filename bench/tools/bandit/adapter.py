#!/usr/bin/env python
"""Bandit adapter for AgentVulnBench v0 (locate stage only; Python cases only; no exploit input or patch).

  uv venv bench/tools/.cache/venv-bandit --python 3.12
  uv pip install --python bench/tools/.cache/venv-bandit/Scripts/python.exe bandit==1.9.4
  python bench/tools/bandit/adapter.py [--cases a,b]

Runs `bandit -r . -f json -q` (all default plugins, default excludes) over the whole repo tree at the vuln SHA.
TypeScript/JavaScript cases get an empty finding list (Bandit is Python-only), so they count as misses.
Ranking (Bandit's own signals only): issue_severity HIGH > MEDIUM > LOW, then issue_confidence, then path, line,
test id. Class = issue_cwe mapped by common.CWE_CLASS, else 'other'.
"""
import argparse, json, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import CACHE, tool_cases, cwe_class, norm_path, write_attempt  # noqa: E402

BANDIT = CACHE / "venv-bandit" / ("Scripts/bandit.exe" if sys.platform == "win32" else "bin/bandit")
RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def rank_raw(res: dict) -> list:
    """Bandit -f json output -> ranked findings (also used by bench/tools/diag_anyrank.py on cached raw output)."""
    found = [{"file": norm_path(r["filename"]), "line": r["line_number"],
              "class": cwe_class([(r.get("issue_cwe") or {}).get("id", "")]),
              "rule": f"{r['test_id']}:{r['test_name']}", "severity": r["issue_severity"],
              "confidence": r["issue_confidence"]} for r in res.get("results", [])]
    found.sort(key=lambda f: (RANK.get(f["severity"], 3), RANK.get(f["confidence"], 3), f["file"], f["line"],
                              f["rule"]))
    return found


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="")
    a = ap.parse_args()
    if not BANDIT.exists():
        sys.exit(f"{BANDIT} missing; see the install lines in this file's docstring")
    ver = subprocess.run([str(BANDIT), "--version"], capture_output=True, text=True).stdout.splitlines()[0].strip()
    sel = set(filter(None, a.cases.split(",")))
    per = {}
    for cid, c in tool_cases().items():
        if sel and cid not in sel:
            continue
        if c["language"] != "python":
            per[cid] = {"ranked": [], "seconds": 0.0, "note": f"n/a: Bandit is Python-only ({c['language']} case)"}
            print(f"{cid}: skipped ({c['language']})", flush=True)
            continue
        raw = CACHE / "raw/bandit" / f"{cid}.json"
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.unlink(missing_ok=True)
        t0 = time.monotonic()
        p = subprocess.run([str(BANDIT), "-r", ".", "-f", "json", "-q", "-o", str(raw)], cwd=c["src"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        secs = time.monotonic() - t0
        if not raw.exists():  # rc 1 just means "issues found"
            sys.exit(f"{cid}: bandit failed rc={p.returncode}: {p.stderr[-800:]}")
        res = json.loads(raw.read_text(encoding="utf-8"))
        found = rank_raw(res)
        nerr = len(res.get("errors", []))
        per[cid] = {"ranked": found, "seconds": secs, "note": f"bandit rc={p.returncode}, {nerr} file errors"}
        print(f"{cid}: {len(found)} findings in {secs:.0f}s (errors={nerr})", flush=True)
    out = write_attempt("bandit", per, {"tool_version": ver, "command": "bandit -r . -f json -q",
                                        "ranking": "severity, confidence, path, line, test id"})
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
