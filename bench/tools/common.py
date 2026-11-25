"""Shared helpers for AgentVulnBench v0 tool adapters (bench/tools/<tool>/adapter.py).

Each adapter scans bench/tools/.cache/src/<case-id>/ (the repo at the vuln SHA, from fetch_src.py), ranks the
tool's findings by the tool's OWN priority signals (never by distance to the answer key), maps them to an
`avb-attempt/0` locate list, and writes bench/scores/v0/<tool>.attempt.json. Adapters never read the answer key
(case.json locator / rd_class); only the scorer does.
"""
import json, re
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
CACHE = BENCH / "tools/.cache"
SCORES = BENCH / "scores/v0"
TOP_K = 10

# CWE -> AgentVulnBench rd_class (coarse; the scorer then applies its own family rule).
CWE_CLASS = {
    94: "code-injection", 95: "code-injection", 96: "code-injection", 913: "code-injection", 470: "code-injection",
    77: "command-injection", 78: "command-injection", 88: "command-injection",
    1336: "template-injection",
    502: "unsafe-deserialization",
    22: "path-traversal", 23: "path-traversal", 36: "path-traversal", 73: "path-traversal",
    918: "ssrf",
    346: "dns-rebinding", 350: "dns-rebinding", 1385: "dns-rebinding",
    285: "authz-bypass", 287: "authz-bypass", 306: "authz-bypass", 862: "authz-bypass", 863: "authz-bypass",
    639: "authz-bypass",
}


def cwe_class(cwes) -> str:
    """First CWE in the tool's list that maps to an rd_class, else 'other'."""
    if isinstance(cwes, (str, int, dict)):
        cwes = [cwes]
    for c in cwes or []:
        if isinstance(c, dict):
            c = c.get("id", "")
        m = re.search(r"CWE-(\d+)", str(c)) or re.fullmatch(r"\s*(\d+)\s*", str(c))
        if m and int(m.group(1)) in CWE_CLASS:
            return CWE_CLASS[int(m.group(1))]
    return "other"


def tool_cases():
    """Case ids plus the only inputs a tool may see (SPEC s2): language, repo, vuln SHA, one-line attacker model."""
    out = {}
    for p in sorted((BENCH / "cases").glob("*/case.json")):
        c = json.loads(p.read_text(encoding="utf-8"))
        out[c["id"]] = {"id": c["id"], "language": c["language"], "attacker": c["attacker"],
                        "repo": c["repo"], "vuln_sha": c["vuln_sha"], "src": CACHE / "src" / c["id"]}
    return out


def norm_path(p: str) -> str:
    p = str(p).replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def write_attempt(tool: str, per_case: dict, meta: dict, merge: bool = False) -> Path:
    """per_case: {case_id: {"ranked": [{file, line, class, ...}, ...], "seconds": float, "note": str}}
    merge=True (a --cases re-run) replaces only those cases in an existing attempt file."""
    SCORES.mkdir(parents=True, exist_ok=True)
    out = SCORES / f"{tool}.attempt.json"
    cases = json.loads(out.read_text(encoding="utf-8"))["cases"] if merge and out.exists() else {}
    for cid, r in sorted(per_case.items()):
        ranked = r.get("ranked", [])
        cases[cid] = {"locate": ranked[:TOP_K], "n_findings_total": len(ranked),
                      "budget": {"seconds": round(r.get("seconds", 0.0), 1), "tokens": 0, "usd": 0}}
        if r.get("note"):
            cases[cid]["note"] = r["note"]
    cases = dict(sorted(cases.items()))
    out.write_text(json.dumps({"schema": "avb-attempt/0", "tool": tool, "meta": meta, "cases": cases},
                              indent=1) + "\n", encoding="utf-8")
    return out
