#!/usr/bin/env python
"""Semgrep OSS adapter for AgentVulnBench v0 (locate stage only; Semgrep emits no exploit input or patch).

  python bench/tools/semgrep/adapter.py [--cases a,b] [--jobs 2] [--refresh-rules]

Rules: snapshots of the public registry packs p/python, p/javascript (byte-identical to p/typescript) and
p/security-audit in bench/tools/.cache/semgrep-rules/, checked against the sha256s in SNAPSHOT.json. The rule YAML
is under the Semgrep Rules License, so it is not committed; --refresh-rules re-downloads and records new hashes.
Scans the whole repo tree at the vuln SHA with Semgrep's default .semgrepignore (but --no-git-ignore, because the cache sits
inside this git repo's ignored .cache/), --metrics=off.
Ranking (Semgrep's own signals only): severity ERROR > WARNING > INFO, then metadata.confidence HIGH > MEDIUM > LOW,
then path, line, rule id. Class = first CWE in the rule metadata that common.CWE_CLASS maps, else 'other'.
"""
import argparse, hashlib, json, subprocess, sys, time, urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import CACHE, tool_cases, cwe_class, norm_path, write_attempt  # noqa: E402

HERE = Path(__file__).resolve().parent
RULES = CACHE / "semgrep-rules"
PACKS = {"python": ["p-python.yaml", "p-security-audit.yaml"],
         "typescript": ["p-javascript.yaml", "p-security-audit.yaml"],
         "javascript": ["p-javascript.yaml", "p-security-audit.yaml"]}
SEV = {"ERROR": 0, "WARNING": 1, "INFO": 2}
CONF = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check_rules(refresh):
    snap = HERE / "SNAPSHOT.json"
    want = json.loads(snap.read_text()) if snap.exists() else {}
    if refresh or not want:
        RULES.mkdir(parents=True, exist_ok=True)
        if refresh or not list(RULES.glob("p-*.yaml")):
            for p in ("python", "javascript", "typescript", "security-audit"):
                with urllib.request.urlopen(f"https://semgrep.dev/c/p/{p}", timeout=120) as r:
                    (RULES / f"p-{p}.yaml").write_bytes(r.read())
        want = {"fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source": "https://semgrep.dev/c/p/<pack>",
                "sha256": {f.name: sha(f) for f in sorted(RULES.glob("p-*.yaml"))}}
        snap.write_text(json.dumps(want, indent=1) + "\n")
    for name, h in want["sha256"].items():
        if not (RULES / name).exists() or sha(RULES / name) != h:
            sys.exit(f"rule snapshot {name} missing or not matching SNAPSHOT.json (registry packs change over time)")
    return want


def rule_id(check_id: str) -> str:
    """Local config files prefix the registry id with their own path; keep only the registry id."""
    return check_id.split("semgrep-rules.", 1)[-1]


def rank_raw(res: dict) -> list:
    """Semgrep --json output -> ranked findings (also used by bench/tools/diag_anyrank.py on cached raw output)."""
    found = []
    for r in res.get("results", []):
        md = r.get("extra", {}).get("metadata", {})
        found.append({"file": norm_path(r["path"]), "line": r["start"]["line"], "class": cwe_class(md.get("cwe")),
                      "rule": rule_id(r["check_id"]), "severity": r["extra"].get("severity"),
                      "confidence": md.get("confidence")})
    found.sort(key=lambda f: (SEV.get(f["severity"], 3), CONF.get(str(f["confidence"]).upper(), 3),
                              f["file"], f["line"], f["rule"]))
    return found


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--refresh-rules", action="store_true")
    ap.add_argument("--src-root", default=None,
                    help="scan <src-root>/<case-id> instead of the cache. Windows: semgrep-core cannot open paths over "
                         "260 chars (langflow, llama-index fail with 'Failed to obtain target files'), so copy those "
                         "trees to a short real path (a junction does not help) and pass it here")
    ap.add_argument("--from-raw", action="store_true",
                    help="do not scan: rebuild the attempt from cached raw output (keeps recorded seconds/notes)")
    a = ap.parse_args()
    snap = check_rules(a.refresh_rules)
    if a.from_raw:
        old = json.loads((HERE.parents[1] / "scores/v0/semgrep.attempt.json").read_text(encoding="utf-8"))
        per = {cid: {"ranked": rank_raw(json.loads((CACHE / "raw/semgrep" / f"{cid}.json").read_text(encoding="utf-8"))),
                     "seconds": v["budget"]["seconds"], "note": v.get("note", "")} for cid, v in old["cases"].items()}
        print(f"wrote {write_attempt('semgrep', per, old['meta'])}")
        return
    ver = subprocess.run(["semgrep", "--version"], capture_output=True, text=True).stdout.strip().splitlines()[-1]
    sel = set(filter(None, a.cases.split(",")))
    per = {}
    for cid, c in tool_cases().items():
        if sel and cid not in sel:
            continue
        if a.src_root:
            c["src"] = Path(a.src_root) / cid
        raw = CACHE / "raw/semgrep" / f"{cid}.json"
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.unlink(missing_ok=True)
        cmd = ["semgrep", "scan", "--metrics=off", "--disable-version-check", "--json", "--quiet", "--no-git-ignore",
               "--timeout", "30", "--jobs", str(a.jobs), "--output", str(raw)]
        for r in PACKS[c["language"]]:
            cmd += ["--config", str(RULES / r)]
        cmd.append(".")
        t0 = time.monotonic()
        p = subprocess.run(cmd, cwd=c["src"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        secs = time.monotonic() - t0
        if not raw.exists():
            sys.exit(f"{cid}: semgrep failed rc={p.returncode}: {p.stderr[-800:]}")
        res = json.loads(raw.read_text(encoding="utf-8"))
        if p.returncode == 2 or not res.get("paths", {}).get("scanned"):
            sys.exit(f"{cid}: semgrep scanned no targets (rc={p.returncode}): "
                     f"{[e.get('message') for e in res.get('errors', [])][:2]}; see --src-root")
        found = rank_raw(res)
        nerr = len(res.get("errors", []))
        per[cid] = {"ranked": found, "seconds": secs, "note": f"semgrep rc={p.returncode}, {nerr} scan errors"}
        print(f"{cid}: {len(found)} findings in {secs:.0f}s (rc={p.returncode}, errors={nerr})", flush=True)
    out = write_attempt("semgrep", per, {"tool_version": f"semgrep {ver} (OSS CLI)", "rules": snap,
                                         "packs": PACKS, "ranking": "severity, confidence, path, line, rule"},
                        merge=bool(sel))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
