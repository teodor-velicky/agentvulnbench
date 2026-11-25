#!/usr/bin/env python
"""Fetch every bench case's full repository tree at its vuln SHA (GitHub codeload tarball) for static tools.

  python -I bench/tools/fetch_src.py [--cases a,b]

Output: bench/tools/.cache/src/<case-id>/ (gitignored via `.cache/`), plus .cache/src/<case-id>.manifest.json
(committed roll-up of the manifests used for v0 scores: bench/tools/src-manifest.json)
(tarball sha256, member counts, members skipped because they cannot exist on this filesystem).
Per SPEC s2 the tool gets the repo at the vuln SHA only: no .git, no history, no advisory.
Downloads are untrusted data: extracted with tarfile filter='data', never executed.
"""
import argparse, hashlib, json, sys, tarfile, urllib.request
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
CACHE = BENCH / "tools/.cache"


def cases(sel=None):
    out = {}
    for p in sorted((BENCH / "cases").glob("*/case.json")):
        c = json.loads(p.read_text(encoding="utf-8"))
        if not sel or c["id"] in sel:
            out[c["id"]] = c
    return out


def fetch(c):
    dest = CACHE / "src" / c["id"]
    man = CACHE / "src" / f"{c['id']}.manifest.json"
    if man.exists() and dest.is_dir():
        return json.loads(man.read_text())
    owner_repo = c["repo"].rstrip("/").split("github.com/")[1]
    url = f"https://codeload.github.com/{owner_repo}/tar.gz/{c['vuln_sha']}"
    tgz = CACHE / "tgz" / f"{c['id']}.tgz"
    tgz.parent.mkdir(parents=True, exist_ok=True)
    if not tgz.exists():
        print(f"  download {url}", flush=True)
        with urllib.request.urlopen(url, timeout=600) as r, open(str(tgz) + ".part", "wb") as fh:
            while chunk := r.read(1 << 20):
                fh.write(chunk)
        Path(str(tgz) + ".part").replace(tgz)
    h = hashlib.sha256(tgz.read_bytes()).hexdigest()
    dest.mkdir(parents=True, exist_ok=True)
    n = skipped = 0
    skipped_names = []
    with tarfile.open(tgz) as tf:
        for m in tf:
            parts = m.name.split("/", 1)
            if len(parts) < 2 or not parts[1]:
                continue
            m.name = parts[1]
            if not (m.isfile() or m.isdir()):
                continue  # symlinks/devices are irrelevant to static scanning
            try:
                tf.extract(m, dest, filter="data")
                n += 1
            except Exception as exc:  # names illegal on Windows, over-long paths
                skipped += 1
                if len(skipped_names) < 20:
                    skipped_names.append(f"{m.name}: {type(exc).__name__}")
    info = {"case": c["id"], "url": url, "vuln_sha": c["vuln_sha"], "tarball_sha256": h,
            "extracted": n, "skipped": skipped, "skipped_sample": skipped_names,
            "locator_present": (dest / c["locator"]["file"]).is_file()}
    man.write_text(json.dumps(info, indent=2))
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="")
    a = ap.parse_args()
    for cid, c in cases(set(filter(None, a.cases.split(",")))).items():
        i = fetch(c)
        print(f"{cid}: extracted={i['extracted']} skipped={i['skipped']} locator_present={i['locator_present']}", flush=True)
        if not i["locator_present"]:
            sys.exit(f"{cid}: locator file missing after extraction")


if __name__ == "__main__":
    main()
