#!/usr/bin/env python3
"""AgentVulnBench v0 reproduce harness: 3-arm Docker proof per case.

    python bench/run.py --all            # every case under bench/cases/*/case.json
    python bench/run.py <case-id> [...]  # one or more cases
    python bench/run.py --list           # list discovered cases

For each case it builds two images from the case Dockerfile (vuln SHA and fix SHA,
tags pitsense_rd_bench_<case>:vuln / :fix), checks that each image really holds the
pinned SHA, then runs ATTACK (exploit on vuln), CONTROL (benign input on vuln) and
FIX (exploit on fix) N times each. Every trial gets a fresh target container and a
fresh random nonce. At run time containers have no egress: `--network none`, or an
`--internal` Docker network for client/server cases. Results go to
bench/results/<case>.json. Exit status is non-zero if any case misses its
expectation (default ATTACK N/N, CONTROL 0/N, FIX 0/N).

Stdlib only; needs the docker CLI. See bench/SPEC.md for the case format.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

BENCH = Path(__file__).resolve().parent
CASES = BENCH / "cases"
RESULTS = BENCH / "results"
PREFIX = "pitsense_rd_bench_"
HARNESS_VERSION = "0.1.0"
SHA_FILE = "/opt/bench/sha"  # every case image must write the checked-out SHA here
ARMS = (  # arm, image variant, input name
    ("attack", "vuln", "attack"),
    ("control", "vuln", "control"),
    ("fix", "fix", "attack"),
)


def sh(cmd: list[str], timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(cmd)}\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}")
    return p


def discover() -> dict[str, Path]:
    found = {}
    for cj in sorted(CASES.glob("*/case.json")):
        found[cj.parent.name] = cj.parent
    return found


def load_case(d: Path) -> dict:
    c = json.loads((d / "case.json").read_text(encoding="utf-8"))
    for k in ("id", "kbc_id", "advisory_url", "repo", "vuln_sha", "fix_sha", "rd_class", "attacker", "target", "deliver", "oracle"):
        if k not in c:
            raise ValueError(f"{d.name}/case.json: missing field {k!r}")
    if c["id"] != d.name:
        raise ValueError(f"{d.name}/case.json: id {c['id']!r} must equal the directory name")
    if c["target"].get("network", "none") not in ("none", "internal"):
        raise ValueError(f"{d.name}: target.network must be 'none' or 'internal'")
    if c["deliver"].get("mode", "exec") not in ("exec", "client"):
        raise ValueError(f"{d.name}: deliver.mode must be 'exec' or 'client'")
    return c


def subst(args: list[str], **kw: str) -> list[str]:
    out = []
    for a in args:
        for k, v in kw.items():
            a = a.replace("{" + k + "}", v)
        out.append(a)
    return out


def log(msg: str) -> None:
    print(msg, flush=True)


def build(case: dict, d: Path, variant: str, no_cache: bool) -> dict:
    sha = case["vuln_sha"] if variant == "vuln" else case["fix_sha"]
    tag = f"{PREFIX}{case['id']}:{variant}"
    b = case.get("build", {})
    cmd = ["docker", "build", "-q", "-t", tag, "-f", str(d / b.get("dockerfile", "Dockerfile")),
           "--build-arg", f"{b.get('sha_arg', 'REPO_SHA')}={sha}"]
    for k, v in b.get("args", {}).items():
        cmd += ["--build-arg", f"{k}={v}"]
    if no_cache:
        cmd.append("--no-cache")
    cmd.append(str(d / b.get("context", ".")))
    t0 = time.time()
    log(f"  build {tag} ({sha[:12]}) ...")
    sh(cmd, timeout=3600, check=True)
    image_id = sh(["docker", "image", "inspect", "-f", "{{.Id}}", tag], check=True).stdout.strip()
    got = sh(["docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", tag, SHA_FILE]).stdout.strip()
    if got != sha:
        raise RuntimeError(f"{tag}: {SHA_FILE} says {got!r}, expected {sha}")
    return {"tag": tag, "image_id": image_id, "sha": sha, "sha_verified": True, "build_seconds": round(time.time() - t0, 1)}


def run_trial(case: dict, d: Path, image: str, arm: str, inp: str, idx: int, net: str | None) -> dict:
    nonce = "PSB" + secrets.token_hex(8)
    tgt = case["target"]
    name = f"{PREFIX}{case['id']}_{arm}_{idx}_{secrets.token_hex(3)}"
    mount = ["--mount", f"type=bind,source={d},target=/case,readonly"]
    env = []
    for k, v in tgt.get("env", {}).items():
        env += ["-e", f"{k}={subst([v], nonce=nonce)[0]}"]
    netargs = ["--network", "none"] if net is None else ["--network", net, "--network-alias", "target"]
    tcmd = subst(tgt.get("command") or ["sleep", "infinity"], nonce=nonce)
    rec: dict = {"trial": idx, "nonce": nonce, "container": name}
    try:
        p = sh(["docker", "run", "-d", "--name", name, *netargs, *mount, *env,
                *(["--entrypoint", tgt["entrypoint"]] if tgt.get("entrypoint") else []), image, *tcmd], timeout=120)
        if p.returncode != 0:
            raise RuntimeError(f"target start failed: {p.stderr.strip()[-500:]}")
        insp = json.loads(sh(["docker", "inspect", name], check=True).stdout)[0]
        rec["network_mode"] = insp["HostConfig"]["NetworkMode"]
        if tgt.get("ready"):
            deadline = time.time() + tgt.get("ready_timeout", 90)
            while True:
                r = sh(["docker", "exec", name, *subst(tgt["ready"], nonce=nonce)], timeout=60)
                if r.returncode == 0:
                    break
                if time.time() > deadline:
                    logs = sh(["docker", "logs", "--tail", "30", name]).stdout
                    raise RuntimeError(f"target not ready after {tgt.get('ready_timeout', 90)}s; logs:\n{logs}")
                time.sleep(1)
        dl = case["deliver"]
        dcmd = subst(dl["command"], input=inp, nonce=nonce, target="target")
        if dl.get("mode", "exec") == "exec":
            r = sh(["docker", "exec", name, *dcmd], timeout=dl.get("timeout", 120))
        else:
            r = sh(["docker", "run", "--rm", "--name", name + "_client", "--network", net, *mount,
                    "--entrypoint", dcmd[0], image, *dcmd[1:]], timeout=dl.get("timeout", 120))
        rec["deliver_rc"] = r.returncode
        rec["deliver_tail"] = (r.stdout + r.stderr).strip()[-400:]
        o = sh(["docker", "exec", name, *subst(case["oracle"]["command"], nonce=nonce)], timeout=60)
        rec["oracle_rc"] = o.returncode
        rec["oracle_out"] = (o.stdout + o.stderr).strip()[-300:]
        rec["hit"] = o.returncode == 0
    except Exception as e:  # a harness error counts as "no hit" and is recorded
        rec["hit"] = False
        rec["error"] = str(e)[-800:]
    finally:
        sh(["docker", "rm", "-f", name], timeout=60)
        sh(["docker", "rm", "-f", name + "_client"], timeout=60)
    return rec


def run_case(cid: str, d: Path, trials: int, no_cache: bool) -> dict:
    case = load_case(d)
    started = dt.datetime.now(dt.timezone.utc)
    log(f"== {cid}  ({case['kbc_id']}, {case['rd_class']}, attacker={case['attacker']})")
    res: dict = {"case": cid, "kbc_id": case["kbc_id"], "advisory_url": case["advisory_url"],
                 "harness_version": HARNESS_VERSION, "case_version": case.get("version", "0"),
                 "started_utc": started.isoformat(timespec="seconds"), "trials_per_arm": trials,
                 "target_network": case["target"].get("network", "none")}
    net = None
    try:
        images = {v: build(case, d, v, no_cache) for v in ("vuln", "fix")}
        res["images"] = images
        if case["target"].get("network", "none") == "internal":
            net = f"{PREFIX}net_{cid}"
            sh(["docker", "network", "rm", net])
            sh(["docker", "network", "create", "--internal", net], check=True)
            ninfo = json.loads(sh(["docker", "network", "inspect", net], check=True).stdout)[0]
            res["network"] = {"name": net, "internal": ninfo["Internal"]}
            if not ninfo["Internal"]:
                raise RuntimeError(f"network {net} is not internal")
        expect = {"attack": trials, "control": 0, "fix": 0}
        expect.update({k: (trials if v == "all" else v) for k, v in case.get("expect", {}).items()})
        res["arms"] = {}
        for arm, variant, inp in ARMS:
            recs = []
            for i in range(1, trials + 1):
                r = run_trial(case, d, images[variant]["tag"], arm, inp, i, net)
                recs.append(r)
                log(f"  {arm:7s} #{i}: {'HIT' if r['hit'] else 'miss'}" + (f"  ERROR {r['error'][:200]}" if r.get("error") else ""))
            hits = sum(r["hit"] for r in recs)
            res["arms"][arm] = {"image": variant, "input": inp, "hits": hits, "trials": trials,
                                "expected_hits": expect[arm], "ok": hits == expect[arm], "records": recs}
        errors = [r["error"] for a in res["arms"].values() for r in a["records"] if r.get("error")]
        ok = all(a["ok"] for a in res["arms"].values()) and not errors
        bad_net = [r.get("network_mode") for a in res["arms"].values() for r in a["records"]
                   if r.get("network_mode") not in ("none", net)]
        if bad_net:
            ok = False
            res["hermeticity_violation"] = bad_net
        res["verdict"] = "PROVEN" if ok else "FAILED"
    except Exception as e:
        res["verdict"] = "ERROR"
        res["error"] = str(e)[-2000:]
        log(f"  ERROR: {str(e)[:1500]}")
    finally:
        if net:
            sh(["docker", "network", "rm", net])
    res["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / f"{cid}.json").write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cases", nargs="*", help="case ids (directory names under bench/cases)")
    ap.add_argument("--all", action="store_true", help="run every discovered case")
    ap.add_argument("--list", action="store_true", help="list discovered cases and exit")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--no-cache", action="store_true", help="rebuild images without the Docker layer cache")
    a = ap.parse_args()
    found = discover()
    if a.list:
        for cid, d in found.items():
            c = load_case(d)
            print(f"{cid:40s} {c['rd_class']:24s} {c['attacker']:22s} {c['advisory_url']}")
        return 0
    ids = list(found) if a.all else a.cases
    if not ids:
        ap.error("give case ids or --all")
    unknown = [i for i in ids if i not in found]
    if unknown:
        ap.error(f"unknown case(s): {', '.join(unknown)}; known: {', '.join(found)}")
    results = [run_case(i, found[i], a.trials, a.no_cache) for i in ids]
    print()
    print(f"{'case':40s} {'ATTACK':>7s} {'CONTROL':>8s} {'FIX':>5s}  net       verdict")
    for r in results:
        arms = r.get("arms", {})
        cell = lambda k: f"{arms[k]['hits']}/{arms[k]['trials']}" if k in arms else "-"
        print(f"{r['case']:40s} {cell('attack'):>7s} {cell('control'):>8s} {cell('fix'):>5s}  {r['target_network']:9s} {r['verdict']}")
    return 0 if all(r["verdict"] == "PROVEN" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
