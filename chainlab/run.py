#!/usr/bin/env python3
"""CHAINLAB v0 runner: hermetic 3-arm Docker proof of a model-mediated agent-chain bug.

    python chainlab/run.py --list                 # discovered cases
    python chainlab/run.py <case-id> [<case-id>..] # run one or more cases
    python chainlab/run.py --all                   # run every case

CHAINLAB proves that an agent FRAMEWORK lacks a guard on a model-mediated attacker
path (prompt injection -> the framework's own LLM call -> a tool -> host impact). A
deterministic SCRIPTED MODEL (a fake LLM implementing the framework's LLM interface)
is plugged into the framework and returns the attacker-chosen completion verbatim, so
a positive result depends on the framework, not on how gullible any real model is.

For each case the runner builds TWO images from the one case Dockerfile -- the pinned
vulnerable framework version and the pinned fixed version (build arg PKG_VERSION) --
checks each image really holds the pinned version, then runs three arms N times each:

    ATTACK  : vulnerable image + attacker scripted-model response  -> canary MUST fire
    CONTROL : vulnerable image + benign scripted-model response    -> canary must NOT fire
    FIX     : fixed image      + attacker scripted-model response   -> canary must NOT fire

Every trial gets a fresh container and a fresh nonce. Run time has NO egress: every
arm runs with `--network none`. A case is PROVEN with N trials when ATTACK N/N,
CONTROL 0/N, FIX 0/N, both versions verified, and no harness/hermeticity error.

The result is written to chainlab/results/<case-id>/proof_result.json. Its core shape
(finding_id, sink, sink_class, arms{attack,control,fix}{trials,canary_hits,exfil},
network, verdict) mirrors PitSense's schemas/proof_result.schema.json so CHAINLAB proofs
are directly comparable with the engine's; chainlab_* fields add the scripted-model
provenance.

The harness is SPEC-DRIVEN: a new reproduction is a new folder with spec.json + a
Dockerfile + a driver + fixtures. There is no bug-specific code in this file. Stdlib
only; needs the docker CLI. See chainlab/README.md and chainlab/SPEC.md.

Docker policy (division charter rd_docker_policy) is enforced at startup: C: free
space must be >= MIN_FREE_GB and the run aborts if below ABORT_FREE_GB; if any PitSense
container (pitsense_* that is not pitsense_rd_*) is running the runner refuses to start
so it does not collide with a live hunt. Every object this runner creates is prefixed
pitsense_rd_chainlab_ and removed when the run ends.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

CHAINLAB = Path(__file__).resolve().parent
CASES = CHAINLAB / "cases"
RESULTS = CHAINLAB / "results"
PREFIX = "pitsense_rd_chainlab_"
HARNESS_VERSION = "0.1.0"
VERSION_FILE = "/opt/chainlab/version"  # every case image writes its installed version here
MIN_FREE_GB = 80.0   # charter: start Docker work only with >= 80 GB free on C:
ABORT_FREE_GB = 60.0  # charter: abort if free space drops below 60 GB
# arm name, image variant, fixture (scripted-model response) name
ARMS = (
    ("attack", "vuln", "attack"),
    ("control", "vuln", "control"),
    ("fix", "fix", "attack"),
)
# chainlab rd_class -> PitSense sink_class enum (schemas/proof_result.schema.json)
SINK_CLASS_MAP = {
    "code-exec": "code-exec",
    "prompt-injection-to-tool": "code-exec",
    "unsafe-deserialization": "unsafe-deserialization",
    "ssrf-url-fetch": "ssrf-url-fetch",
    "path-traversal": "path-traversal",
}


def sh(cmd: list[str], timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(cmd)}\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}")
    return p


def log(msg: str) -> None:
    print(msg, flush=True)


def free_gb() -> float:
    anchor = Path(CHAINLAB.anchor or "C:\\")
    return shutil.disk_usage(str(anchor)).free / (1024 ** 3)


def hunt_containers() -> list[str]:
    """Running containers named pitsense_* but NOT pitsense_rd_* => a live PitSense proof."""
    out = sh(["docker", "ps", "--format", "{{.Names}}"]).stdout
    return [n for n in out.split() if n.startswith("pitsense_") and not n.startswith("pitsense_rd_")]


def preflight(stage: str) -> None:
    gb = free_gb()
    floor = MIN_FREE_GB if stage == "start" else ABORT_FREE_GB
    if gb < floor:
        raise RuntimeError(f"C: free space {gb:.1f} GB < {floor:.0f} GB floor ({stage}); aborting per rd_docker_policy")
    hunt = hunt_containers()
    if hunt:
        raise RuntimeError(f"PitSense container(s) running: {', '.join(hunt)}; refusing to collide with a live hunt")


def discover() -> dict[str, Path]:
    found = {}
    for sj in sorted(CASES.glob("*/spec.json")):
        found[sj.parent.name] = sj.parent
    return found


def load_spec(d: Path) -> dict:
    s = json.loads((d / "spec.json").read_text(encoding="utf-8"))
    required = ("id", "framework", "cve", "advisory_url", "sink", "sink_class", "rd_class",
                "attacker", "scripted_model", "build", "run")
    for k in required:
        if k not in s:
            raise ValueError(f"{d.name}/spec.json: missing field {k!r}")
    if s["id"] != d.name:
        raise ValueError(f"{d.name}/spec.json: id {s['id']!r} must equal the directory name")
    fw = s["framework"]
    for k in ("name", "vuln_version", "fix_version"):
        if k not in fw:
            raise ValueError(f"{d.name}: framework.{k} required")
    if s["run"].get("network", "none") != "none":
        raise ValueError(f"{d.name}: run.network must be 'none' (CHAINLAB v0 is egress-free)")
    return s


def subst(args: list[str], **kw: str) -> list[str]:
    out = []
    for a in args:
        for k, v in kw.items():
            a = a.replace("{" + k + "}", v)
        out.append(a)
    return out


def build(spec: dict, d: Path, variant: str, no_cache: bool) -> dict:
    version = spec["framework"]["vuln_version"] if variant == "vuln" else spec["framework"]["fix_version"]
    tag = f"{PREFIX}{spec['id']}:{variant}"
    b = spec["build"]
    arg = b.get("version_arg", "PKG_VERSION")
    cmd = ["docker", "build", "-q", "-t", tag, "-f", str(d / b.get("dockerfile", "Dockerfile")),
           "--build-arg", f"{arg}={version}"]
    for k, v in b.get("args", {}).items():
        cmd += ["--build-arg", f"{k}={v}"]
    if no_cache:
        cmd.append("--no-cache")
    cmd.append(str(d / b.get("context", ".")))
    t0 = time.time()
    log(f"  build {tag} ({spec['framework']['name']}=={version}) ...")
    sh(cmd, timeout=3600, check=True)
    image_id = sh(["docker", "image", "inspect", "-f", "{{.Id}}", tag], check=True).stdout.strip()
    got = sh(["docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", tag, VERSION_FILE]).stdout.strip()
    if got != version:
        raise RuntimeError(f"{tag}: {VERSION_FILE} says {got!r}, expected {version}")
    return {"tag": tag, "image_id": image_id, "version": version, "version_verified": True,
            "build_seconds": round(time.time() - t0, 1)}


def run_trial(spec: dict, d: Path, image: str, arm: str, fixture: str, idx: int) -> dict:
    nonce = "PSB" + secrets.token_hex(8)
    run = spec["run"]
    name = f"{PREFIX}{spec['id']}_{arm}_{idx}_{secrets.token_hex(3)}"
    mount = ["--mount", f"type=bind,source={d},target=/case,readonly"]
    env = []
    for k, v in run.get("env", {}).items():
        env += ["-e", f"{k}={subst([v], nonce=nonce)[0]}"]
    rec: dict = {"trial": idx, "nonce": nonce, "container": name}
    try:
        p = sh(["docker", "run", "-d", "--name", name, "--network", "none", *mount, *env,
                image, "sleep", "infinity"], timeout=120)
        if p.returncode != 0:
            raise RuntimeError(f"target start failed: {p.stderr.strip()[-500:]}")
        insp = json.loads(sh(["docker", "inspect", name], check=True).stdout)[0]
        rec["network_mode"] = insp["HostConfig"]["NetworkMode"]
        dcmd = subst(run["driver"], arm=fixture, nonce=nonce)
        r = sh(["docker", "exec", name, *dcmd], timeout=run.get("timeout", 120))
        rec["deliver_rc"] = r.returncode
        rec["deliver_tail"] = (r.stdout + r.stderr).strip()[-500:]
        o = sh(["docker", "exec", name, *subst(run["oracle"], nonce=nonce)], timeout=60)
        rec["oracle_rc"] = o.returncode
        rec["oracle_out"] = (o.stdout + o.stderr).strip()[-300:]
        rec["hit"] = o.returncode == 0
    except Exception as e:  # a harness error counts as "no hit" and is recorded
        rec["hit"] = False
        rec["error"] = str(e)[-800:]
    finally:
        sh(["docker", "rm", "-f", name], timeout=60)
    return rec


def run_case(cid: str, d: Path, trials: int, no_cache: bool) -> dict:
    spec = load_spec(d)
    started = dt.datetime.now(dt.timezone.utc)
    fw = spec["framework"]
    log(f"== {cid}  ({spec['cve']}, {spec['rd_class']}, attacker={spec['attacker']})")
    res: dict = {
        "schema": "chainlab-proof/0",
        "finding_id": cid,
        "sink": spec["sink"],
        "sink_class": SINK_CLASS_MAP.get(spec["sink_class"], spec["sink_class"]),
        "network": "none",
        "chainlab_cve": spec["cve"],
        "chainlab_ghsa": spec.get("ghsa"),
        "chainlab_advisory_url": spec["advisory_url"],
        "chainlab_rd_class": spec["rd_class"],
        "chainlab_attacker": spec["attacker"],
        "chainlab_scripted_model": spec["scripted_model"],
        "chainlab_framework": fw,
        "harness_version": HARNESS_VERSION,
        "spec_version": spec.get("version", "0"),
        "started_utc": started.isoformat(timespec="seconds"),
        "trials_per_arm": trials,
    }
    try:
        preflight("start")
        images = {v: build(spec, d, v, no_cache) for v in ("vuln", "fix")}
        res["versions"] = {
            f"{fw['name']}_vuln": images["vuln"]["version"],
            f"{fw['name']}_fix": images["fix"]["version"],
            "image_vuln": images["vuln"]["image_id"],
            "image_fix": images["fix"]["image_id"],
            "scripted_model_interface": spec["scripted_model"].get("interface", ""),
        }
        res["chainlab_images"] = images
        expect = {"attack": trials, "control": 0, "fix": 0}
        arms_detail: dict = {}
        res["arms"] = {}
        for arm, variant, fixture in ARMS:
            preflight("during")  # re-check disk before each arm; abort below floor
            recs = []
            for i in range(1, trials + 1):
                r = run_trial(spec, d, images[variant]["tag"], arm, fixture, i)
                recs.append(r)
                log(f"  {arm:7s} #{i}: {'HIT' if r['hit'] else 'miss'}" + (f"  ERROR {r['error'][:200]}" if r.get("error") else ""))
            hits = sum(r["hit"] for r in recs)
            res["arms"][arm] = {"trials": trials, "canary_hits": hits, "exfil": 0}
            arms_detail[arm] = {"image": variant, "fixture": fixture, "expected_hits": expect[arm],
                                "ok": hits == expect[arm], "records": recs}
        res["chainlab_arms_detail"] = arms_detail
        errors = [r["error"] for a in arms_detail.values() for r in a["records"] if r.get("error")]
        bad_net = [r.get("network_mode") for a in arms_detail.values() for r in a["records"]
                   if r.get("network_mode") != "none"]
        ok = all(a["ok"] for a in arms_detail.values()) and not errors and not bad_net
        if bad_net:
            res["hermeticity_violation"] = bad_net
        res["fix_patches_claimed_sink"] = True  # FIX arm is the upstream fix release for the claimed sink
        res["verdict"] = "PROVEN" if ok else "REJECT"
    except Exception as e:
        res["verdict"] = "ERROR"
        res["error"] = str(e)[-2000:]
        log(f"  ERROR: {str(e)[:1500]}")
    res["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    outdir = RESULTS / cid
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "proof_result.json").write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    return res


def cleanup() -> None:
    """Remove every container/image this runner may have left behind."""
    ids = sh(["docker", "ps", "-aq", "--filter", f"name={PREFIX}"]).stdout.split()
    if ids:
        sh(["docker", "rm", "-f", *ids], timeout=120)
    imgs = sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}", "--filter", f"reference={PREFIX}*"]).stdout.split()
    if imgs:
        sh(["docker", "rmi", "-f", *imgs], timeout=300)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cases", nargs="*", help="case ids (directory names under chainlab/cases)")
    ap.add_argument("--all", action="store_true", help="run every discovered case")
    ap.add_argument("--list", action="store_true", help="list discovered cases and exit")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--no-cache", action="store_true", help="rebuild images without the Docker layer cache")
    ap.add_argument("--keep", action="store_true", help="do not remove built images on exit (keeps the layer cache warm)")
    a = ap.parse_args()
    found = discover()
    if a.list:
        for cid, d in found.items():
            s = load_spec(d)
            print(f"{cid:44s} {s['rd_class']:26s} {s['attacker']:20s} {s['cve']}")
        return 0
    ids = list(found) if a.all else a.cases
    if not ids:
        ap.error("give case ids or --all")
    unknown = [i for i in ids if i not in found]
    if unknown:
        ap.error(f"unknown case(s): {', '.join(unknown)}; known: {', '.join(found)}")
    results = []
    try:
        results = [run_case(i, found[i], a.trials, a.no_cache) for i in ids]
    finally:
        if not a.keep:
            log("cleanup: removing pitsense_rd_chainlab_ containers and images ...")
            cleanup()
    print()
    print(f"{'case':44s} {'ATTACK':>7s} {'CONTROL':>8s} {'FIX':>5s}  verdict")
    for r in results:
        arms = r.get("arms", {})
        cell = lambda k: f"{arms[k]['canary_hits']}/{arms[k]['trials']}" if k in arms else "-"
        print(f"{r['finding_id']:44s} {cell('attack'):>7s} {cell('control'):>8s} {cell('fix'):>5s}  {r['verdict']}")
    return 0 if results and all(r["verdict"] == "PROVEN" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
