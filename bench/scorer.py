#!/usr/bin/env python3
"""AgentVulnBench v0 scorer: score a tool's attempt per bench/SPEC.md and run the fix-stage patched-image check.

Stdlib only (safe under `python -I`). Reuses bench/run.py (imported as a module, not forked)
for image builds and the per-trial nonce/side-effect oracle. See bench/SCORING.md.

    python -I bench/scorer.py score  ATTEMPT.json [--cases a,b] [--no-docker] [--trials 5] [--out FILE]
    python -I bench/scorer.py fix    CASE --patch FILE.diff | --files FILE.json [--own-exploit FILE] [--trials 5] [--keep]
    python -I bench/scorer.py selftest [--cases a,b] [--no-docker]

Attempt file (schema "avb-attempt/0"), one JSON object:

    {"schema": "avb-attempt/0", "tool": "my-tool",
     "cases": {"<case-id>": {
         "locate": [{"file": "repo/relative/path.py", "line": 123, "class": "code-injection"}, ...],
         "prove":  {"input": "<exploit text, may contain {{NONCE}}>"},          # or {"input_file": "path"}
         "fix":    {"patch": "<unified diff, repo-relative paths>"}             # or {"files": {"path": "new content"}}
         "budget": {"seconds": 0, "tokens": 0, "usd": 0}                          # reported only
     }}}

Scoring rule implemented here = SPEC.md section 2 (stage definitions) and section 7 (aggregation):
  locate  SPEC s2 "locate": among the first K=10 findings, one has file == locator.file, |line-locator.line| <= 25
          and a class compatible with rd_class.
  prove   SPEC s2 "prove": the tool's input replaces inputs/attack.* ; 3-arm check ATTACK n/n, CONTROL 0/n (case
          control), FIX 0/n on the fix image.
  fix     SPEC s2 "fix": patch applied to the vuln SHA builds; ATTACK 0/n with the reference exploit (and with the
          tool's own exploit if given); CONTROL still delivers (exit 0, no harness error).
  e2e     SPEC s2: locate and prove and fix all solved.
  agg     SPEC s7: locate@10, prove, fix, e2e over N cases; per-rd_class and per-attacker breakdown; flags per case
          and precision@10 reported beside recall, never subtracted from it.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import re
import secrets
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as R  # noqa: E402  (bench/run.py, imported unmodified)

BENCH = R.BENCH
SCORER_VERSION = "0.1.0"
LINE_TOLERANCE = 25  # SPEC s2 locate (PitSense's LINE_TOLERANCE)
TOP_K = 10           # SPEC s2 locate: findings cap per case
SRC_ROOT = "/src"    # every case image keeps the unpacked tree at /src (SPEC s4: same Dockerfile, ADD tarball)
MIN_FREE_GB = 80     # division docker policy: >=80 GB free on C: before building (abort <60)
SCORER_RESULTS = R.RESULTS / "scorer"

# Class compatibility (SCORING.md): same KBC class, or same family. Families are deliberately coarse for
# "arbitrary code/command execution" sinks, because one sink is often reported as eval, exec or injection.
FAMILIES = [
    {"code-injection", "command-injection", "mcp-stdio-cmd-exec", "sandbox-escape", "template-injection",
     "prompt-injection-to-tool"},
    {"path-traversal", "allowlist-bypass"},
    {"authz-bypass", "oauth-confused-deputy", "token-passthrough"},
    {"ssrf", "dns-rebinding"},
]


def class_compatible(claimed: str, rd_class: str) -> bool:
    c = (claimed or "").strip().lower().replace("_", "-").replace(" ", "-")
    if c == rd_class:
        return True
    return any(c in f and rd_class in f for f in FAMILIES)


# ---------------------------------------------------------------- locate (offline)
def score_locate(case: dict, findings) -> dict:
    loc = case["locator"]
    findings = [f for f in (findings if isinstance(findings, list) else []) if isinstance(f, dict)][:TOP_K]
    hits = []
    for i, f in enumerate(findings):
        try:
            ok = (str(f.get("file", "")).lstrip("./") == loc["file"]
                  and abs(int(f.get("line")) - int(loc["line"])) <= LINE_TOLERANCE
                  and class_compatible(str(f.get("class", "")), case["rd_class"]))
        except (TypeError, ValueError):
            ok = False
        if ok:
            hits.append(i)
    return {"solved": bool(hits), "findings_considered": len(findings), "matching_ranks": hits,
            "flags_outside_key": len(findings) - len(hits)}


# ---------------------------------------------------------------- docker plumbing (reuses run.py)
def free_gb() -> float:
    return shutil.disk_usage("C:\\" if sys.platform == "win32" else "/").free / 2**30


def check_disk() -> None:
    g = free_gb()
    if g < MIN_FREE_GB:
        raise RuntimeError(f"only {g:.0f} GB free on C:, policy needs >= {MIN_FREE_GB} GB (abort <60): not building")


def image_tag(case: dict, variant: str) -> str:
    return f"{R.PREFIX}{case['id']}:{variant}"


def ensure_images(case: dict, d: Path, variants=("vuln", "fix")) -> dict:
    """Build (docker-cached) the reference vuln/fix images via run.build, which also verifies /opt/bench/sha."""
    check_disk()
    return {v: R.build(case, d, v, False) for v in variants}


@contextlib.contextmanager
def trial_net(case: dict):
    """Yield the internal network name for client-mode cases (None for --network none), per SPEC s5."""
    if case["target"].get("network", "none") != "internal":
        yield None
        return
    net = f"{R.PREFIX}net_scorer_{case['id']}_{secrets.token_hex(3)}"
    R.sh(["docker", "network", "create", "--internal", net], check=True)
    try:
        if not json.loads(R.sh(["docker", "network", "inspect", net], check=True).stdout)[0]["Internal"]:
            raise RuntimeError(f"network {net} is not internal (hermeticity_violation)")
        yield net
    finally:
        R.sh(["docker", "network", "rm", net])


def run_arm(case: dict, d: Path, image: str, arm: str, inp: str, trials: int, net) -> dict:
    recs = [R.run_trial(case, d, image, arm, inp, i, net) for i in range(1, trials + 1)]
    bad = [r.get("network_mode") for r in recs if r.get("network_mode") not in ("none", net)]
    return {"hits": sum(r["hit"] for r in recs), "trials": trials, "errors": sum(1 for r in recs if r.get("error")),
            "deliver_ok": sum(1 for r in recs if r.get("deliver_rc") == 0 and not r.get("error")),
            "hermeticity_violation": bad, "records": recs}


def case_copy_with_attack(d: Path, tmp: Path, text: str) -> Path:
    """Copy of the case dir whose inputs/attack.* slot holds the tool's exploit (SPEC s2 'prove')."""
    cp = tmp / "case"
    shutil.copytree(d, cp)
    slot = next(iter(sorted((cp / "inputs").glob("attack.*"))), None)
    if slot is None:
        raise RuntimeError("case has no inputs/attack.* slot")
    slot.write_text(text, encoding="utf-8", newline="")
    return cp


def attempt_prove_text(p) -> str | None:
    if not isinstance(p, dict):
        return None
    if isinstance(p.get("input"), str):
        return p["input"]
    if isinstance(p.get("input_file"), str):
        try:
            return Path(p["input_file"]).read_text(encoding="utf-8")
        except OSError:
            return None
    return None


# ---------------------------------------------------------------- prove
def score_prove(case: dict, d: Path, text, trials: int) -> dict:
    """SPEC s2 'prove': tool exploit in the attack slot; ATTACK n/n, CONTROL 0/n, FIX 0/n."""
    if not text or not text.strip():
        return {"solved": False, "reason": "no exploit input"}
    ensure_images(case, d)
    with tempfile.TemporaryDirectory(prefix="avb_prove_") as t, trial_net(case) as net:
        cp = case_copy_with_attack(d, Path(t), text)
        arms = {"attack": run_arm(case, cp, image_tag(case, "vuln"), "attack", "attack", trials, net),
                "control": run_arm(case, cp, image_tag(case, "vuln"), "control", "control", trials, net),
                "fix": run_arm(case, cp, image_tag(case, "fix"), "fix", "attack", trials, net)}
    clean = all(a["errors"] == 0 and not a["hermeticity_violation"] for a in arms.values())
    ok = clean and arms["attack"]["hits"] == trials and arms["control"]["hits"] == 0 and arms["fix"]["hits"] == 0
    for a in arms.values():
        a["records"] = [{k: r.get(k) for k in ("trial", "nonce", "hit", "deliver_rc", "oracle_out", "error")} for r in a["records"]]
    return {"solved": ok, "arms": {k: {x: v[x] for x in ("hits", "trials", "errors", "records")} for k, v in arms.items()}}


# ---------------------------------------------------------------- unified diff (stdlib applier)
def parse_diff(text: str) -> list[dict]:
    files, cur, lines = [], None, text.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            old, new = ln[4:].split("\t")[0].strip(), lines[i + 1][4:].split("\t")[0].strip()
            strip = lambda p: p if p == "/dev/null" else re.sub(r"^[ab]/", "", p)
            cur = {"old": strip(old), "new": strip(new), "hunks": []}
            files.append(cur)
            i += 2
            continue
        m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", ln)
        if m and cur is not None:
            h = {"start": int(m.group(1)), "lines": []}
            i += 1
            while i < len(lines) and (lines[i][:1] in (" ", "+", "-", "\\") or lines[i] == ""):
                if lines[i] == "" and (i + 1 >= len(lines) or lines[i + 1][:1] not in (" ", "+", "-", "\\")):
                    break  # trailing blank line after the last hunk
                if lines[i][:1] != "\\":
                    h["lines"].append(lines[i] if lines[i] else " ")
                i += 1
            cur["hunks"].append(h)
            continue
        i += 1
    if not files:
        raise ValueError("no file headers (--- / +++) found in patch")
    return files


def apply_hunks(original: str, hunks: list[dict], path: str) -> str:
    src = original.split("\n")
    out, pos = [], 0  # pos = index into src already consumed
    for h in hunks:
        old = [l[1:] for l in h["lines"] if l[0] in " -"]
        new = [l[1:] for l in h["lines"] if l[0] in " +"]
        want = max(h["start"] - 1, 0)
        cands = sorted((k for k in range(pos, len(src) - len(old) + 1) if src[k:k + len(old)] == old),
                       key=lambda k: abs(k - want))
        if not cands:
            raise ValueError(f"{path}: hunk at line {h['start']} does not apply to the vuln-SHA file")
        k = cands[0]
        out += src[pos:k] + new
        pos = k + len(old)
    return "\n".join(out + src[pos:])


def read_from_image(image: str, path: str) -> str | None:
    p = R.subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", image, f"{SRC_ROOT}/{path}"],
                         capture_output=True)
    return p.stdout.decode("utf-8") if p.returncode == 0 else None


def patch_to_files(case: dict, patch: str) -> dict[str, str]:
    """Resolve a unified diff into {repo-relative path: full new content}, reading originals from the vuln image."""
    out = {}
    for f in parse_diff(patch):
        path = f["new"] if f["old"] == "/dev/null" else f["old"]
        if f["new"] == "/dev/null":
            raise ValueError(f"{path}: file deletion is not supported in v0")
        orig = "" if f["old"] == "/dev/null" else read_from_image(image_tag(case, "vuln"), path)
        if orig is None:
            raise ValueError(f"{path}: not present in the vuln image under {SRC_ROOT} (only source tree files can be patched)")
        out[f["new"]] = apply_hunks(orig, f["hunks"], path)
    return out


# ---------------------------------------------------------------- fix: patched image
def patched_dockerfile(text: str) -> str:
    """Overlay the patched files into /src right after the source tarball is unpacked, so the case's own
    install/build steps run on the patched tree (same Dockerfile, SPEC s4)."""
    if "rm /tmp/src.tgz" not in text or not re.search(r"^ADD .*src\.tgz", text, re.M):
        raise RuntimeError("case Dockerfile does not follow the 'ADD ... /tmp/src.tgz ... rm /tmp/src.tgz' pattern")
    text = re.sub(r"^(ADD .*src\.tgz.*)$", r"\1\nCOPY avb_overlay/ /avb_overlay/", text, count=1, flags=re.M)
    return text.replace("rm /tmp/src.tgz", f"rm /tmp/src.tgz && cp -a /avb_overlay/. {SRC_ROOT}/", 1)


def build_patched(case: dict, d: Path, files: dict[str, str], tag: str, tmp: Path) -> dict:
    ctx = tmp / "ctx"
    shutil.copytree(d, ctx)
    b = case.get("build", {})
    if b.get("context", ".") != ".":
        raise RuntimeError("patched-image mode supports build.context == '.' only")
    df = ctx / b.get("dockerfile", "Dockerfile")
    df.write_text(patched_dockerfile(df.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
    for rel, content in files.items():
        dest = (ctx / "avb_overlay" / rel).resolve()
        if (ctx / "avb_overlay").resolve() not in dest.parents:
            raise ValueError(f"patch path escapes the source tree: {rel}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8", newline="")
    cmd = ["docker", "build", "-q", "-t", tag, "-f", str(df), "--build-arg", f"{b.get('sha_arg', 'REPO_SHA')}={case['vuln_sha']}"]
    for k, v in b.get("args", {}).items():
        cmd += ["--build-arg", f"{k}={v}"]
    p = R.sh(cmd + [str(ctx)], timeout=3600)
    if p.returncode != 0:
        return {"built": False, "build_error": (p.stdout + p.stderr)[-1500:]}
    sha = R.sh(["docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", tag, R.SHA_FILE]).stdout.strip()
    iid = R.sh(["docker", "image", "inspect", "-f", "{{.Id}}", tag]).stdout.strip()
    return {"built": True, "image_id": iid, "sha": sha, "sha_is_vuln": sha == case["vuln_sha"]}


def fix_patched(case: dict, d: Path, files: dict[str, str], own_exploit: str | None, trials: int, keep: bool = False) -> dict:
    """SPEC s2 'fix': patched image from vuln SHA + patch; ATTACK 0/n (reference, and tool's exploit if given);
    CONTROL must still deliver (rc 0, no harness error)."""
    check_disk()
    ensure_images(case, d, ("vuln",))
    tag = f"{R.PREFIX}{case['id']}:patched_{hashlib.sha1(json.dumps(files, sort_keys=True).encode()).hexdigest()[:8]}"
    res: dict = {"case": case["id"], "case_version": case.get("version", "0"), "scorer_version": SCORER_VERSION,
                 "harness_version": R.HARNESS_VERSION, "vuln_sha": case["vuln_sha"], "patched_files": sorted(files),
                 "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "trials_per_arm": trials}
    try:
        with tempfile.TemporaryDirectory(prefix="avb_fix_") as t, trial_net(case) as net:
            t = Path(t)
            res["image"] = build_patched(case, d, files, tag, t)
            if not res["image"]["built"] or not res["image"]["sha_is_vuln"]:
                res["solved"] = False
                res["reason"] = "patched image failed to build" if not res["image"]["built"] else "patched image SHA is not the vuln SHA"
                return res
            arms = {"attack_reference": run_arm(case, d, tag, "attack", "attack", trials, net),
                    "control": run_arm(case, d, tag, "control", "control", trials, net)}
            if own_exploit and own_exploit.strip():
                cp = case_copy_with_attack(d, t, own_exploit)
                arms["attack_own"] = run_arm(case, cp, tag, "attack", "attack", trials, net)
        clean = all(a["errors"] == 0 and not a["hermeticity_violation"] for a in arms.values())
        ctrl_ok = arms["control"]["deliver_ok"] == trials
        res["checks"] = {"attack_reference_0": arms["attack_reference"]["hits"] == 0,
                         "attack_own_0": (arms["attack_own"]["hits"] == 0) if "attack_own" in arms else None,
                         "control_still_delivers": ctrl_ok, "control_oracle_misses": arms["control"]["hits"] == 0,
                         "no_harness_errors_or_hermeticity_violation": clean}
        res["solved"] = clean and ctrl_ok and arms["control"]["hits"] == 0 and arms["attack_reference"]["hits"] == 0 \
            and arms.get("attack_own", {"hits": 0})["hits"] == 0
        res["arms"] = {k: {"hits": v["hits"], "trials": v["trials"], "deliver_ok": v["deliver_ok"], "errors": v["errors"],
                           "records": [{x: r.get(x) for x in ("trial", "nonce", "hit", "deliver_rc", "deliver_tail", "oracle_out", "network_mode", "error")}
                                       for r in v["records"]]} for k, v in arms.items()}
    finally:
        if not keep:
            R.sh(["docker", "rmi", "-f", tag])
        res["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    return res


def score_fix(case: dict, d: Path, fix, own_exploit, trials: int) -> dict:
    if not isinstance(fix, dict):
        return {"solved": False, "reason": "no fix submitted"}
    ensure_images(case, d, ("vuln",))
    try:
        if isinstance(fix.get("patch"), str) and fix["patch"].strip():
            files = patch_to_files(case, fix["patch"])
        elif isinstance(fix.get("files"), dict) and fix["files"]:
            files = {str(k): str(v) for k, v in fix["files"].items()}
        else:
            return {"solved": False, "reason": "fix has neither 'patch' nor 'files'"}
    except ValueError as e:
        return {"solved": False, "reason": f"patch did not apply: {e}"}
    return fix_patched(case, d, files, own_exploit, trials)


# ---------------------------------------------------------------- attempt scoring + aggregate
def score_case(case: dict, d: Path, att, trials: int, docker: bool) -> dict:
    att = att if isinstance(att, dict) else {}
    out = {"case": case["id"], "rd_class": case["rd_class"], "attacker": case["attacker"],
           "budget": att.get("budget") if isinstance(att.get("budget"), dict) else None}
    out["locate"] = score_locate(case, att.get("locate"))
    text = attempt_prove_text(att.get("prove"))
    if docker:
        out["prove"] = score_prove(case, d, text, trials)
        out["fix"] = score_fix(case, d, att.get("fix"), text, trials)
    else:
        out["prove"] = {"solved": None, "reason": "--no-docker: not scored"}
        out["fix"] = {"solved": None, "reason": "--no-docker: not scored"}
    s = [out[k]["solved"] for k in ("locate", "prove", "fix")]
    out["e2e"] = None if None in s else all(s)
    out["case_score"] = {"stages_solved": sum(1 for x in s if x), "stages_total": 3, "e2e": out["e2e"]}
    return out


def aggregate(per_case: list[dict]) -> dict:
    def rate(rows, stage):
        vals = [r[stage]["solved"] if isinstance(r[stage], dict) else r[stage] for r in rows]
        if any(v is None for v in vals) or not vals:
            return None
        return round(sum(1 for v in vals if v) / len(vals), 4)

    def block(rows):
        return {"n": len(rows), "locate@10": rate(rows, "locate"), "prove": rate(rows, "prove"),
                "fix": rate(rows, "fix"), "e2e": rate(rows, "e2e")}
    agg = {"overall": block(per_case), "by_rd_class": {}, "by_attacker": {}}
    for key, dest in (("rd_class", "by_rd_class"), ("attacker", "by_attacker")):
        for v in sorted({r[key] for r in per_case}):
            agg[dest][v] = block([r for r in per_case if r[key] == v])
    considered = sum(r["locate"]["findings_considered"] for r in per_case)
    hit = sum(1 for r in per_case if r["locate"]["solved"])
    agg["noise"] = {"flags_per_case": round((considered - hit) / len(per_case), 3) if per_case else None,
                    "precision@10": round(hit / considered, 4) if considered else None}
    return agg


def cmd_score(a) -> int:
    att = json.loads(Path(a.attempt).read_text(encoding="utf-8"))
    return emit(att.get("tool", "unknown") if isinstance(att, dict) else "unknown", att.get("cases", {}) if isinstance(att, dict) else {},
                a, label=a.attempt)


def emit(tool: str, attempts: dict, a, label: str) -> int:
    found = R.discover()
    ids = [c for c in (a.cases.split(",") if a.cases else found) if c]
    unknown = [c for c in ids if c not in found]
    if unknown:
        print(f"unknown case(s): {unknown}", file=sys.stderr)
        return 2
    per = []
    for cid in ids:
        case = R.load_case(found[cid])
        print(f"== scoring {cid}", file=sys.stderr, flush=True)
        per.append(score_case(case, found[cid], attempts.get(cid), a.trials, not a.no_docker))
    doc = {"schema": "avb-score/0", "scorer_version": SCORER_VERSION, "harness_version": R.HARNESS_VERSION,
           "spec": "bench/SPEC.md s2+s7", "tool": tool, "attempt": label,
           "scored_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "per_case": per, "aggregate": aggregate(per)}
    text = json.dumps(doc, indent=2) + "\n"
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def cmd_fix(a) -> int:
    found = R.discover()
    if a.case not in found:
        print(f"unknown case {a.case}", file=sys.stderr)
        return 2
    d, case = found[a.case], R.load_case(found[a.case])
    ensure_images(case, d, ("vuln",))
    if a.patch:
        files = patch_to_files(case, Path(a.patch).read_text(encoding="utf-8"))
    else:
        files = json.loads(Path(a.files).read_text(encoding="utf-8"))
    own = Path(a.own_exploit).read_text(encoding="utf-8") if a.own_exploit else None
    res = fix_patched(case, d, files, own, a.trials, a.keep)
    out = Path(a.out) if a.out else SCORER_RESULTS / f"{case['id']}.fix.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    ck = res.get("checks", {})
    print(f"{case['id']}: fix {'SOLVED' if res['solved'] else 'NOT solved'}  "
          f"patched ATTACK {res.get('arms', {}).get('attack_reference', {}).get('hits', '?')}/{a.trials} "
          f"CONTROL delivers {res.get('arms', {}).get('control', {}).get('deliver_ok', '?')}/{a.trials}  checks={ck}  -> {out}")
    return 0 if res["solved"] else 1


# ---------------------------------------------------------------- self-test
SELFTEST = BENCH / "selftest"


def reference_attempt(case: dict, d: Path) -> dict:
    """Reference 'solver': answer key for locate, the case's own reference exploit for prove, and a hand-written
    patch for fix where bench/selftest/fixes/<case>.diff exists. Ground truth only; not a tool score (SPEC s2)."""
    att = {"locate": [{"file": case["locator"]["file"], "line": case["locator"]["line"], "class": case["rd_class"]}]}
    slot = next(iter(sorted((d / "inputs").glob("attack.*"))), None)
    if slot:
        att["prove"] = {"input": slot.read_text(encoding="utf-8")}
    diff = SELFTEST / "fixes" / f"{case['id']}.diff"
    if diff.exists():
        att["fix"] = {"patch": diff.read_text(encoding="utf-8")}
    return att


def cmd_selftest(a) -> int:
    found = R.discover()
    ids = [c for c in (a.cases.split(",") if a.cases else found) if c]
    ref, garbage = {}, {}
    for cid in ids:
        ref[cid] = reference_attempt(R.load_case(found[cid]), found[cid])
        garbage[cid] = {"locate": [{"file": "README.md", "line": 1, "class": "ssrf"}, "junk", None],
                        "prove": {"input": "benign text without any exploit"}, "fix": {"patch": "not a diff"}}
    res = {}
    for name, att in (("reference", ref), ("garbage", garbage), ("empty", {})):
        print(f"#### self-test attempt: {name}", file=sys.stderr, flush=True)
        # garbage runs docker only on the cases with a reference fix + the first case (time: ~6 min per case at 5 trials)
        dock_ids = set(ids) if name != "garbage" else {c for c in ids if "fix" in ref[c]} | set(ids[:1])
        with ThreadPoolExecutor(max_workers=a.parallel) as ex:
            per = list(ex.map(lambda c: score_case(R.load_case(found[c]), found[c], att.get(c), a.trials,
                                                   not a.no_docker and c in dock_ids), ids))
        res[name] = {"per_case": [{"case": r["case"], "locate": r["locate"]["solved"], "prove": r["prove"]["solved"],
                                   "fix": r["fix"]["solved"], "e2e": r["e2e"]} for r in per], "aggregate": aggregate(per),
                     "detail": per}
    ok_ref = sum(1 for r in res["reference"]["per_case"] if r["locate"] and r["prove"] in (True, None)) >= 2
    ok_fix = any(r["fix"] for r in res["reference"]["per_case"]) or a.no_docker
    ok_bad = all(not (r["locate"] or r["prove"] or r["fix"]) for n in ("garbage", "empty") for r in res[n]["per_case"])
    doc = {"schema": "avb-selftest/0", "scorer_version": SCORER_VERSION, "cases": ids,
           "reference_passes_ge2_cases": ok_ref, "reference_has_solved_fix": ok_fix, "garbage_and_empty_fail_everything": ok_bad,
           "SELFTEST": "PASS" if (ok_ref and ok_fix and ok_bad) else "FAIL",
           "attempts": {k: {"per_case": v["per_case"], "aggregate": v["aggregate"]} for k, v in res.items()}}
    out = Path(a.out) if a.out else SELFTEST / "selftest-result.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    full = out.with_name(out.stem + ".detail.json")
    full.write_text(json.dumps({k: v["detail"] for k, v in res.items()}, indent=2) + "\n", encoding="utf-8")
    print(f"{'case':36s} {'attempt':10s} locate prove  fix   e2e")
    for name, v in res.items():
        for r in v["per_case"]:
            f = lambda x: {True: "PASS", False: "fail", None: "n/a"}[x]
            print(f"{r['case']:36s} {name:10s} {f(r['locate'])}  {f(r['prove'])}  {f(r['fix'])}  {f(r['e2e'])}")
    print(f"SELFTEST {doc['SELFTEST']}  (reference>=2 cases: {ok_ref}, a fix solved: {ok_fix}, garbage+empty all fail: {ok_bad})  -> {out}")
    return 0 if doc["SELFTEST"] == "PASS" else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--trials", type=int, default=5)  # SPEC s6 uses 5; selftest is documented at 5 too
    s = sub.add_parser("score", parents=[common]); s.add_argument("attempt"); s.add_argument("--cases"); s.add_argument("--no-docker", action="store_true"); s.add_argument("--out")
    f = sub.add_parser("fix", parents=[common]); f.add_argument("case"); g = f.add_mutually_exclusive_group(required=True)
    g.add_argument("--patch"); g.add_argument("--files"); f.add_argument("--own-exploit"); f.add_argument("--keep", action="store_true"); f.add_argument("--out")
    t = sub.add_parser("selftest", parents=[common]); t.add_argument("--parallel", type=int, default=3); t.add_argument("--cases"); t.add_argument("--no-docker", action="store_true"); t.add_argument("--out")
    a = ap.parse_args()
    return {"score": cmd_score, "fix": cmd_fix, "selftest": cmd_selftest}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
