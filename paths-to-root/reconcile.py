"""Reconcile the two path raters into one KBC row-to-path map .

Usage (from this folder's parent): python -I paths-to-root/reconcile.py [--write]

Rater 1 = rule script map_kbc_paths.py -> kbc-path-map.csv.
Rater 2 = blind LLM rater -> rater2/labels.csv (rater2/RESULTS.md).
Where they agree, the shared label is adopted. Where they disagree, ADJUDICATED gives the
adopted label and a one-line reason. The adjudicator re-read each row's
description and notes in kbc-snapshot/*.jsonl against rater2/CODEBOOK.md; the
adjudicator saw both raters' labels, so this is a third, non-blind judgement, not a vote.
--write refreshes reconciled-path-map.csv.
"""
import collections
import csv
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "kbc-snapshot")
LABS = [f"P{k}" for k in range(1, 9)] + ["none"]

# id -> (adopted label, reason). Must cover exactly the rater-1/rater-2 disagreements.
ADJUDICATED = {
    "kbc-ghsa-35w5-fv47-8956": ("P2", "AST allow-list checked the template, eval ran the substituted string: a gate/executor differential; nothing at rest is loaded as code"),
    "kbc-ghsa-3r68-hf9h-887v": ("none", "authenticated client calls operator-disabled tools; missing guard is per-tool authorization at dispatch, not authentication or Origin binding; no host impact in the row"),
    "kbc-ghsa-4fc4-wcmh-4g86": ("P7", "row's entry is a malicious MCP server's OAuth redirect to /oauth/callback; impact is command exec on the client host (P7 sink). A web page could also navigate there (P6 reading), but the advisory frames the server"),
    "kbc-ghsa-53gh-p8jc-7rg8": ("none", "attacker writes the proxy's own config; P4 is about third-party artefacts the server opens. Counting it would widen P4 to any config-driven import. Contested: P4 under a broad reading"),
    "kbc-ghsa-6wvf-77m9-58rm": ("none", "template arrives in the request body and is rendered at once: request-time SSTI by an authed user, not an artefact at rest. Contested: P4 under a broad reading"),
    "kbc-ghsa-c2jp-c369-7pvx": ("P7", "kept on P7 for consistency with its chain successor rww4, which both raters put on P7; P7's guard list names browser-bound consent. Caveat: attacker is a malicious OAuth client at the proxy, not a malicious server"),
    "kbc-ghsa-fvww-7h3r-vfhp": ("none", "auth decorator registered for '*' so an ownership check never ran: authorization logic between authenticated principals, no host impact"),
    "kbc-ghsa-g3r5-9h93-4j2c": ("P3", "entry, guard (containment checked then used: TOCTOU), sink (write outside root) and impact (code load on restart) match P3; only the attacker differs: an authed workflow author, not a model"),
    "kbc-ghsa-gppg-gqw8-wh9g": ("none", "attacker must control the proxy's own secret value (environment/config), which the G1 rule and P4 both exclude; no third-party artefact"),
    "kbc-ghsa-hf3x-42qp-4rq6": ("P3", "archive member names escape the staging root: P3's containment guard, file write sink; v1's own P3 checklist names archive members. Attacker is the archive author, not a model"),
    "kbc-ghsa-hxmv-c4g6-5fqc": ("P4", "a crafted recipe directory's tools.py is exec_module()d at load without the opt-in that guards sibling autoload paths: third-party artefact trusted as code, misplaced guard"),
    "kbc-ghsa-jpw9-pfvf-9f58": ("none", "session id served without checking the owning principal: cross-user session use among authenticated users, not network-position trust; no host impact"),
    "kbc-ghsa-v798-mcc6-2m3m": ("P2", "authentication exists (P6's guard is present); the missing guard is a validator that itself execs the code it validates: P2's authed-user position. The Langflow chain therefore crosses P6 -> P2"),
    "kbc-ghsa-w66g-j6c4-hcfc": ("none", "JQL project allowlist skipped: data-scope confinement in a SaaS query, not a filesystem root; impact is reading excluded data, not host impact"),
    "kbc-ghsa-w66g-j6c4-hcfc-b": ("none", "CQL space allowlist skipped: same as the Jira half (data-scope, no host impact)"),
    "kbc-ghsa-wrwr-h859-xh2r": ("none", "guard shape is a clean differential (validated a coerced copy, used the original), but the row documents prototype pollution only, no executor sink; would move to P2 if a pollution->exec gadget is shown"),
}

# Adjudications the adjudicator flags as reasonable either way (used for the reported range).
CONTESTED = {"kbc-ghsa-53gh-p8jc-7rg8", "kbc-ghsa-6wvf-77m9-58rm", "kbc-ghsa-c2jp-c369-7pvx",
             "kbc-ghsa-g3r5-9h93-4j2c", "kbc-ghsa-hf3x-42qp-4rq6", "kbc-ghsa-wrwr-h859-xh2r"}


def main():
    r1 = {r["id"]: r for r in csv.DictReader(open(os.path.join(HERE, "kbc-path-map.csv"), encoding="utf-8"))}
    r2 = {r["id"]: r for r in csv.DictReader(open(os.path.join(HERE, "rater2", "labels.csv"), encoding="utf-8"))}
    assert set(r1) == set(r2), sorted(set(r1) ^ set(r2))
    # cross-check rows against the corpus itself
    corpus = {}
    for f in glob.glob(os.path.join(CORPUS, "*.jsonl")):
        for line in open(f, encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                corpus[r["id"]] = r
    # the map covers the 121-row snapshot; later KBC batches add rows not yet mapped
    assert set(r1) <= set(corpus), sorted(set(r1) - set(corpus))
    print(f"corpus rows now {len(corpus)}; mapped snapshot {len(r1)}; unmapped later rows {len(set(corpus) - set(r1))}")
    dis = {i for i in r1 if r1[i]["path"] != r2[i]["path"].strip()}
    if dis != set(ADJUDICATED):
        sys.exit(f"adjudication mismatch: missing {sorted(dis - set(ADJUDICATED))}, extra {sorted(set(ADJUDICATED) - dis)}")
    out = []
    for i in sorted(r1):
        a, b = r1[i]["path"], r2[i]["path"].strip()
        if a == b:
            adopted, basis, why = a, "agree", r1[i]["why"]
        else:
            adopted, why = ADJUDICATED[i]
            assert adopted in LABS
            basis = "adjudicated:" + ("r1" if adopted == a else "r2" if adopted == b else "neither")
            if i in CONTESTED:
                basis += ":contested"
        out.append({"id": i, "rd_class": r1[i]["rd_class"], "attacker": r1[i]["attacker"],
                    "rater1": a, "rater2": b, "adopted": adopted, "basis": basis, "reason": why})
    n = len(out)
    c = collections.Counter(o["adopted"] for o in out)
    on = n - c["none"]
    both = sum(1 for o in out if o["rater1"] != "none" and o["rater2"] != "none")
    either = sum(1 for o in out if o["rater1"] != "none" or o["rater2"] != "none")
    print(f"rows {n}; disagreements {len(dis)}; adopted r1 {sum(o['basis'].startswith('adjudicated:r1') for o in out)}, "
          f"r2 {sum(o['basis'].startswith('adjudicated:r2') for o in out)}; contested {len(CONTESTED)}")
    print(f"reconciled on a path {on} ({on / n:.1%}); none {c['none']}")
    con = [o for o in out if "contested" in o["basis"]]
    alt = {o["id"]: (o["rater1"] if o["adopted"] == o["rater2"] else o["rater2"]) for o in con}
    lo = on - sum(1 for o in con if o["adopted"] != "none" and alt[o["id"]] == "none")
    hi = on + sum(1 for o in con if o["adopted"] == "none" and alt[o["id"]] != "none")
    print(f"range: on a path for both raters {both}; for either rater {either}; flipping contested calls {lo}-{hi}")
    for p in LABS:
        print(f"  {p:5} r1 {sum(o['rater1'] == p for o in out):3}  r2 {sum(o['rater2'] == p for o in out):3}  reconciled {c[p]:3}")
    print("reconciled path x attacker:")
    att = sorted({o["attacker"] for o in out})
    for p in LABS:
        cc = collections.Counter(o["attacker"] for o in out if o["adopted"] == p)
        print(f"  {p:5} " + ", ".join(f"{k} {cc[k]}" for k in att if cc[k]))
    ra = collections.Counter(o["adopted"] for o in out if o["attacker"] == "remote-authed-user")
    print("remote-authed-user rows by reconciled path: " + ", ".join(f"{k} {v}" for k, v in ra.most_common()))
    if "--write" in sys.argv:
        with open(os.path.join(HERE, "reconciled-path-map.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(out[0]))
            w.writeheader()
            w.writerows(out)
        print("wrote reconciled-path-map.csv")


if __name__ == "__main__":
    main()
