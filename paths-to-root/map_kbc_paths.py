"""Rater 1: map every KBC row to one of the eight paths to root (rule-based rater).

Usage (from this folder's parent): python -I paths-to-root/map_kbc_paths.py [--write]

Rules: a default per (rd_class, attacker) cell, then per-row overrides where the row's
`reason` puts it on a different path. Every override names its reason. "none" = the row
fits no path; the reason says why. One author wrote these rules after reading each row's
`reason` field (2026-11-25). The blind second rater is in rater2/ and the reconciliation in
reconcile.py. --write refreshes kbc-path-map.csv.
"""
import collections
import csv
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "kbc-snapshot")  # the 121-row, four-batch KBC snapshot

CELL = {
    ("code-injection", "untrusted-llm-input"): "P1",
    ("prompt-injection-to-tool", "untrusted-llm-input"): "P1",
    ("sandbox-escape", "remote-authed-user"): "P2",
    ("sandbox-escape", "untrusted-llm-input"): "P2",
    ("allowlist-bypass", "remote-authed-user"): "P2",
    ("path-traversal", "untrusted-llm-input"): "P3",
    ("allowlist-bypass", "untrusted-llm-input"): "P3",
    ("command-injection", "untrusted-data-store"): "P4",
    ("code-injection", "untrusted-data-store"): "P4",
    ("template-injection", "untrusted-data-store"): "P4",
    ("unsafe-deserialization", "untrusted-data-store"): "P4",
    ("unsafe-deserialization", "remote-unauth"): "P5",
    ("unsafe-deserialization", "untrusted-llm-input"): "P5",
    ("authz-bypass", "remote-unauth"): "P6",
    ("authz-bypass", "remote-authed-user"): "P6",
    ("dns-rebinding", "malicious-web-content"): "P6",
    ("mcp-stdio-cmd-exec", "malicious-web-content"): "P6",
    ("code-injection", "remote-unauth"): "P6",
    ("token-passthrough", "remote-unauth"): "P6",
    ("oauth-confused-deputy", "malicious-mcp-server"): "P7",
    ("oauth-confused-deputy", "remote-unauth"): "P7",
    ("token-passthrough", "malicious-mcp-server"): "P7",
    ("token-passthrough", "remote-authed-user"): "P7",
    ("command-injection", "malicious-mcp-server"): "P7",
    ("code-injection", "malicious-mcp-server"): "P7",
    ("mcp-stdio-cmd-exec", "malicious-mcp-server"): "P7",
    ("ssrf", "malicious-mcp-server"): "P7",
    ("ssrf", "malicious-web-content"): "P8",
    ("ssrf", "remote-authed-user"): "P8",
    ("ssrf", "remote-unauth"): "P8",
    ("ssrf", "untrusted-llm-input"): "P8",
    ("allowlist-bypass", "malicious-web-content"): "P8",
}

# id -> (path, reason). Overrides beat the cell default.
OVERRIDE = {
    "kbc-ghsa-2h4w-29cv-2cmv": ("P2", "denylist vs sh -c newline: gate/executor differential"),
    "kbc-ghsa-wvpx-g427-q9wc": ("P2", "safe_exec restricted globals: incomplete gate before exec"),
    "kbc-ghsa-5xvg-pmgg-3mxr": ("P2", "regex denylist then Pyodide: gate/executor differential"),
    "kbc-ghsa-4j8x-x6v7-w9rh": ("P2", "authed user string spliced into Python run by the CSV agent gate"),
    "kbc-ghsa-x6vm-w76m-8j7c": ("P2", "regex validator vs Pyodide executor"),
    "kbc-ghsa-hf3x-42qp-4rq6": ("P3", "archive member names escape the staging root (containment)"),
    "kbc-ghsa-g3r5-9h93-4j27": ("P3", "validated path then cloned later: containment TOCTOU"),
    "kbc-ghsa-w794-rj3p-xv4w": ("P6", "user-saved MCP stdio config spawned as-is by the control plane"),
    "kbc-ghsa-v798-mcc6-2m3m": ("P6", "second link of the Langflow validate_code chain (authed exec)"),
    "kbc-ghsa-8qpj-27x8-pwpm": ("P2", "weak-globals PythonREPL sandbox"),
    "kbc-ghsa-3769-jgqc-cxmw": ("P2", "caller options merged over NodeVM sandbox defaults"),
    "kbc-ghsa-pw38-xv9x-h8ch": ("P1", "model-server output eval()d"),
    "kbc-ghsa-mrw7-hf4f-83pf": ("P5", "client prompt_embeds torch.load"),
    "kbc-ghsa-rwrf-2pqf-9j8m": ("P7", "server-supplied schema $ref fetched by the client"),
    "kbc-ghsa-4fc4-wcmh-4g8v": ("P6", "web page sets Inspector stdio command via URL params"),
    "kbc-ghsa-x39x-9qw5-ghrf": ("P8", "allowed_domains check vs fetcher URL parser"),
}
NONE_REASON = {
    "library-caller": "library-caller attacker: outside the thesis attacker list",
}
NONE_ROW = {
    "kbc-ghsa-7h8w-hj9j-8rjf": "authed user's path interpolated into a shell command: classic injection, no agent-specific guard",
    "kbc-ghsa-53gh-p8jc-7rgq": "proxy config names a module to import: config-writer position, not a path",
    "kbc-ghsa-6wvf-77m9-58rm": "authed user's template rendered in unsandboxed Jinja2: no model, gate or artefact",
}

NAMES = {
    "P1": "Model output into an interpreter",
    "P2": "Hand-rolled gate parses differently from the executor",
    "P3": "Model-chosen tool argument escapes confinement",
    "P4": "Repository or artefact at rest trusted as code",
    "P5": "Serialized object crosses a trust boundary",
    "P6": "Control plane trusts its network position",
    "P7": "Malicious MCP server makes the client a confused deputy",
    "P8": "Fetch guard lets an attacker URL into the internal network",
    "none": "fits no path",
}


# The map covers the 121-row, four-batch KBC snapshot. Later batches (KBC-E, kbc-e.jsonl) are
# not mapped by this script (see kbc-e-oos/); the filter keeps the snapshot fixed.
SNAPSHOT_BATCHES = {"backfill-2026-11", "fresh-targets", "mcp-agents", "serving-lowcode"}


def load():
    rows = []
    for f in sorted(glob.glob(os.path.join(CORPUS, "*.jsonl"))):
        if os.path.basename(f)[:-6] not in SNAPSHOT_BATCHES:
            continue
        for line in open(f, encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                r["_batch"] = os.path.basename(f)[:-6]
                rows.append(r)
    return rows


def assign(r):
    k = r["kbc"]
    rid = r["id"]
    # ids in OVERRIDE/NONE_ROW are prefixes of the full id
    for key, (p, why) in OVERRIDE.items():
        if rid.startswith(key[:22]):
            return p, "override: " + why
    for key, why in NONE_ROW.items():
        if rid.startswith(key[:22]):
            return "none", why
    if k["attacker"] in NONE_REASON:
        return "none", NONE_REASON[k["attacker"]]
    p = CELL.get((k["rd_class"], k["attacker"]))
    if p is None:
        sys.exit(f"no rule for {rid} {k['rd_class']} {k['attacker']}")
    return p, "cell default"


def main():
    rows = load()
    out = []
    for r in rows:
        p, why = assign(r)
        out.append((r["id"], r["_batch"], r["kbc"]["rd_class"], r["kbc"]["attacker"], p, why))
    c = collections.Counter(o[4] for o in out)
    n = len(out)
    mapped = n - c["none"]
    print(f"rows {n}; mapped to a path {mapped} ({mapped / n:.1%}); none {c['none']}")
    for p in ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "none"]:
        print(f"{p:5} {c[p]:3}  {NAMES[p]}")
    used = {k[:22] for k in OVERRIDE} | {k[:22] for k in NONE_ROW}
    hit = {o[0][:22] for o in out}
    stale = used - hit
    if stale:
        sys.exit(f"override ids not in corpus: {sorted(stale)}")
    if "--write" in sys.argv:
        with open(os.path.join(HERE, "kbc-path-map.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["id", "batch", "rd_class", "attacker", "path", "why"])
            w.writerows(sorted(out))
        print("wrote kbc-path-map.csv")


if __name__ == "__main__":
    main()
