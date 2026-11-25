"""HIT iff git_add staged a path that escapes the granted repository (a '../' entry) carrying
the per-trial nonce. Reads the committed-nothing index via `git ls-files` in /srv/repo.

A benign add of a file *inside* the repo (control) stages `work_<nonce>.txt`, which has no
'../' prefix, so it does not match -- the oracle keys on the confinement escape, not merely on
the nonce being present somewhere in the index.
"""
import subprocess
import sys

nonce = sys.argv[1]
out = subprocess.run(["git", "-C", "/srv/repo", "ls-files"],
                     capture_output=True, text=True).stdout
escaped = [ln for ln in out.splitlines() if ln.startswith("../") and nonce in ln]
if escaped:
    print(f"out-of-bounds path staged in /srv/repo index: {escaped[0]}")
    sys.exit(0)
print("no out-of-bounds entry in index")
sys.exit(1)
