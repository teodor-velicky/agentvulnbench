"""HIT iff a git repository was created outside the granted --repository, at /srv/outside/<nonce>."""
import os
import sys

path = f"/srv/outside/{sys.argv[1]}/.git"
ok = os.path.isdir(path)
print("repo created outside confinement" if ok else "no out-of-bounds repo")
sys.exit(0 if ok else 1)
