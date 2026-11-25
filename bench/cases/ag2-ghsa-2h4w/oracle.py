"""HIT iff a non-allow-listed command ran through the read-only shell: /tmp/avb_canary_<nonce> exists."""
import os
import sys
p = f"/tmp/avb_canary_{sys.argv[1]}"
hit = os.path.exists(p)
print(f"{p} created" if hit else "no canary"); sys.exit(0 if hit else 1)
