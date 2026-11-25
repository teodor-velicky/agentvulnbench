"""HIT iff the unpickled gadget ran its OS command: /tmp/avb_canary holds this trial's nonce."""
import sys

nonce = sys.argv[1]
try:
    got = open("/tmp/avb_canary", encoding="utf-8").read().strip()
except FileNotFoundError:
    print("no canary file (no code execution)")
    sys.exit(1)
if got == nonce:
    print("canary holds the per-trial nonce: pickle gadget executed")
    sys.exit(0)
print(f"canary mismatch: {got!r} != {nonce!r}")
sys.exit(1)
