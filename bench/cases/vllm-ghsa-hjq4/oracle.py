"""HIT iff the victim process unpickled the attacker's object: /tmp/avb_canary (victim container) holds the nonce."""
import sys
nonce = sys.argv[1]
try:
    data = open("/tmp/avb_canary", encoding="utf-8").read()
except FileNotFoundError:
    print("no canary"); sys.exit(1)
hit = nonce in data
print("victim ran the attacker's pickle payload" if hit else "canary without nonce"); sys.exit(0 if hit else 1)
