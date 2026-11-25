"""HIT iff the service process ran a shell command that wrote the trial nonce to the canary file."""
import sys
try:
    data = open("/tmp/pitsense_canary", encoding="utf-8").read()
except FileNotFoundError:
    print("no canary"); sys.exit(1)
ok = sys.argv[1] in data
print("canary", "matches nonce" if ok else "wrong nonce"); sys.exit(0 if ok else 1)
