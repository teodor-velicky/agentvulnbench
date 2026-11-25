"""HIT iff the program named by the repository's core.fsmonitor ran: /tmp/avb_canary holds the nonce."""
import sys
nonce = sys.argv[1]
try:
    data = open("/tmp/avb_canary", encoding="utf-8").read()
except FileNotFoundError:
    print("no canary"); sys.exit(1)
hit = nonce in data
print("repo-config program ran (canary has nonce)" if hit else "canary without nonce"); sys.exit(0 if hit else 1)
