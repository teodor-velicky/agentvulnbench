"""HIT iff the internal-only loopback service received a request for the per-trial nonce path."""
import sys
try:
    data = open("/tmp/internal_hits", encoding="utf-8").read()
except FileNotFoundError:
    print("internal service received no requests"); sys.exit(1)
ok = f"/{sys.argv[1]}" in data
print("internal service hit with nonce path" if ok else "internal service hit, wrong path"); sys.exit(0 if ok else 1)
