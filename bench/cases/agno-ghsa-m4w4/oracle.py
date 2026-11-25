"""HIT iff eval of the field_type string ran a shell command that wrote the trial nonce."""
import sys

try:
    data = open("/tmp/avbcanary", encoding="utf-8").read()
except FileNotFoundError:
    print("no canary")
    sys.exit(1)
ok = sys.argv[1] in data
print("canary matches nonce" if ok else "canary present but wrong nonce")
sys.exit(0 if ok else 1)
