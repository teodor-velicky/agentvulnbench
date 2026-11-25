"""HIT iff alice's search result contains bob's secret (cross-tenant read)."""
import sys
secret = f"sk-{sys.argv[1]}-live"  # must match target.env AVB_APP_SECRET in case.json
try:
    data = open("/tmp/result.json", encoding="utf-8").read()
except FileNotFoundError:
    print("no output"); sys.exit(1)
hit = secret in data
print("other tenant's secret in result" if hit else "no foreign secret in result"); sys.exit(0 if hit else 1)
