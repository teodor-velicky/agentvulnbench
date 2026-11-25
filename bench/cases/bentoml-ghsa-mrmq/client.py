"""Unauthenticated remote client on the internal network. POSTs inputs/<arm> as multipart/form-data
to the service's file-typed endpoint: either a URL string (attack) or inline file bytes (control)."""
import json
import sys
import urllib.error
import urllib.request

arm, nonce, host = sys.argv[1], sys.argv[2], sys.argv[3]
spec = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))
b = "avbboundary" + nonce
if spec["kind"] == "url":
    part = f'Content-Disposition: form-data; name="f"\r\n\r\n{spec["url"]}\r\n'.encode()
else:
    part = (f'Content-Disposition: form-data; name="f"; filename="{spec["filename"]}"\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n{spec["content"]}\r\n').encode()
body = f"--{b}\r\n".encode() + part + f"--{b}--\r\n".encode()
req = urllib.request.Request(f"http://{host}:3000/size", data=body, method="POST",
                             headers={"Content-Type": f"multipart/form-data; boundary={b}"})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print(r.status, r.read()[:200])
except urllib.error.HTTPError as e:
    print(e.code, e.read()[:300])
