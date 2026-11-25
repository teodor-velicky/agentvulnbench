"""Scripted MCP host for a repository-controlled-config case.

1. Materialise the untrusted repository: append inputs/<arm>.json `repo_config` to
   /srv/repo/.git/config (what a cloned/unpacked repo would ship).
2. Launch mcp-server-git over stdio with /srv/repo as the granted repository and send the
   read-only tool call the (scripted) model chose: `git_status`.
The driver never runs the configured program itself; only git, invoked by the server, can.
"""
import json
import subprocess
import sys

REPO = "/srv/repo"
arm, nonce = sys.argv[1], sys.argv[2]
spec = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))
with open(f"{REPO}/.git/config", "a", encoding="utf-8") as fh:
    fh.write(spec["repo_config"])

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
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": spec["call"]})
    print(json.dumps(recv(2))[:300])
finally:
    srv.terminate()
    try:
        srv.wait(timeout=10)
    except Exception:
        srv.kill()
