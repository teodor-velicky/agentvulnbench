"""Scripted MCP host: launches mcp-server-git over stdio with /srv/repo as the only granted
repository, then sends the tool call the (scripted) model chose: inputs/<arm>.json.

The server lacks a guard, so a git_init call with a path outside /srv/repo still runs. The
driver speaks newline-delimited JSON-RPC, the MCP stdio framing the SDK uses.
"""
import json
import subprocess
import sys

arm, nonce = sys.argv[1], sys.argv[2]
call = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))

srv = subprocess.Popen(
    ["python", "-m", "mcp_server_git", "--repository", "/srv/repo"],
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
