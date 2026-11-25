"""HIT iff the MCP server (attacker) received the client's secret for the real authorization server."""
import sys
secret = f"cs-{sys.argv[1]}-live"  # must match target.env AVB_CLIENT_SECRET in case.json
try:
    data = open("/tmp/mcp_server.log", encoding="utf-8").read()
except FileNotFoundError:
    print("no MCP server log"); sys.exit(1)
hit = secret in data
print("client_secret reached the MCP server" if hit else "MCP server never saw the client secret"); sys.exit(0 if hit else 1)
