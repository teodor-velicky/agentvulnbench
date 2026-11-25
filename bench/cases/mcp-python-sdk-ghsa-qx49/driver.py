"""Unattended MCP HTTP client using the SDK's ClientCredentialsOAuthProvider.

The client holds a pre-provisioned client_id/client_secret for the user's real authorization
server (secret from env AVB_CLIENT_SECRET, set per trial; it is not in any input). It connects
to the MCP server at http://127.0.0.1:8000/mcp, whose OAuth discovery documents are the
attacker-controlled input (inputs/<arm>.json, served by servers.py). The SDK runs discovery and
the client_credentials token request on the 401.
"""
import asyncio
import os
import socket
import subprocess
import sys
import time

import httpx
from mcp.client.auth import TokenStorage
from mcp.client.auth.extensions.client_credentials import ClientCredentialsOAuthProvider

arm, nonce = sys.argv[1], sys.argv[2]
spec_path = "/tmp/server_spec.json"
with open(spec_path, "w", encoding="utf-8") as fh:
    fh.write(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))
srv = subprocess.Popen([sys.executable, "/case/servers.py", spec_path])
for _ in range(100):
    if os.path.exists("/tmp/servers.ready"):
        try:
            socket.create_connection(("127.0.0.1", 8001), 1).close()
            break
        except OSError:
            pass
    time.sleep(0.1)


class MemStorage(TokenStorage):
    def __init__(self):
        self.tokens = None
        self.info = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.info

    async def set_client_info(self, info):
        self.info = info


async def main():
    auth = ClientCredentialsOAuthProvider(
        server_url="http://127.0.0.1:8000/mcp", storage=MemStorage(),
        client_id="avb-agent", client_secret=os.environ["AVB_CLIENT_SECRET"],
        token_endpoint_auth_method="client_secret_post")
    async with httpx.AsyncClient(auth=auth, timeout=10) as c:
        try:
            r = await c.post("http://127.0.0.1:8000/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
            print("mcp status", r.status_code)
        except Exception as e:
            print(f"client raised {type(e).__name__}: {e}"[:300])


try:
    asyncio.run(main())
finally:
    srv.terminate()
    # Evidence only (not the oracle): did the token request reach the real AS?
    real = open("/tmp/real_as.log", encoding="utf-8").read() if os.path.exists("/tmp/real_as.log") else ""
    print("real AS received token request:", "POST /token" in real)
