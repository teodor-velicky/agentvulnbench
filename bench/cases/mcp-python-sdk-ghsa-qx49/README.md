GHSA-qx49-fqc8-xw99 (CVE-2026-115563): MCP python-sdk OAuth client lets the MCP server choose where client credentials go.
A malicious server publishes no PRM (legacy path) and serves AS metadata whose `issuer` is the user's real AS but whose token_endpoint is its own; ClientCredentialsOAuthProvider POSTs the pre-provisioned client_secret there.
Oracle: the MCP server's (attacker's) request log holds cs-<nonce>-live (env-only secret). Control: an honest server whose PRM names the real AS; the secret goes to the real AS (127.0.0.1:8001), never to the MCP server.
Fix 3eed7ce (1.30.0) computes the expected issuer before discovery (PRM AS, or the resource origin on the legacy path) and rejects metadata whose issuer differs (OAuthFlowError), so no token request is sent.
Run: `python bench/run.py mcp-python-sdk-ghsa-qx49`.
