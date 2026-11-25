GHSA-7f8r-222p-6f5g (CVE-2025-49596): MCP Inspector proxy unauthenticated command execution.
createTransport() builds a StdioClientTransport from the `command`/`args` query params of GET /stdio, which had no auth or origin check, so malicious web content in the victim's browser can make the loopback proxy spawn any local process. The driver starts the real proxy and fires the attacker's cross-origin GET; the spawned `sh -c` writes /tmp/avb_canary_<nonce>.
Oracle: that canary holds `pwned-<nonce>`. Control hits the same /stdio endpoint with a benign `echo` command (no file written).
Fix 50df0e1 adds a session-token authMiddleware and an origin-validation middleware to /stdio; the unauthenticated GET gets 401, so nothing is spawned.
Run: `python bench/run.py mcp-inspector-ghsa-7f8r`.
