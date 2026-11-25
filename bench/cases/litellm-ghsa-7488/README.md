GHSA-7488-6r32-c95q (CVE-2026-59822): LiteLLM MCP auth falls back to anonymous "OAuth2 passthrough" whenever any Authorization header is present and LiteLLM key validation fails with 401/403.
Client (internal net, no LiteLLM key) sends `Authorization: Token not-a-litellm-key` to /mcp/notes, initializes an MCP session and calls save_note on the operator's stdio MCP server (`allow_all_keys: true`: open to every LiteLLM key, keys still required).
Oracle: /tmp/notes/n_<nonce> in the gateway container holds the nonce. Control: the same call with no Authorization header (rejected on the vuln image too), isolating the passthrough fallback.
Fix 73869f0 (1.84.0) only falls back when every targeted server is auth_type=oauth2, so the request fails closed. Note: DB-less proxy (no Postgres), so a non-Bearer header is used: a Bearer junk key hits "No connected db" (400) before the 401 path; with a DB the advisory's Bearer form takes the same fallback.
Run: `python bench/run.py litellm-ghsa-7488`.
