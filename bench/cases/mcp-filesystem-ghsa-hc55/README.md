GHSA-hc55-p739-j48w (CVE-2025-53110): @modelcontextprotocol/server-filesystem path prefix bypass.
validatePath() used `startsWith(allowedDir)`, so with /srv/allowed granted, /srv/allowed_private/x passes.
Scripted host sends the model's write_file call over stdio; oracle: nonce lands in /srv/allowed_private.
Control writes the nonce inside /srv/allowed. Fix d00c60d adds path-validation.ts (separator-aware check).
Run: `python bench/run.py mcp-filesystem-ghsa-hc55`.
Note: the fix commit also bundles the symlink fix (CVE-2025-53109 / GHSA-q66q); the exploit here is the prefix bypass only and FIX 0/5 holds. Isolated and noted per METHODOLOGY s3 exclusion rule 5.
