GHSA-6hqx-gqrx-c5r2: mcp-server-git ran git with the repository's own .git/config trusted (config-exec wave, head of chain).
A cloned/unpacked repo's `core.fsmonitor` names a shell command; the agent's read-only `git_status` makes git run it as the server user.
Oracle: /tmp/avb_canary holds the nonce (written only by the fsmonitor program). Control ships a benign repo config (user.name with the nonce) and makes the same git_status call.
Fix a4a43ac adds harden_repo(): GIT_CONFIG_COUNT overrides (core.fsmonitor=false, hooks off, ...) so the repo value is ignored.
Run: `python bench/run.py mcp-server-git-ghsa-6hqx`.
