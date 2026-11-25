GHSA-rvqx-wpfh-mfx7 (CVE-2025-3248, CISA KEV): Langflow POST /api/v1/validate/code had no auth and exec()'d submitted function definitions.
A client on an internal-only network sends, with no credentials, a function whose default argument runs `echo <nonce> > /tmp/pitsense_canary`.
Oracle: the canary in the server container holds the nonce. Control: same endpoint, same text as an inert string default (no call).
Server runs with LANGFLOW_AUTO_LOGIN=False (the login-protected deployment the advisory is about; with auto-login on, anyone can mint a token).
Fix faac4db adds CurrentActiveUser to the route, so the unauthenticated request gets 403. Run: `python bench/run.py langflow-ghsa-rvqx`.
