GHSA-5cgr-j3jf-jw3v (CVE-2025-68143): mcp-server-git git_init escapes the --repository confinement.
call_tool handles git_init before the repo check and passes arguments["repo_path"] straight to git.Repo.init, so a model can create a repo at any absolute path. Scripted MCP host forwards the model's git_init call over stdio.
Oracle: a .git appears at /srv/outside/<nonce>, outside the granted /srv/repo. Control inits inside /srv/repo (benign).
Fix eac56e7 removes the git_init tool; the fixed call_tool runs git.Repo(repo_path) first, which raises on the nonexistent outside path (no repo created).
Run: `python bench/run.py mcp-server-git-ghsa-5cgr`.
