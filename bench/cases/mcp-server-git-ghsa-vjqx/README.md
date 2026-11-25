GHSA-vjqx-cfc4-9h6v (CVE-2026-27735): mcp-server-git git_add path traversal.
git_add staged files via `repo.index.add(files)` with no confinement check, so a model can pass `../outside/<nonce>.txt` and stage a file outside the granted --repository. Scripted MCP host forwards the model's git_add call over stdio; the driver first creates the victim file on disk.
Oracle: the /srv/repo index holds a '../'-escaping entry carrying the nonce (`git ls-files`). Control stages `work_<nonce>.txt` inside the repo (benign, no escape).
Fix 862e717 switches git_add to `repo.git.add("--", *files)`; the git CLI rejects paths outside the repository ("fatal: ... is outside repository"), so nothing is staged.
Run: `python bench/run.py mcp-server-git-ghsa-vjqx`.
