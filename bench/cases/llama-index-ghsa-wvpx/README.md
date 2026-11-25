GHSA-wvpx-g427-q9wc (CVE-2024-3098): llama-index PandasQueryEngine code execution via safe_exec/safe_eval.
_get_restricted_globals builds globals from ALLOWED_BUILTINS but never sets '__builtins__', so exec/eval auto-inject the real builtins module; model code reaches bare exec() with no underscores, defeating the DunderVisitor check.
Oracle: the escaped code runs `os.system` and writes the nonce to /tmp/avbcanary. Control is a benign pandas expression over the same parser.
Fix 2c92e88 extends DunderVisitor to reject any builtin outside ALLOWED_BUILTINS and bans imports, so bare exec is blocked.
Run: `python bench/run.py llama-index-ghsa-wvpx`.
