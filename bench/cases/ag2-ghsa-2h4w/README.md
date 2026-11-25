GHSA-2h4w-29cv-2cmv (CVE-2026-113663): AG2 restricted shell (readonly=True / allowed=[...]) newline bypass.
The restricted-mode filter checks only the head command against the allow-list and rejects a denylist of shell operators that omitted `\n`/`\r`/`&`; the whole string then runs via `sh -c`, so `ls /home/app/ws\ntouch /tmp/avb_canary_<nonce>` runs touch (the head needs a trailing space to match `ls`).
Oracle: /tmp/avb_canary_<nonce> exists. Control: an allowed read-only command naming the same path (`ls /tmp/avb_canary_<nonce>`), which only lists.
Fix 3cd8672 (1.1.1) adds `\n`, `\r`, `&`, `<` to the operator list and runs restricted commands as parsed argv without a shell, so the attack is rejected.
Run: `python bench/run.py ag2-ghsa-2h4w`.
