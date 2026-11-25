GHSA-6v92-r5mx-h5fx (CVE-2025-5120): smolagents LocalPythonExecutor sandbox escape.
Scripted model emits `list(map(getattr, [warnings], ["sys"]))[0]`, which skips the module allowlist and reaches `sys.modules["os"].system`.
Oracle: the shell command writes the trial nonce to /tmp/pitsense_canary. Control uses the same path on `warnings.warn`.
Fix 33a942e wraps callables so indirect getattr re-checks forbidden modules. Run: `python bench/run.py smolagents-ghsa-6v92`.
