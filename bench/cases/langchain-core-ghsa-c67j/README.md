GHSA-c67j-w6g6-q2cm (CVE-2025-68664, "LangGrinch"): langchain-core serialization injection.
dumps() did not escape user dicts shaped like {"lc":1,"type":"secret",...}; loads() then revived them from os.environ.
Model-controlled additional_kwargs carry the marker; oracle: the per-trial env secret appears in the restored message.
Control sends an ordinary dict (it even names the env var). Fix 5ec0fa6 escapes lc-shaped dicts on dump.
Run: `python bench/run.py langchain-core-ghsa-c67j`.
