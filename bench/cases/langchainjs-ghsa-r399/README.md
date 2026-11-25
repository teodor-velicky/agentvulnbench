GHSA-r399-636x-v7f6 (CVE-2025-68665): @langchain/core (langchainjs) serialization injection — the JS twin of langchain-core GHSA-c67j ("LangGrinch").
toJSON did not escape user dicts shaped like {"lc":1,"type":"secret",...}, and load()'s reviver revived them from process.env. Model-controlled additional_kwargs carry the marker; the app serialises and load()s the message. Oracle: the per-trial env secret sk-<nonce>-live appears in the restored message.
Control sends an ordinary dict (it even names the env var); nothing is revived.
Fix e5063f9 escapes lc-shaped plain objects on serialization (`{"__lc_escaped__":...}`, unwrapped as plain data) and makes `secretsFromEnv` default false, so load() no longer reads process.env.
Run: `python bench/run.py langchainjs-ghsa-r399`.
