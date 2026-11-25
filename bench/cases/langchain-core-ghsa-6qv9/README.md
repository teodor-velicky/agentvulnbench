GHSA-6qv9-48xg-fc7f (CVE-2025-65106): langchain-core mustache template injection (attribute traversal).
`_get_key` resolved dotted names with getattr() on any Python object, so a tenant-authored template `{{doc.__init__.__globals__.os.environ.AVB_APP_SECRET}}` reads the app's env.
Oracle: the rendered prompt holds the per-trial env secret sk-<nonce>-live (never in any input). Control renders `{{doc.title}}` (same object, ordinary attribute).
Fix c4b6ba2 only traverses dict/list/tuple and rejects other types, so the name renders empty. Tagged library-caller (template author is the attacker).
Run: `python bench/run.py langchain-core-ghsa-6qv9`.
