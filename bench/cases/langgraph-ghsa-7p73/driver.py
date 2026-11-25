"""Minimal multi-tenant memory app on langgraph's SqliteStore.

Two tenants store memories under ("memories", <tenant>). Bob's memory holds the app-issued API
key (AVB_APP_SECRET, set per trial). Alice calls the app's search endpoint with her own filter
(inputs/<arm>.json, {field: value}); the app scopes the search to her namespace and writes the
results she would receive to /tmp/result.json.
"""
import json
import os
import sys

from langgraph.store.sqlite import SqliteStore

arm, nonce = sys.argv[1], sys.argv[2]
user_filter = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))
with SqliteStore.from_conn_string("/tmp/store.db") as store:
    store.setup()
    store.put(("memories", "alice"), "m1", {"status": "open", "text": f"buy milk {nonce}"})
    store.put(("memories", "bob"), "m1", {"status": "open", "text": "bob api key", "key": os.environ["AVB_APP_SECRET"]})
    try:
        items = store.search(("memories", "alice"), filter=user_filter, limit=50)
        out = json.dumps([{"ns": list(i.namespace), "value": i.value} for i in items])
    except Exception as e:
        out = f"search raised {type(e).__name__}: {e}"
open("/tmp/result.json", "w", encoding="utf-8").write(out)
print(out[:300])
