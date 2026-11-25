"""Victim: rank 0 of a vLLM StatelessProcessGroup (the group PyNcclPipe KV transfer builds).

The operator configures the group's host as 127.0.0.1 (only local peers should join), port 29600,
world size 2. Rank 0 creates the TCPStore server and then receives one object from rank 1 with
recv_obj (pickle.loads of the stored bytes), as KV-transfer metadata exchange does.
"""
from vllm.distributed.utils import StatelessProcessGroup

pg = StatelessProcessGroup.create(host="127.0.0.1", port=29600, rank=0, world_size=2,
                                  store_timeout=3600)
open("/tmp/victim.joined", "w").write("ok")
obj = pg.recv_obj(src=1)
print("victim received", type(obj).__name__, flush=True)
import threading  # noqa: E402
threading.Event().wait()
