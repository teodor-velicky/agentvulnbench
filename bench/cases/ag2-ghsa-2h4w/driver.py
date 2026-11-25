"""Scripted model + AG2 sandbox shell in restricted mode.

The developer exposes a shell to the agent with readonly=True (only read-only head commands such
as ls/cat/grep are allowed, and shell operators are rejected). The scripted model emits the
command in inputs/<arm>.txt verbatim; the driver passes it to ShellAdapter.run exactly as the
agent's tool call would.
"""
import asyncio
import sys

from ag2.tools.sandbox import LocalEnvironment
from ag2.tools.sandbox.adapter.shell import ShellAdapter

arm, nonce = sys.argv[1], sys.argv[2]
command = open(f"/case/inputs/{arm}.txt", encoding="utf-8").read().replace("{{NONCE}}", nonce).rstrip("\n")
shell = ShellAdapter(LocalEnvironment(path="/home/app/ws", cleanup=False), readonly=True)
print(asyncio.run(shell.run(command))[:300])
