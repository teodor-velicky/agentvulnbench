"""The operator's internal MCP server behind the LiteLLM gateway (stdio). `save_note` has a side
effect (writes /tmp/notes/<name>), so a call that reaches it is observable."""
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def save_note(name: str, text: str) -> str:
    """Save a note to the team's internal notes store."""
    os.makedirs("/tmp/notes", exist_ok=True)
    safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_")
    with open(f"/tmp/notes/{safe}", "w", encoding="utf-8") as fh:
        fh.write(text)
    return "saved"


@mcp.tool()
def echo(text: str) -> str:
    """Echo text back (read-only)."""
    return text


if __name__ == "__main__":
    mcp.run()
