"""A local FastMCP dev server exactly as the docs show it: default host (127.0.0.1), streamable HTTP,
no explicit transport_security. One tool with a side effect, one read-only tool."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes", port=8000)


@mcp.tool()
def save_note(name: str, text: str) -> str:
    """Save a note to the local notes directory."""
    with open(f"/tmp/notes_{name}", "w", encoding="utf-8") as f:
        f.write(text)
    return "saved"


@mcp.tool()
def echo(text: str) -> str:
    """Return the text unchanged."""
    return text


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
