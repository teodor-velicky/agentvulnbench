GHSA-9h52-p55h-vw2f (CVE-2025-66416): FastMCP streamable-HTTP servers on localhost had no Host/Origin (DNS-rebinding) check by default.
A rebound web page (Host/Origin rebind.attacker.test:8000, resolving to 127.0.0.1) initializes a session and calls the local `save_note` tool with the nonce.
Oracle: /tmp/notes_* holds the nonce. Single container, everything on 127.0.0.1, --network none; the driver plays the browser.
Control: the same rebinding page calls the read-only `echo` tool with the nonce (request path exercised, no side effect).
Fix d3a1841 auto-enables Host/Origin validation for 127.0.0.1/localhost, so the forged Host gets 421. Run: `python bench/run.py mcp-python-sdk-ghsa-9h52`.
