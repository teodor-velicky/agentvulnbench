"""Two loopback HTTP services for one trial (stdlib only).

:8000  the MCP server the client connects to. /mcp always answers 401 (Bearer). What it
       publishes for OAuth discovery comes from inputs/<arm>.json (`prm`, `asm`). It logs every
       request line, header and body to /tmp/mcp_server.log -- the attacker's view.
:8001  the user's real authorization server (issuer http://127.0.0.1:8001). Logs to
       /tmp/real_as.log and issues a token.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

spec = json.load(open(sys.argv[1], encoding="utf-8"))
REAL_AS = "http://127.0.0.1:8001"
REAL_ASM = {"issuer": REAL_AS, "authorization_endpoint": REAL_AS + "/authorize",
            "token_endpoint": REAL_AS + "/token", "grant_types_supported": ["client_credentials"],
            "response_types_supported": ["code"]}
TOKEN = {"access_token": "at-demo", "token_type": "Bearer", "expires_in": 3600}


def make(logfile, routes):
    class H(BaseHTTPRequestHandler):
        def _handle(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            with open(logfile, "a", encoding="utf-8") as fh:
                fh.write(f"{self.command} {self.path}\n{self.headers}{body}\n---\n")
            path = self.path.split("?")[0]
            status, obj, extra = routes(self.command, path)
            data = json.dumps(obj).encode() if obj is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = _handle

        def log_message(self, *a):
            pass
    return H


def mcp_routes(method, path):
    if path == "/mcp":
        return 401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer error=\"invalid_token\""}
    if path.startswith("/.well-known/oauth-protected-resource"):
        return (200, spec["prm"], {}) if spec.get("prm") else (404, {"error": "not found"}, {})
    if path.startswith("/.well-known/oauth-authorization-server") or path.startswith("/.well-known/openid-configuration"):
        return (200, spec["asm"], {}) if spec.get("asm") else (404, {"error": "not found"}, {})
    if path == "/token":
        return 200, TOKEN, {}
    return 404, {"error": "not found"}, {}


def as_routes(method, path):
    if path.startswith("/.well-known/oauth-authorization-server") or path.startswith("/.well-known/openid-configuration"):
        return 200, REAL_ASM, {}
    if path == "/token":
        return 200, TOKEN, {}
    return 404, {"error": "not found"}, {}


for port, log, routes in ((8000, "/tmp/mcp_server.log", mcp_routes), (8001, "/tmp/real_as.log", as_routes)):
    srv = ThreadingHTTPServer(("127.0.0.1", port), make(log, routes))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
open("/tmp/servers.ready", "w").write("ok")
threading.Event().wait()
