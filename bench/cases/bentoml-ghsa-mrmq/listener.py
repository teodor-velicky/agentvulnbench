"""Internal-only HTTP service on 127.0.0.1:9999 inside the target container (the SSRF victim).
Logs every request path it receives to /tmp/internal_hits; nothing outside the container can reach it."""
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        with open("/tmp/internal_hits", "a", encoding="utf-8") as f:
            f.write(self.path + "\n")
        body = b"internal-admin-data"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", 9999), H).serve_forever()
