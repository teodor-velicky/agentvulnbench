"""Ready when the proxy answers its liveliness probe on the container's own address."""
import socket
import sys
import urllib.request

host = socket.gethostbyname(socket.gethostname())
try:
    urllib.request.urlopen(f"http://{host}:4000/health/liveliness", timeout=3)
except Exception:
    sys.exit(1)
