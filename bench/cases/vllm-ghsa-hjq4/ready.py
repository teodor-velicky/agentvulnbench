"""Ready when the victim's TCPStore port accepts connections on loopback (its configured host)."""
import socket
import sys

try:
    socket.create_connection(("127.0.0.1", 29600), 2).close()
except OSError:
    sys.exit(1)
