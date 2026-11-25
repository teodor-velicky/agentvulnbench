import socket, sys
try:
    socket.create_connection(("127.0.0.1", 8000), timeout=2).close(); sys.exit(0)
except OSError:
    sys.exit(1)
