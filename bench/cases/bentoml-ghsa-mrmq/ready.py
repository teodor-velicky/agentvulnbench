import sys, urllib.request
try:
    sys.exit(0 if urllib.request.urlopen("http://target:3000/readyz", timeout=3).status == 200 else 1)
except Exception:
    sys.exit(1)
