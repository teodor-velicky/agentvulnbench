import sys, urllib.request
try:
    sys.exit(0 if urllib.request.urlopen("http://target:7860/health", timeout=3).status == 200 else 1)
except Exception:
    sys.exit(1)
