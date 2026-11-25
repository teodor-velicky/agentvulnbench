"""HIT iff the server-side save_note tool ran for the rebinding page and wrote the per-trial nonce."""
import glob, sys
hits = [p for p in glob.glob("/tmp/notes_*") if sys.argv[1] in open(p, encoding="utf-8").read()]
print("note written by cross-site request:" if hits else "no note with nonce", hits); sys.exit(0 if hits else 1)
