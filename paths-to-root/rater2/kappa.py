"""Cohen's kappa between rater 2 (labels.csv) and rater 1 (../kbc-path-map.csv). Stdlib only.
Run: python -I paths-to-root/rater2/kappa.py [--disagreements]"""
import csv, os, sys
from collections import Counter

here = os.path.dirname(os.path.abspath(__file__))
r1 = {r["id"]: r for r in csv.DictReader(open(os.path.join(here, "..", "kbc-path-map.csv"), encoding="utf-8"))}
r2 = {r["id"]: r for r in csv.DictReader(open(os.path.join(here, "labels.csv"), encoding="utf-8"))}
assert set(r1) == set(r2), (len(r1), len(r2), sorted(set(r1) ^ set(r2))[:5])
ids = sorted(r1)
a = [r1[i]["path"] for i in ids]
b = [r2[i]["path"].strip() for i in ids]
n = len(ids)
labs = [f"P{k}" for k in range(1, 9)] + ["none"]
unk = set(a + b) - set(labs)
assert not unk, unk
po = sum(x == y for x, y in zip(a, b)) / n
ca, cb = Counter(a), Counter(b)
pe = sum(ca[l] * cb[l] for l in labs) / n ** 2
kappa = (po - pe) / (1 - pe)
# collapsed: path vs none
fa = ["path" if x != "none" else "none" for x in a]
fb = ["path" if x != "none" else "none" for x in b]
po2 = sum(x == y for x, y in zip(fa, fb)) / n
c1, c2 = Counter(fa), Counter(fb)
pe2 = sum(c1[l] * c2[l] for l in ("path", "none")) / n ** 2
kappa2 = (po2 - pe2) / (1 - pe2) if pe2 < 1 else float("nan")
# agreement restricted to rows both place on a path
both = [(x, y) for x, y in zip(a, b) if x != "none" and y != "none"]
print(f"n={n}")
print(f"raw agreement = {po:.4f} ({sum(x==y for x,y in zip(a,b))}/{n})")
print(f"cohen kappa (9 labels) = {kappa:.4f}  (pe={pe:.4f})")
print(f"path-vs-none: agreement = {po2:.4f}, kappa = {kappa2:.4f}")
print(f"agreement where both assign a path = {sum(x==y for x,y in both)/len(both):.4f} ({sum(x==y for x,y in both)}/{len(both)})")
print("\nper-path coverage (rows1 / rows2 / both-agree):")
for l in labs:
    print(f"  {l:5s} {ca[l]:3d} {cb[l]:3d} {sum(1 for x,y in zip(a,b) if x==y==l):3d}")
print("\nconfusion (rows = rater1 map, cols = rater2):")
print("      " + "".join(f"{l:>6s}" for l in labs))
for x in labs:
    print(f"{x:5s} " + "".join(f"{sum(1 for p,q in zip(a,b) if p==x and q==y):6d}" for y in labs))
if "--disagreements" in sys.argv:
    print("\ndisagreements: id | rater1 | rater2 | class | rater2 reason")
    for i, x, y in zip(ids, a, b):
        if x != y:
            print(f"{i} | {x} | {y} | {r1[i]['rd_class']} | {r2[i]['reason']}")
