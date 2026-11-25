#!/usr/bin/env python
"""rankbase: LLM-free sink-danger x entry-reachability ranking baseline for AgentVulnBench v0 (locate only).

  python -I bench/tools/rankbase/adapter.py [--cases a,b] [--out-dir DIR]

See README.md (designed without the answer keys; not tuned after the first run). Stdlib only.
"""
import argparse, ast, re, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import common  # noqa: E402
from common import tool_cases, write_attempt  # noqa: E402

SKIP_DIRS = {".git", "node_modules", "tests", "test", "__tests__", "docs", "doc", "examples", "example", "cookbook",
             "migrations", "vendor", "dist", "build", "site-packages", "benchmarks", "fixtures", "e2e", "samples",
             "templates", "scripts", ".github", "venv", ".venv"}
PY_EXT, JS_EXT = {".py"}, {".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx"}
MAX_BYTES = 400_000

# (family, class, weight, regex). Weights = generic sink danger, set up front and never tuned.
PY_SINKS = [
    ("exec-eval", "code-injection", 10, r"(?<![\w.])(eval|exec)\s*\("),
    ("compile", "code-injection", 6, r"(?<![\w.])compile\s*\("),
    ("shell-true", "command-injection", 10, r"shell\s*=\s*True"),
    ("os-system", "command-injection", 10, r"\bos\.(system|popen)\s*\("),
    ("subprocess", "command-injection", 6, r"\bsubprocess\.(run|Popen|call|check_output|check_call)\s*\("),
    ("asyncio-subproc", "command-injection", 7, r"create_subprocess_(exec|shell)\s*\("),
    ("pickle", "unsafe-deserialization", 9, r"\b(pickle|cloudpickle|dill|marshal|shelve)\.(loads?|Unpickler)\b"),
    ("yaml-load", "unsafe-deserialization", 9, r"\byaml\.(load|unsafe_load|full_load)\s*\((?![^)]*SafeLoader)"),
    ("torch-load", "unsafe-deserialization", 9, r"\btorch\.load\s*\("),
    ("jinja-string", "template-injection", 7, r"\b(Template|from_string|render_template_string)\s*\("),
    ("str-format", "template-injection", 4, r"\.format(_map)?\s*\(\s*\*\*"),
    ("outbound-http", "ssrf", 5, r"\b(requests|httpx|aiohttp|urllib\.request|session|client)\.(get|post|put|request|urlopen|stream)\s*\("),
    ("urlopen", "ssrf", 5, r"\burlopen\s*\("),
    ("fs-open", "path-traversal", 4, r"(?<![\w.])open\s*\(|\.(read_text|read_bytes|write_text|write_bytes|open)\s*\("),
    ("send-file", "path-traversal", 5, r"\b(send_file|FileResponse|send_from_directory|extractall|extract)\s*\("),
    ("importlib", "code-injection", 4, r"\b(__import__|import_module)\s*\("),
    ("getattr-dyn", "code-injection", 3, r"(?<![\w.])getattr\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)"),
]
JS_SINKS = [
    ("eval", "code-injection", 10, r"(?<![\w.])eval\s*\("),
    ("new-function", "code-injection", 10, r"\bnew\s+Function\s*\("),
    ("vm", "code-injection", 9, r"\bvm\.(runIn\w+|Script|compileFunction)\b|new\s+vm\.Script"),
    ("child-exec", "command-injection", 10, r"\b(exec|execSync)\s*\("),
    ("child-spawn", "command-injection", 6, r"\b(spawn|spawnSync|execFile|execFileSync|fork)\s*\("),
    ("deser", "unsafe-deserialization", 7, r"\b(deserialize|unserialize|node-serialize|yaml\.load)\s*\("),
    ("template", "template-injection", 6, r"\b(ejs\.render|Handlebars\.compile|nunjucks\.renderString|_\.template|mustache\.render)\s*\("),
    ("outbound-fetch", "ssrf", 5, r"(?<![\w.])fetch\s*\(|\b(axios|got|request)(\.(get|post|put|request))?\s*\(|\bhttps?\.(get|request)\s*\("),
    ("fs-read", "path-traversal", 4, r"\b(fs|fsp|fs\.promises)\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync|readdir|unlink)\s*\(|\bsendFile\s*\("),
    ("dyn-import", "code-injection", 4, r"\brequire\s*\(\s*[a-zA-Z_]|\bimport\s*\(\s*[a-zA-Z_]"),
]
ROUTE_PY = re.compile(r"^\s*@\s*[\w.]*(route|get|post|put|delete|patch|websocket|tool|call_tool|handler|"
                      r"endpoint|command|callback|resource|prompt|action|register)\b", re.I)
ROUTE_JS = re.compile(r"\b(app|router|server|mcp|fastify|api)\.(get|post|put|delete|patch|all|use|tool|registerTool|"
                      r"setRequestHandler|resource|prompt)\s*\(|@(Get|Post|Put|Delete|Controller)\b|"
                      r"\bCallToolRequestSchema\b|\bDynamicStructuredTool\b")
PATH_HINT = re.compile(r"(server|api|route|router|tool|handler|mcp|endpoint|view|controller|gateway|proxy|agent)", re.I)
LITERAL_ARG = re.compile(r"\(\s*(?:[rbfu]{0,2}(['\"]).*?\1|\d+)\s*[,)]")
FN_JS = re.compile(r"function\s*\*?\s*\w*\s*\(([^)]*)\)|(?:async\s+)?\w+\s*\(([^)]*)\)\s*(?::\s*[^{=]+)?\{|"
                   r"(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>")


def skip(rel: Path) -> bool:
    if any(p in SKIP_DIRS for p in rel.parts[:-1]):
        return True
    n = rel.name
    return n.endswith((".min.js", ".d.ts", "_test.py", ".test.ts", ".spec.ts", ".test.js")) or n.startswith(("test_", "conftest"))


def py_funcs(text: str):
    """[(start, end, params:set, routed:bool)] for every function def."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    lines = text.splitlines()
    out = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = n.args
            params = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
            params |= {a.vararg.arg} if a.vararg else set()
            params |= {a.kwarg.arg} if a.kwarg else set()
            params -= {"self", "cls"}
            decos = [lines[d.lineno - 1] for d in n.decorator_list if d.lineno - 1 < len(lines)]
            out.append((n.lineno, getattr(n, "end_lineno", n.lineno), params, any(ROUTE_PY.match(d) for d in decos)))
    return out


def enclosing(funcs, ln):
    best = None
    for f in funcs:
        if f[0] <= ln <= f[1] and (best is None or f[0] >= best[0]):
            best = f
    return best


def score_file(rel: str, text: str, lang: str):
    pats = [(f, c, w, re.compile(rx)) for f, c, w, rx in (PY_SINKS if lang == "py" else JS_SINKS)]
    lines = text.splitlines()
    funcs = py_funcs(text) if lang == "py" else []
    hint = 0.5 if PATH_HINT.search(rel) else 0.0
    out = []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith(("#", "//", "*", "/*", "import ", "from ")):
            continue
        for fam, cls, w, rx in pats:
            m = rx.search(line)
            if not m:
                continue
            mult, why = 1.0 + hint, (["path-hint"] if hint else [])
            if lang == "py":
                fn = enclosing(funcs, i)
                if fn:
                    if fn[3]:
                        mult += 1.0
                        why.append("routed-fn")
                    if any(re.search(rf"\b{re.escape(p)}\b", line) for p in fn[2]):
                        mult += 1.0
                        why.append("param-in-sink")
            else:
                if ROUTE_JS.search("\n".join(lines[max(0, i - 40):i])):
                    mult += 1.0
                    why.append("route/tool-registration-near")
                names = set()
                for j in range(i - 1, max(-1, i - 60), -1):
                    mf = FN_JS.search(lines[j])
                    if mf:
                        sig = next((g for g in mf.groups() if g is not None), "")
                        names = {t.strip().split(":")[0].strip("{} .?") for t in sig.split(",") if t.strip()}
                        break
                if any(n and re.search(rf"\b{re.escape(n)}\b", line) for n in names):
                    mult += 1.0
                    why.append("param-in-sink")
            if LITERAL_ARG.match(line[m.end() - 1:]) and "param-in-sink" not in why:
                mult *= 0.4
                why.append("literal-arg")
            out.append({"file": rel, "line": i, "class": cls, "family": fam, "score": round(w * mult, 3),
                        "why": "+".join(why)})
    return out


def scan(src: Path, lang: str):
    exts = PY_EXT if lang == "python" else JS_EXT | PY_EXT
    cands = []
    for p in sorted(src.rglob("*")):
        if p.suffix not in exts or not p.is_file():
            continue
        rel = p.relative_to(src)
        if skip(rel):
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        cands += score_file(rel.as_posix(), text, "py" if p.suffix == ".py" else "js")
    by_file = {}  # per-file decay: the i-th best hit in a file keeps 1/(1+0.35 i) of its score
    for c in sorted(cands, key=lambda c: (-c["score"], c["file"], c["line"])):
        n = by_file.get(c["file"], 0)
        by_file[c["file"]] = n + 1
        c["score"] = round(c["score"] / (1 + 0.35 * n), 3)
    cands.sort(key=lambda c: (-c["score"], c["file"], c["line"]))
    return cands


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="")
    ap.add_argument("--out-dir", default=None, help="write the attempt here instead of bench/scores/v0 (reproduction check)")
    a = ap.parse_args()
    sel = set(filter(None, a.cases.split(",")))
    per = {}
    for cid, c in tool_cases().items():
        if sel and cid not in sel:
            continue
        t0 = time.monotonic()
        found = scan(c["src"], c["language"])
        per[cid] = {"ranked": found, "seconds": time.monotonic() - t0, "note": "rankbase heuristic"}
        print(f"{cid}: {len(found)} candidates in {time.monotonic() - t0:.1f}s", flush=True)
    meta = {"tool_version": "rankbase 0 (LLM-free heuristic, stdlib)",
            "ranking": "sink-danger weight x entry-reachability multiplier, per-file decay",
            "designed_without_answer_keys": True}
    if a.out_dir:
        common.SCORES = Path(a.out_dir)
    print(f"wrote {write_attempt('rankbase', per, meta, merge=bool(sel) and not a.out_dir)}")


if __name__ == "__main__":
    main()
