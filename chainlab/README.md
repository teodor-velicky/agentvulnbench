# CHAINLAB

A hermetic harness that proves **model-mediated** agent-framework bugs: cases where untrusted content (a
document, web page, tool result or user message) steers an agent's LLM into output that the framework then
routes to a dangerous sink (code execution, a shell command, a query, a file path) with no guard. The attacker
never types the payload directly; they steer the model. CHAINLAB settles whether that counts as
attacker-reachable by replacing the model with a **scripted model** and proving that the framework, not the
model, is at fault.

All six cases are public, already-fixed advisories. They are the model-mediated proofs cited by the paper in
`paths-to-root/`.

## The scripted model

Each case plugs a **deterministic fake LLM** into the framework's own LLM interface (for example LangChain's
`FakeListLLM`, a `BaseLLM` subclass). It returns the attacker-chosen completion verbatim, ignoring the prompt.
A positive result therefore shows that the **framework lacks a guard**, independent of how gullible any real
model is. The rule for what the scripted model may and may not assume, and why a missing framework guard is the
finding, is the G1 rule in `paths-to-root/PAPER.md` section 2.3.

## How to run

```
python chainlab/run.py --list                                      # discovered cases
python chainlab/run.py langchain-llmmathchain-cve-2023-29374        # one case
python chainlab/run.py --all                                       # every case
```

Requires the `docker` CLI and Python 3.11+ (stdlib only). For each case the runner builds
two images from the one case `Dockerfile` — the pinned **vulnerable** and **fixed**
framework versions (build arg `PKG_VERSION`) — verifies each image holds the pinned version,
then runs three arms **5× each**:

| Arm | Image | Scripted-model response | PROVEN requires |
|---|---|---|---|
| **ATTACK** | vulnerable | attacker payload (`fixtures/attack.txt`) | canary fires 5/5 |
| **CONTROL** | vulnerable | benign, same-feature (`fixtures/control.txt`) | 0/5 |
| **FIX** | fixed | attacker payload | 0/5 |

Every trial gets a fresh container and a fresh nonce. **Every arm runs with
`--network none`** (no egress; dependencies are installed only at image build time). A case
is **PROVEN** at ATTACK 5/5 · CONTROL 0/5 · FIX 0/5 with both versions verified and no
harness or hermeticity error. Results go to `chainlab/results/<id>/proof_result.json`, whose
core shape (`finding_id`, `sink`, `sink_class`, `arms.{attack,control,fix}.{trials,
canary_hits,exfil}`, `network`, `verdict`) follows the PitSense engine's proof-result
shape; `chainlab_*` fields carry the
scripted-model provenance.

## Results

| Case | CVE / GHSA | Framework (vuln → fix) | Sink | ATTACK | CONTROL | FIX | Verdict |
|---|---|---|---|---|---|---|---|
| `langchain-llmmathchain-cve-2023-29374` | CVE-2023-29374 / GHSA-fprp-p869-w6q2 | langchain 0.0.131 → 0.0.142 | `LLMMathChain._process_llm_result` → `PythonREPL().run()` (exec) | 5/5 | 0/5 | 0/5 | **PROVEN** |
| `langchain-palchain-cve-2023-36258` | CVE-2023-36258 / GHSA-2qmj-7962-cjq8 | langchain 0.0.235 → 0.0.247 | `PALChain._call` → `PythonREPL().run()` (exec, no guard) | 5/5 | 0/5 | 0/5 | **PROVEN** |
| `langchain-experimental-palchain-cve-2023-44467` | CVE-2023-44467 / GHSA-gjjr-63x4-v8cq | langchain-experimental 0.0.23 → 0.0.24 | `PALChain._call` → `PythonREPL().run()` (exec past a bypassable `__import__` guard) | 5/5 | 0/5 | 0/5 | **PROVEN** |
| `xinference-llama3-tool-parser-ghsa-x2rj-828p-hx9m` | CVE-2026-61539 / GHSA-x2rj-828p-hx9m | xinference 2.5.0 → 2.7.0 | `Llama3ToolParser.extract_tool_calls` → `eval(model_output, {}, {})` (serving-layer parser, no guard) | 5/5 | 0/5 | 0/5 | **PROVEN** |
| `praisonai-codeagent-ghsa-2xv2-w8cq-5gxw` | CVE-2026-61447 / GHSA-2xv2-w8cq-5gxw | praisonaiagents 1.6.77 → 1.6.78 | `CodeAgent._execute_python` → `subprocess.run([python,tmp], env=os.environ.copy())` (sandbox flag ignored) | 5/5 | 0/5 | 0/5 | **PROVEN** |
| `langroid-neo4j-cypher-ghsa-2pq5-3q89-j7cc` | CVE-2026-55615 / GHSA-2pq5-3q89-j7cc | langroid 0.65.4 → 0.65.5 | `Neo4jChatAgent.cypher_retrieval_tool` → `read_query` → neo4j `session.run(<llm_cypher>)` (**SQL/Cypher sink**; read/RAG tool, auto-commit, no read-only gate) | 5/5 | 0/5 | 0/5 | **PROVEN** |

Re-run any case with `python chainlab/run.py <case-id>` (about 1 to 2 min per case if the images are
cached; the first build takes about 3 to 4 min), or `--all` for the set. Committed proofs are at
`chainlab/results/<case-id>/proof_result.json`.

## The harness is spec-driven — adding a case

The runner (`run.py`) contains **no bug-specific code**. A new reproduction is a new folder
under `chainlab/cases/<id>/`:

```
chainlab/cases/<id>/
  spec.json          framework + pinned vuln/fix versions, sink, scripted-model, canary, run commands
  Dockerfile         installs the framework at build arg PKG_VERSION; writes it to /opt/chainlab/version
  driver.py          plugs the scripted model into the framework and runs the chain end to end
  oracle.py          exit 0 iff the per-trial nonce reached the host side effect
  fixtures/attack.txt   the scripted model's attacker response (may contain {{NONCE}})
  fixtures/control.txt  a benign, same-feature scripted response
```

`spec.json` fields: `id` (= folder name), `framework{name,vuln_version,fix_version,repo}`,
`cve`, `ghsa`, `advisory_url`, `sink`, `sink_class`, `rd_class`, `attacker`,
`attacker_story`, `scripted_model{interface,plugged_into,behavior,may_assume,may_not_assume}`,
`canary`, `build{dockerfile,version_arg}`, `run{network:"none",driver,oracle,timeout}`,
`expect`. See `cases/langchain-llmmathchain-cve-2023-29374/spec.json` and
[`SPEC.md`](SPEC.md). Cases are discovered by globbing `cases/*/spec.json`; there is no
central index, so adding a case means adding a folder.

## Host safety checks

- The runner checks free disk space on the drive that holds `chainlab/` at start (needs at least 80 GB; aborts
  below 60 GB) and again before each arm. It also refuses to start while any container named `pitsense_*` (other
  than its own `pitsense_rd_*`) is running.
- Every object it creates is prefixed `pitsense_rd_chainlab_`, and all its containers and images are removed on
  exit (`--keep` keeps images to warm the cache). One stack at a time.
- Synthetic nonces only; attacks target only the local case containers.

## Limits (v0)

- **Scope.** v0 proves code/command-execution and SQL/Cypher-query model-mediated sinks. The rule that CONTROL
  must be a benign use of the same feature is the load-bearing check for this class; for a query sink the
  real-effect oracle reads a committed database side effect, never the shape of the query string.
- **Six reproductions**: LangChain LLMMathChain, PALChain and the experimental PAL `__import__` bypass (2023),
  Xinference's serving-layer `eval()` tool-call parser and PraisonAI's CodeAgent with `sandbox=True` ignored
  (2026), and the Langroid Neo4jChatAgent SQL/Cypher case. They span agent-framework, model-serving and graph-RAG
  surfaces and two sink families. A pure tool-argument to shell/file case is not covered yet.
- **Language-agnostic runner.** `driver` and `oracle` are command arrays and the case `Dockerfile` chooses the
  base image, so a non-Python case needs only its own Dockerfile, driver and oracle.
- **Version pinning, not source SHA.** CHAINLAB pins by released PyPI/npm version (the fix is a release bump)
  rather than AgentVulnBench's source-tarball-at-SHA scheme; both are deterministic. Dependency trees resolve via
  `uv --exclude-newer` so old pins still build.
