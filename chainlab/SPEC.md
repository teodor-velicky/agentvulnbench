# CHAINLAB case spec format (`chainlab-case/0`)

A case is a folder `chainlab/cases/<id>/` containing `spec.json`, a `Dockerfile`, a
`driver.py`, an `oracle.py`, and `fixtures/{attack,control}.txt`. The runner
(`chainlab/run.py`) discovers cases by globbing `cases/*/spec.json`; there is no central
index. The runner has no bug-specific code — everything a case needs is in its folder.

## `spec.json` fields

| Field | Req | Meaning |
|---|---|---|
| `schema` | yes | `"chainlab-case/0"` |
| `id` | yes | must equal the folder name |
| `version` | yes | case revision string; bump on any input/Dockerfile/oracle change |
| `title` | no | one line |
| `cve`, `ghsa`, `advisory_url` | yes (`cve`/`ghsa` may be null, not both) | provenance; public, already-fixed only |
| `framework` | yes | `{name, vuln_version, fix_version, repo}` — the two **released** versions, pinned |
| `sink` | yes | `file:symbol` of the framework sink the fixed version changes |
| `sink_class` | yes | one of `code-exec`, `unsafe-deserialization`, `ssrf-url-fetch`, `path-traversal`, … (mapped to PitSense's enum in results) |
| `rd_class` | yes | KBC class, e.g. `prompt-injection-to-tool` |
| `attacker` | yes | `untrusted-llm-input` for model-mediated cases |
| `attacker_story` | yes | one paragraph: which untrusted content would make a real model emit the attack output |
| `scripted_model` | yes | `{interface, plugged_into, behavior, may_assume, may_not_assume}` — the fake-LLM contract (see the G1 rule, `paths-to-root/PAPER.md` section 2.3) |
| `injected_content`, `benign_content` | no | relative paths to the fixtures (documentation; the driver reads `fixtures/<arm>.txt`) |
| `canary` | yes | `{kind, mechanism}` — the host side effect the oracle observes |
| `build` | yes | `{dockerfile, version_arg, context?}`; `version_arg` default `PKG_VERSION` |
| `run` | yes | `{network:"none", driver:[...], oracle:[...], timeout?, env?}`; placeholders `{arm}` (fixture name) and `{nonce}` |
| `expect` | no | override expected hits; v0 cases use the default `{attack:5, control:0, fix:0}` |

## Contract the files must honour

- **Dockerfile.** One file, parametrised by `--build-arg <version_arg>=<version>`. It installs
  the framework at that version and writes the version to `/opt/chainlab/version` (the runner
  verifies it per image). Resolve old dependency trees with `uv pip install --exclude-newer
  <date just after the fix release>` so vuln pins still build. Base image pinned by digest.
- **driver.py `<arm> <nonce>`.** Reads `fixtures/<arm>.txt`, substitutes `{{NONCE}}`, builds
  the **scripted model** from the framework's own LLM interface, plugs it into the framework
  component, and runs the chain/agent end to end. Catches exceptions (the fixed version is
  expected to reject the attack input).
- **oracle.py `<nonce>`.** Exit 0 (HIT) iff the per-trial nonce reached a **host side effect**
  (file written, secret read back, process state) — never the chain's own stdout, and keyed on
  the fresh nonce so a stale artifact cannot cause a false hit.
- **fixtures.** `attack.txt` is the scripted model's attacker response; `control.txt` is a
  **benign response that exercises the same feature/path** (the load-bearing discriminator for
  the model-mediated class — see the G1 rule (`paths-to-root/PAPER.md` section 2.3)). Both may contain `{{NONCE}}`.

## Proof rule

With 5 trials per arm: **PROVEN** iff ATTACK 5/5, CONTROL 0/5, FIX 0/5, both framework
versions verified from `/opt/chainlab/version`, every trial's `NetworkMode == "none"`, and no
harness error. Mirrors PitSense's 3-arm standard. The result (`chainlab/results/<id>/
proof_result.json`) is PitSense-`proof_result`-shaped plus `chainlab_*` provenance.

## Inclusion / exclusion

Same spirit as AgentVulnBench (`bench/SPEC.md §8`): public, already-fixed advisory with known
vuln and fix releases; builds CPU-only offline at run time; 3-arm proof deterministic. Exclude
unfixed/disputed/by-design advisories, anything needing a GPU/model weights/paid API/live
network service, and any case whose only oracle is the model's own behaviour.
