# Security policy

## What this repository contains

Every case in AgentVulnBench (`bench/cases/`) and every CHAINLAB reproduction (`chainlab/cases/`) is a
**public, already-fixed** vulnerability: a published GitHub Security Advisory with a released fix. No case
describes an unfixed, unpublished or embargoed bug, and none should be added (`CONTRIBUTING.md`).

The case images are **deliberately vulnerable** builds of old upstream versions. Run them only through
`bench/run.py` or `chainlab/run.py`, which use `--network none` or an internal-only Docker network, mount the
case read-only and never mount the Docker socket. Do not deploy a case image anywhere.

## Reporting a problem

Report privately, not in a public issue, if you find:

- a security problem in this repository's own code (harness, scorer, adapters, scripts), for example a way for a
  case or an attempt file to escape the harness's isolation;
- a case that turns out to describe a vulnerability that is **not** fixed in the upstream project's current
  release (an incomplete fix), or any other undisclosed vulnerability.

Use GitHub's private vulnerability reporting on this repository ("Security" tab → "Report a vulnerability"), or
e-mail **hello@pitsense.io** with "AgentVulnBench security" in the subject.

Vulnerabilities in the upstream projects themselves (LangChain, MCP servers, vLLM and so on) belong to those
projects: report them through each project's own security policy.
