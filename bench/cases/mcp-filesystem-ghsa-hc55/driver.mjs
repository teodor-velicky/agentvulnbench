// Scripted MCP host: launches server-filesystem over stdio with /srv/allowed as the only
// allowed directory, then sends the tool call the (scripted) model chose: inputs/<arm>.json.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";

const [arm, nonce] = process.argv.slice(2);
const call = JSON.parse(readFileSync(`/case/inputs/${arm}.json`, "utf8").replaceAll("{{NONCE}}", nonce));
const srv = spawn("node", ["/src/src/filesystem/dist/index.js", "/srv/allowed"], { stdio: ["pipe", "pipe", "inherit"] });
let buf = "";
const waiters = new Map();
srv.stdout.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && waiters.has(msg.id)) { waiters.get(msg.id)(msg); waiters.delete(msg.id); }
  }
});
let nextId = 1;
const rpc = (method, params) => new Promise((res) => {
  const id = nextId++; waiters.set(id, res);
  srv.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
});
const timer = setTimeout(() => { console.log("timeout"); srv.kill(); process.exit(2); }, 30000);
await rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "avb-driver", version: "0" } });
srv.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
const res = await rpc("tools/call", call);
console.log(JSON.stringify(res).slice(0, 300));
clearTimeout(timer); srv.kill(); process.exit(0);
