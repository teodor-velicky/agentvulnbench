// Minimal app: persist an LLM turn by serialising the message (JSON.stringify -> toJSON),
// then restore it with @langchain/core's load(). The model controls additional_kwargs (as with
// tool-call / function_call payloads). The app keeps a real secret in its environment
// (AVB_APP_SECRET, set per trial by the harness). The restored, attacker-visible message is
// written where the app would show or forward it (/tmp/restored.json).
//
// tsx runs the TS source directly; imports resolve @langchain/core's deps from /src/node_modules.
import { AIMessage } from "/src/libs/langchain-core/src/messages/ai.js";
import { load } from "/src/libs/langchain-core/src/load/index.js";
import * as fs from "node:fs";

const [, , arm, nonce] = process.argv;
const kwargs = JSON.parse(
  fs.readFileSync(`/case/inputs/${arm}.json`, "utf-8").replaceAll("{{NONCE}}", nonce)
);
const msg = new AIMessage({ content: "ok", additional_kwargs: kwargs });
const stored = JSON.stringify(msg); // vuln toJSON does not escape the model's lc-shaped dict
let out;
try {
  const restored = await load(stored);
  out = JSON.stringify(restored?.additional_kwargs ?? restored);
} catch (e) {
  out = `load threw ${e?.constructor?.name}: ${e?.message}`;
}
fs.writeFileSync("/tmp/restored.json", out);
console.log(out.slice(0, 300));
