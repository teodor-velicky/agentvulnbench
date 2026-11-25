// HIT iff the proxy spawned the attacker's command, which wrote the per-trial canary file.
// Keys on the nonce so a stale artifact cannot cause a hit (each trial is a fresh container).
import * as fs from "node:fs";
const nonce = process.argv[2];
const path = `/tmp/avb_canary_${nonce}`;
let data;
try {
  data = fs.readFileSync(path, "utf-8");
} catch {
  console.log("no canary: command was not executed");
  process.exit(1);
}
const hit = data.includes(`pwned-${nonce}`);
console.log(hit ? "command executed: canary written by spawned process" : "canary present but wrong content");
process.exit(hit ? 0 : 1);
