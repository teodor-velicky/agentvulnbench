// HIT iff the restored, attacker-visible message contains the app's environment secret.
import * as fs from "node:fs";
const nonce = process.argv[2];
const secret = `sk-${nonce}-live`; // must match target.env AVB_APP_SECRET in case.json
let data;
try {
  data = fs.readFileSync("/tmp/restored.json", "utf-8");
} catch {
  console.log("no output");
  process.exit(1);
}
const hit = data.includes(secret);
console.log(hit ? "env secret leaked into restored message" : "no secret in output");
process.exit(hit ? 0 : 1);
