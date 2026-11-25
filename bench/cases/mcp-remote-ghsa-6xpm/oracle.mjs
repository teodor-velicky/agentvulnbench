// HIT iff open() launched the registered scheme handler, which wrote the per-trial canary.
// Keyed on the nonce so a stale artifact from another trial cannot cause a hit.
import * as fs from "node:fs";
const nonce = process.argv[2];
const path = `/tmp/avb_canary_${nonce}`;
let data;
try {
  data = fs.readFileSync(path, "utf-8");
} catch {
  console.log("no canary: open() did not launch the scheme handler");
  process.exit(1);
}
const hit = data.includes(`pwned-${nonce}`);
console.log(hit ? "scheme handler launched by open(): canary written" : "canary present but wrong content");
process.exit(hit ? 0 : 1);
