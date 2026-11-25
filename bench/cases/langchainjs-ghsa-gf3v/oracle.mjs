// HIT iff the loopback-only internal service received a request for /<nonce>.
import fs from "node:fs";

let data = "";
try {
  data = fs.readFileSync("/tmp/internal_hits", "utf-8");
} catch {
  console.log("internal service received no requests");
  process.exit(1);
}
const ok = data.split("\n").includes(`/${process.argv[2]}`);
console.log(ok ? "internal service hit with nonce path" : "internal service hit, wrong path");
process.exit(ok ? 0 : 1);
