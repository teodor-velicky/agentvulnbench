// Hermetic resolver stub (the case's DNS): the public docs host docs.example.test resolves to
// 127.0.0.1, where sites.mjs serves it. Every other name goes to the real resolver. Same in all arms.
import dns from "node:dns";

const real = dns.lookup;
dns.lookup = function (host, opts, cb) {
  if (typeof opts === "function") { cb = opts; opts = {}; }
  if (host === "docs.example.test") {
    if (opts && opts.all) return process.nextTick(cb, null, [{ address: "127.0.0.1", family: 4 }]);
    return process.nextTick(cb, null, "127.0.0.1", 4);
  }
  return real.call(this, host, opts, cb);
};
