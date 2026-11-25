GHSA-gf3v-fwqg-4vh7 (CVE-2026-26019): langchainjs RecursiveUrlLoader followed crawled links with no private-address check (startsWith origin test only, skipped for `//` links).
An attacker-authored page on the crawled docs site (docs.example.test, stub-resolved to 127.0.0.1) links `//127.0.0.1:9999/<nonce>`; the loader fetches the internal service.
Oracle: the loopback-only service on :9999 logged /<nonce>. Control: same page with a same-origin link `/<nonce>` (crawled on the docs site; internal service untouched).
One container, --network none, sites.mjs serves both hosts on 127.0.0.1. The docs host is served by name from the same container; the attack and control arms differ only in the link target.
Fix d5e3db0 calls validateSafeUrl() before every fetch (blocks loopback/private IPs) and uses isSameOrigin(). Run: `python bench/run.py langchainjs-ghsa-gf3v`.
