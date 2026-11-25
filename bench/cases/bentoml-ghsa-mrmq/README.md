GHSA-mrmq-3q62-6cc8 (CVE-2025-54381): BentoML SSRF via file-typed inputs given as a URL string.
MultipartSerde.ensure_file() downloaded any URL with httpx, with no destination check.
A client on an internal-only network sends `f=http://127.0.0.1:9999/<nonce>`; oracle: the target's loopback-only service logged the nonce path.
Control uploads real file bytes (named with the nonce) through the same multipart field; the loopback service is never contacted.
Fix 534c358 adds is_safe_url() (rejects loopback/private/link-local) before downloading. Run: `python bench/run.py bentoml-ghsa-mrmq`.
