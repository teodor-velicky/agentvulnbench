GHSA-hvj5-mvw9-93j3 (CVE-2024-2912): BentoML unauthenticated RCE via pickle request bodies.
api_endpoint() chose the deserializer from the client's Content-Type, so application/vnd.bentoml+pickle was unpickled.
A client container on an internal-only network POSTs a pickle that runs `echo <nonce> > /tmp/pitsense_canary` in the service.
Control POSTs the same command string as ordinary JSON. Fix fd70379 rejects the pickle media type on the main service (415).
Run: `python bench/run.py bentoml-ghsa-hvj5`.
