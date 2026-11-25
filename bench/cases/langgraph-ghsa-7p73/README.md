GHSA-7p73-8jqx-23r8 (CVE-2025-64104): langgraph SqliteStore filter-key SQL injection.
`_prepare_batch_search_queries` pasted filter keys into `json_extract(value, '$.<key>')`; a key `status') = 'x' OR 1=1 OR json_extract(value, '$.status` escapes the namespace scope.
Oracle: alice's namespace-scoped search returns bob's memory with the per-trial env secret sk-<nonce>-live. Control filters on a plain key (status=open) and gets only alice's row.
Fix bc9d45b validates filter keys against `^[a-zA-Z0-9_.-]+$` (ValueError). Tagged library-caller (filter keys are app-API input).
Run: `python bench/run.py langgraph-ghsa-7p73`.
