GHSA-m4w4-3r8h-jw98 (CVE-2026-35002): agno eval()s a tool schema's field_type string.
In Model.run_function_calls, a get_user_input call's user_input_fields[].field_type is passed to eval() with only (NameError, SyntaxError) caught, so a model-chosen string runs arbitrary Python while the HITL input schema is built.
Oracle: the eval runs os.system and writes the nonce to /tmp/avbcanary. Control sends a benign bare-name field_type through the same eval (NameError, no side effect).
Fix cbf6755 replaces eval with a fixed type_mapping lookup (defaulting to str), so the payload no longer executes.
Run: `python bench/run.py agno-ghsa-m4w4`.
