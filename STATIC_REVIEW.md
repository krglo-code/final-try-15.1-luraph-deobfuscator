# Static review utility

Run `python static_review.py path/to/script.lua` to produce a JSON triage report.
Use `-o report.json` to save it.

This utility only reads source bytes and extracts visible indicators and literal
strings. It does **not** execute Lua/Luau, invoke `loadstring`, decrypt runtime
constants, defeat anti-tamper checks, or reconstruct Luraph VM bytecode.

The included Luraph pipeline contains dynamic harness/REPL components. Treat
unknown input as untrusted: do not run sandbox or devirtualization modes on
scripts you do not own or have permission to analyze. A static report is not
proof that a script is safe, and missing indicators do not prove it is benign.

Luraph 15.1/SuperFlow full source recovery is not guaranteed. The existing
v15.1 compatibility shim and implementation directory are both checked by
`perfect_audit.py`; the audit is structural and does not certify deobfuscation
accuracy.
