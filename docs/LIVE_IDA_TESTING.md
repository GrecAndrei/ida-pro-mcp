# Live IDA integration testing

`pytest -q` intentionally does not start IDA. The public agent surface has a
separate opt-in test suite that runs the real stdio MCP server, launches IDA,
and calls every advertised `ida_*` operation through JSON-RPC.

```bash
python scripts/run_live_agent_surface.py --ida-dir /path/to/ida
```

The runner compiles a temporary ELF fixture with known functions, caller and
callee relationships, imports, strings, and a safe mutation target. It uses a
temporary runtime directory, so the checkout and existing IDBs are untouched.

To use a representative sample instead, provide a binary explicitly:

```bash
python scripts/run_live_agent_surface.py \
  --ida-dir /path/to/ida \
  --binary /path/to/sample.exe
```

The suite verifies the complete public operation set:

- session open/state/status/close and `ida_help`;
- discovery, indexing, semantic search, functions, strings, imports, and text
  search;
- decompilation, disassembly, cross-references, callers, and callees;
- rename/comment mutations and durable findings;
- strict invalid-argument handling and a real continuation token round trip.

Semantic coverage uses the configured local embedding profile. By default this
is `qwen3-embedding-0.6b`; an explicit Zembed run can be selected without
changing the installed client configuration:

```bash
python scripts/run_live_agent_surface.py --ida-dir /path/to/ida \
  --embed-profile zembed-1 --embed-model /path/to/zembed-1-Q4_K_M.gguf
```

The suite also starts a separate real-IDA session with embeddings disabled and
verifies that indexing fails clearly instead of reporting a nonexistent index.
For a CPU model comparison, run the suite once per profile in a clean runtime
directory and record total indexing time, peak `llama-server` RSS, and the
top semantic hits for the same queries. Zembed 1 is CC-BY-NC-4.0 and must only
be used where that non-commercial license is acceptable.

It is intentionally opt-in. A missing or unusable IDA install fails an
explicit live run, while ordinary unit/contract test runs skip it.
