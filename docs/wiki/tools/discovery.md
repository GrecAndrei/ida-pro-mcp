# Discovery

Finding your way around the binary: metadata, names, strings, imports, functions,
structured queries, semantic intelligence, architecture registers, and raw-byte inspection.

All discovery operations are read-only and require no `risk_ack`. Every operation takes
an optional `idb` parameter to target a specific open session instead of the active one.

---

## 1. Basic Reconnaissance & Listings

| Operation | Purpose | Notes |
| --- | --- | --- |
| `ida_overview` | Binary metadata, architecture, entry points, and high-level analysis context. | Best first call after opening a binary. |
| `ida_find(query=...)` | Find names, strings, imports, comments, and references matching text. | Supports `kind` filters (`strings`, `names`, `imports`, `comments`, `instructions`, `refs`). |
| `ida_list_functions(query=...)` | List functions, optionally filtered by name. | Returns address, name, size, flags. Caps with `limit`. |
| `ida_list_strings(query=...)` | List strings in the binary, optionally filtered by text. | Supports `min_length` and `limit`. |
| `ida_list_imports(query=...)` | List imported modules and APIs. | Reveals external binary dependencies and capability anchors. |
| `ida_list_segments` | List all segments with name, boundaries, size, permissions, class, and bitness. | See [Segments](segments.md). |
| `ida_list_types(query=...)` | List structs, enums, and typedefs declared in the local TIL. | See [Types](types.md). |
| `ida_list_sigs(query=...)` | List available FLIRT signature files and report which are applied. | See [Signatures](signatures.md). |

---

## 2. Advanced Search & Query Language

| Operation | Purpose | Notes |
| --- | --- | --- |
| `ida_search_data_value(value=...)` | Locate raw byte/word values, pointers, or ASCII strings across binary data. | Accepts hex scalar strings (`'0xDEADBEEF'`) or plain text. Useful when IDA xrefs do not exist. |
| `ida_search_query_lang(query=...)` | Structured search query over names, strings, imports, and functions. | Lenient grammar: `functions with size > 100`, `strings containing cmd.exe`, `calls to malloc`. |

---

## 3. Semantic Retrieval & Indexing

| Operation | Purpose | Notes |
| --- | --- | --- |
| `ida_index_functions` | Build a scoped semantic function index in responsive background slices. | Supports `query`, `ranges`, `min_size`, `max_size`, and `quality="fast"` or `"full"`. Gated in safe mode. |
| `ida_index_status(task_id=...)` | Check progress or retrieve the result of a background indexing job. | Poll with the `task_id` returned by `ida_index_functions`. |
| `ida_cancel_index(task_id=...)` | Cancel a running background semantic-index task. | Stops after the current slice. |
| `ida_semantic_search(query=...)` | Find functions by natural-language intent (e.g. "decrypts payload", "parses packet"). | Stage 1 bi-encoder recall with optional Stage 2 cross-encoder reranking (`rerank=true`). |
| `ida_reranker_status` | Report the cross-encoder reranker backend, model profile, and readiness. | Confirms whether Stage 2 semantic reranking is available. |
| `ida_function_families(query=...)` | Cluster lookalike functions by embedding cosine similarity. | Returns centroid summary, representative member, and member deltas to avoid re-reading duplicates. |

---

## 4. Processor State & Segment Registers

| Operation | Purpose | Notes |
| --- | --- | --- |
| `ida_registers` | Dump architecture registers and register classes for the current processor. | Useful for understanding ABI registers and debugger/emulation states. |
| `ida_sreg_get(start=..., reg=...)` | Read the segment-register value mapping at an address. | Key for segmented architectures (e.g. x86 `CS`/`DS`, ARM `T`, RISC-V GP). |
| `ida_sreg_list(start=...)` | List all segment-register mappings and range boundaries in effect. | Inspects compiler-generated register mode splits. |

---

## 5. Analysis Synchronization & Events

| Operation | Purpose | Notes |
| --- | --- | --- |
| `ida_auto_wait(timeout=...)` | Block until IDA's automatic analysis queue drains and becomes idle. | Ensures complete analysis before running batch pipelines or deep sweeps. |
| `ida_events(limit=...)` | Stream recent analysis and audit events from the IDB. | Useful to verify background analysis progress or mutation effects. |

---

## 6. Raw-byte inspection

For headerless ROM dumps, bootloaders, and embedded binaries, use
`ida_overview`, `ida_list_segments`, `ida_read_bytes`, and
`ida_search_data_value` to inspect the mapped image. Architecture and load-base
changes remain explicit IDA operations rather than agent-surface heuristics;
use snapshots and the existing mutation policy before changing an IDB.
