# Codebase Audit — `ida-pro-mcp`

**Snapshot:** `master` @ `ebdb601` (2026-06-07)
**Author of audit:** opencode (model `minimax-m3-free`)
**Scope:** full source tree under `src/ida_pro_mcp/` (193 files, ~102K LOC) and `tests/` (134 files, ~33K LOC). Some files were read end-to-end; others were read via sub-agent reviews that I have cross-checked. Files I did not open line-by-line are listed in Appendix C; treat findings there as "consensus across two reviewers".

---

## 0.1 Quick Wins Applied (2026-06-07, branch `audit/quick-wins`)

After the audit was written, 6 parallel workstreams (1A–1F) fixed ~40 findings across 38 commits. **1656 tests pass, 68 skip, 11 pre-existing failures unrelated to this pass.** A summary of what changed, organized by workstream.

### 1A — Memory tool / RPC security / BYPASS_SYNC scoping
| Finding | Fix | Commit |
|---|---|---|
| §2.1 [Critical] memory tool path traversal | `realpath` allowlist + size cap + sanitized error | `39a97d1` |
| §2.8 [High] `_send_rpc_raw` size cap | 64 MB cap via `IDA_MCP_MAX_RPC_BYTES` | `0ec56bd` |
| §1.12 [High] process-group Popen flags | `start_new_session=True` on all Popen sites | `bc48665` |
| §1.7 (partial) [High] BYPASS_SYNC scope | Removed unconditional global knob; added `bypass_sync()` context manager in `sync.py` | `229bb75` |
| §1.7 (partial) kernel version parse | Defensive `_parse_kernel_version()` handles `"9.0.beta1"` | (part of `229bb75`) |

### 1B — Persistence hardening
| Finding | Fix | Commit |
|---|---|---|
| §3.1 [High] tmp+rename without fsync | `f.flush(); os.fsync(f.fileno())` before `os.replace` in 3 session write paths | `a8157a4` |
| §3.2 [High] BlackboardStore connections | `with closing(self._conn())` on all public methods | `d796af5` |
| §5.11 [High] `idb.py:201` `min_ea=0` bug | Guard uses `is not None` instead of truthy check | `a832f81` |
| §3.4 [Medium] `needs_rebuild` destructive DELETE | Transactional DELETE + commit; exception is surfaced | `85c7c60` |

### 1C — `trace_analysis.py` emulator (13 commits)
| Finding | Fix | Commit |
|---|---|---|
| §5.1 (1) hardcoded 64-bit mask | Parameterized `EMU_ARCH_MASK` per instance | `c24535a` |
| §5.1 (2) jb/jae on SF not CF | Corrected to `cf` flag | `e0f9aef` |
| §5.1 (3) sar mask | `operand_width` mask | `db6e0c2` |
| §5.1 (4) shift count mask | 5-bit / 6-bit by operand width | `2e1a23a` |
| §5.1 (5) address window collisions | Named constants at module top | `5e2acaf` |
| §5.1 (6) unmapped byte detection | `safe_get_byte()` returns `None` for unmapped | `8d3977c` |
| §5.1 (7) hex address parser | Added `radix` parameter | `2b80bc1` |
| §5.1 (8) call clobbers rsp | rsp adjustment on call/ret | `9261630` |
| §5.1 (9) missing branch mnemonics | Added jg/jl/jge/jle/ja/jbe/jo/jno/js/jns/jp/jnp/jcxz | `20da79e` |
| §5.1 (10) speculative_explore cap | `truncated=True` flag surfaced | `60b0d8d` |
| §5.1 (11) opaque_predicates conflict | Warning on overwrite | `0dd913a` |
| §5.1 (12) addr formatting | Normalized to hex strings | `100d333` |
| §5.1 (13) MOV_MNEMONICS missing | Defined `PEB_RELEVANT_MOV_MNEMONICS` (uppercase) | `5514cb8`, `5e38ef9` |

### 1D — Intelligence dispatch hardening
| Finding | Fix | Commit |
|---|---|---|
| §2.2 [Critical] blackboard_federate path validation | `IDA_MCP_FEDERATION_ALLOWED_ROOTS` env-var allowlist | `f9b728f` |
| §5.2 [Critical] recursive dispatch | Replaced 3 recursive sites with direct handler call refactor | `4b56dc5` |
| §5.2 [Medium] decompile without init_hexrays_plugin | `_safe_decompile()` helper on all 5 call sites | `ed3aa6d` |
| §5.2 [Medium] empty idb_path | Raise on empty path instead of writing to CWD | `4b07d7f` |
| blackboard_federate was dead code | Added to structural-action gate tuple (action now actually runs) | (part of `f9b728f`) |

### 1E — Test infrastructure + test body cleanup
| Finding | Fix | Commit |
|---|---|---|
| §7.11 [Medium] pytest-timeout not in deps | Added `pytest-timeout>=2.3.0` to dev deps | `e48cd0d` |
| §7.12 [Medium] test_mcp_comprehensive ignored | Removed from `addopts --ignore` list | `1e813d7` |
| §7.7 [High] `>=` instead of `==` | 5 sites tightened to `==` with descriptive error messages | `8ee0126` |
| §7.3 [High] `tempfile.mktemp` | 15 sites replaced with `NamedTemporaryFile` | `f880983` |
| §7.8, §7.9 [High] conftest fixtures + env vars | `tmp_session_dir` fixture; forced env var setup before module-scoped fixtures | `8df69d7` |
| §7.2 [Critical] sys.modules teardown | Converted to `monkeypatch.setitem` with auto-undo | `3ea60b0` |
| §7.4 [High] max_open_disputes=1000 | Documented with rationale comment | `66eab09` |
| §7.5 [High] _execute_tool assignment teardown | 20 bare assignments converted to `with _patched_attrs(...)` | `d7540c7` |
| §7.17 [Low] pythonpath | Added `pythonpath = ["."]` to pytest config for `_isolated_repo_loader` | (part of `1e813d7`) |

### 1F — Installer atomicity
| Finding | Fix | Commit |
|---|---|---|
| §6.1 [High] installer crash logging | Log traceback on main() exception | `9c8eec0` |
| §6.2 [High] kill_ida_processes filter | Scoped to target binary path via `--ida-binary-path` | `a20634f` |
| §6.3 [High] zip-slip + size cap | `MAX_DOWNLOAD_SIZE` guard; path traversal rejection; streaming read | `812d1e3` |
| §6.4 [High] MCP config not atomic | `_atomic_write_text` helper: tmp → fsync → replace | `dc59446` |
| §6.5 [High] symlink guard + version parse | `Path.resolve()` guard; defensive `parse_version()` regex | `76221a0` |
| §6.8 [Medium] find_embed_model scope | Restricted to `~/Downloads/ida-pro-mcp/` | `1ed390f` |
| §6.9 [Medium] run_checked timeout | Added `timeout` parameter (default 300s) | `da910af` |

### Pre-existing failures not addressed (11 total)
All 11 failures existed before this pass — verified against `master@ebdb601`:
- `test_classifier_workflows.py` (2): `RecursionError` in classifier dispatcher
- `test_embedder_discovery_cross_platform.py` (3): environment-dependent filesystem layout
- `test_installer_llama_server.py` (5): environment-dependent venv/subprocess setup
- `test_linux_support.py` (1): requires real IDA on PATH
- `test_agent_cfg_similarity_merged.py` (1): text-grep anti-pattern (broken source cursor)
- `test_installer_llama_server.py::test_wipe_venv_renames_when_rmtree_fails`: hangs on `time.sleep` loop

---

## 0. Verdict (one paragraph)

The project is **structurally a CLI tool wearing a project skeleton**. It looks like a real product (docs, use-cases, hardening roadmap, design rules) but underneath the surface it is an overgrown single-author 12K-line `host/server.py` that grew by accretion into a 13.6K-line host layer of 11 mixins, an even more sprawling 6K-line `ida_mcp/` tool layer, and a "feature-bag" of 78 advertised tools whose per-tool action tables are largely duplicates of one another. **There are 6 known critical bugs in production code paths**, **≥30 high-severity issues** that would survive a 30-second code review by a senior reviewer, and a test suite that is **stacked with text-grep, mock-of-implementation, and `try/except: pass`-padded tests** that pass for the wrong reasons. The recent commit history shows a maintenance pattern of `fix X / fix Y / fix Z` — each fix papering over a deeper architectural problem rather than addressing it. The MCP tool surface is too large, the action surface is loosely typed, the run-loop has concurrency gaps, and several code paths could trigger IDA writes that are never rolled back if downstream steps fail.

The recent commits also include genuine improvements — the embedder cross-platform discovery (`e726e14`), the host-wiki hardening (`90779e9`), the IDB-folder locking fixes (`ebdb601` / `82d50e6`). Those are called out in §9 so the review is not all carping. The codebase is closer to "advanced prototype" than to the "Production/Stable" classifier it claims in `pyproject.toml`.

---

## 1. Architecture & Design (highest leverage)

### 1.1 [Critical] God-class host server, 11 mixins, no enforced contracts
`src/ida_pro_mcp/host/server.py:151` defines:
```python
class IDAMCPServer(
    ServerArgsMixin, ServerResponseMixin, ServerSemanticMixin, ServerWikiMixin,
    ServerThreatHuntMixin, ServerBlackboardMixin, ServerPredictorMixin,
    ServerWorkflowMixin, ServerRuntimeMixin, ServerSessionMixin, ServerDispatchMixin,
):
```
The mixins collectively own ~14K LOC. There is no `__init_subclass__` check, no ABC enforcing a contract, no test fixture that constructs the server without all 11 mixins. Constructor order matters (e.g. `ServerArgsMixin.__init__` must run before `ServerRuntimeMixin._detect_ida_dir`), but this is implicit and undocumented. **Any new mixin risks silently breaking the construction order.** `server.py:391-444` is a 50-line block of blank lines with a stranded `# Do NOT raise SystemExit or KeyboardInterrupt - let run() loop exit gracefully` comment — dead visual noise that suggests an incomplete extraction.

### 1.2 [Critical] 1008 `except Exception` blocks; 0 bare `except:` — the codebase swapped one anti-pattern for another
`grep -c '^\s*except\s*Exception\s*:' src/**.py` = **1008**. **Zero** truly bare `except:`. Every single one is `except Exception: pass` or `except Exception: <silently continue>`. This is a *worse* failure mode than bare except because:
- the exception object is bound (`as e`) in many cases but **never logged**,
- the surrounding code keeps running with **partially-mutated state**,
- the user sees a success or a structured error that lies.

Examples:
- `server.py:336-342` silently turns `UsageIntelligence` import failure into `self._usage_intel = None`.
- `server_runtime.py:412-419` (`_save_session_macros`) silently swallows `OSError`/`TypeError` from `json.dump` on a corrupt macro file.
- `server_blackboard.py:1680-1696` runs `_evidence_gravity` which fires 5 tool calls + a semantic search on **every** blackboard write; the whole thing is wrapped in `try/except: pass`.
- `intelligence/embeddings.py:629-630` swallows every error in `search_text` and returns `[]` — indistinguishable from "no results found".
- `session.py:245-273` (`_crystallize_to_global_registry`) and `session.py:317-330` (`_mark_global_skill_used`) both `try/except: pass` around SQLite writes; the user has no indication the global registry write failed.

### 1.3 [Critical] Race conditions on shared `IDAMCPServer` state
`server.py:350-354` declares `current_session = None`, `session_runtimes = {}`, `_semantic_index_lock = threading.RLock()`, `_runtime_lock = threading.RLock()`, `_idle_index_lock = threading.RLock()`. The codebase reads/writes `current_session` and `session_runtimes` from at least:
- main request thread (`server.py:559, 567, 623-625`),
- the idle-index worker daemon (`server_runtime.py:726-818`),
- the background `_trigger_session_diff` thread (`server.py:748-781`),
- the lease-heartbeat thread,
- the embedder's RPC thread.

**No lock is consistently held across reads/writes of `session_runtimes`.** The inflight-call counter is mutated at `server.py:562-577` without `_runtime_lock`, and read by the idle-index worker at `server_runtime.py:746,778` without any lock. This is a textbook lost-update race; it directly causes premature idle-indexing during active calls. The two near-identical `_trigger_session_diff` implementations (`server.py:748-781` and the module-level one in `server_session.py:136-158`) are not in sync.

### 1.4 [Critical] `_handle_session` is a 1489-line if/elif ladder (`server_session.py:160-1649`)
A single function dispatches ~50 actions, each with custom argument parsing, validation, persistence, and side effects.
- The function reads and writes `os.environ["IDA_MCP_CAPSULE"]` at `server_session.py:43-87` — leaking session-scoped state across sessions.
- The macro path (`server_session.py:1488-1576`) re-enters `_execute_tool` recursively, with **a 1-level block on `run_action.startswith("macro_")`** that does not catch alias-based re-entry.
- The `update` action (`server_session.py:804-833`) blindly spreads caller args into `update_session(**kwargs)`, so an LLM can pass `binary_path`, `analysis_options`, etc. and have them silently applied.
- `apply_analogy` (`server_session.py:1280-1303`) calls `self.call_tool("modify", ip, action="rename", addr=addr, value=name)`. The IDA-side `modify` rename action conventionally takes `name`, not `value`; the call will silently call the wrong field. Untested.

The 50-action if/elif pattern is **duplicated** in:
- `server_workflow.py:117-1100` (~1000-line function, 9 actions),
- `server_blackboard.py` (~2200-line file),
- `ida_mcp/tools/llm_helpers.py` (290-line `_handle_feature_expansion_action` with 50+ branches),
- `ida_mcp/tools/intelligence.py` (700-line function, 22 actions),
- `ida_mcp/tools/trace_analysis.py`,
- the IDA-side `server_script.py:222-336` (110-line `process_single`).

### 1.5 [Critical] Action surface is hand-maintained, undocumented
`host/schemas_data.py:16-119` lists 78 `TOOLS`. `ADVERTISED_TOOLS` is a separate list at `schemas_data.py:121-187`. `BASE_TOOL_ALIASES` and `_EXTRA_TOOL_ALIASES` (lines 10-14, 189+) provide name→tool redirect. Then `schemas_data.py` (2014 lines total) keeps per-tool `TOOL_ACTIONS`, `TOOL_ARG_SCHEMAS`, `ARG_ALIASES_BY_TOOL`, `ACTION_ALIASES_BY_TOOL`, descriptions, hints — **all of this must be kept in sync manually** with the actual `if action == "..."` branches in each tool. The doc-sync scripts `tools/sync_tool_counts.py` and `scripts/sync_schemas.py` only check tool *count*; they do not validate action counts, action names, or argument schemas. `tests/test_tool_count_sync.py` therefore only catches "you added a tool but forgot to bump the doc number" — not "your `code(action='decompile')` action takes `addrs` not `addr`".

### 1.6 [High] `host/server.py` swallows an enormous amount of state and ambient config
`__init__` (`server.py:160-388`) reads ~25 env vars, creates the audit logger, the rate limiter, the assembler, the usage-intelligence observer, the insight index, the global facts DB, the wiki cache, the context density optimizer, three RLock objects, two background threads (lease heartbeat, idle index), and registers an atexit handler. This is 230 lines of dense initialization with no seam. Adding a feature means editing this constructor. Testing means spinning up the full server.

### 1.7 [High] Cross-layer state leakage via `os.environ` and module-level mutable globals
- `server_session.py:43-87` writes `os.environ["IDA_MCP_CAPSULE"]` on every session call; multi-session servers will see `IDA_MCP_CAPSULE` from whichever session was last touched.
- `server_script.py:36` sets `BYPASS_SYNC` at module import time. Combined with `sync.py:53,59` (which reads it once at import), this means tools that import `sync` before `server_script` are unprotected. The safety layer is therefore load-order-sensitive. **Setting `BYPASS_SYNC=1` unconditionally also defeats the `@idaread`/`@idawrite` safety net the rest of `sync.py` provides.** `[FIXED: 1A.4 replaced unconditional knob with context manager]`
- `sync.py:21` parses `idaapi.get_kernel_version().split(".")` with no defensive parsing; a non-numeric version like `"9.0.beta1"` raises `ValueError` and breaks every `idaread`/`idawrite` decorator on the entire tool. `[FIXED: 1A.4 added `_parse_kernel_version()`]`
- `sync.py:46,77,80-83` builds a `queue.LifoQueue` "lock" and a re-entrancy state machine; if a tool raises *inside* the wrapped block, the queue is left in a state where the next call from a different owner re-enters under the wrong identity.
- `sync.py:102-103` `raise res` discards the original Python exception context (no `raise ... from`); tracebacks are lost.
- `compat.py:80-88` returns `True` for `at_least(9, 3)` even when running outside IDA (version `(0,0,0)`), so probes for `has_qset_qmap_headers`, `has_microcode_assertions`, `has_mte_intrinsics`, `has_neon_crypto_intrinsics`, `has_cssc_intrinsics`, `has_v850_decompiler`, `has_golang_type_folders`, `has_dart_classifier` all lie in tests, returning `True` for features that don't exist in the test environment. The "conservatively assume newer" comment is **wrong**.
- `cache.py:77-80` (`invalidate_all`) bumps a generation counter but does **not** remove entries, so the `OrderedDict` grows unboundedly until TTL expiry. Memory leak under long-running sessions.
- `ida_mcp/rpc.py:6-7`: `MCP_UNSAFE: set[str]` and `TESTS: dict[str, tuple[Callable, str]]` are module-level mutable globals with no synchronization. Multi-threaded test import order can race.

### 1.8 [High] `proposal_accept` runs execute before verify; no rollback
`server_blackboard.py:1812-1880` calls `_proposal_execute` (which calls `self._execute_tool("modify", {"action": "set_name", ...})`, `..._patch_asm`, `..._set_type`) at line 1844 **before** `_proposal_verify` at line 1845. If verify fails, the writes are already in the IDB. The status is set to `"failed"` in metadata, but IDA-side renames/patches persist. There is **no snapshot/rollback path**. This is an integrity hole in a tool whose entire stated purpose is to gate risky writes.

### 1.9 [High] `_handle_batch` double-truncates and double-runs
`server_dispatch.py:147-216` (`call_tool`) calls `truncate_response(res, max_tokens=self.default_truncate_tokens)`. Then `server.py:588-593` calls `_prepare_response_payload` which **also** truncates/compacts. Every batched call pays the truncation cost twice.

### 1.10 [High] Response pipeline has 7+ "ghost chain" recursive phases
`server_response.py:865-1014` runs up to 7 ghost-chain inline phases per response, each potentially calling `_execute_tool` recursively. Combined with `_add_address_calculations` (line 502-651) which builds a `PPAAEngine` on first use and runs up to 6 sqlite lookups per hex address, and `_add_auto_blackboard` (line 1045-1111) which may write 5+ blackboard entries per `decompile`, the response pipeline can fire **12-20 recursive tool calls** for a single user-initiated `code(action='decompile')`. No opt-out, no telemetry, no latency budget.

The `_observe_preference` call at `server.py:580-584` and `server_dispatch.py:196-200` invokes a function that is `pass` (`server_response.py:280-282`). It's a dead no-op kept "for compat".

The `_add_pointer_note` at `server_response.py:179-205` and the `_guardrail_reason_tags` set at `server_response.py:336-349` both have `tn in {"code", "graph", "graph", "ctree", ...}` with `"graph"` duplicated. Set semantics collapses the duplicate but indicates a copy-paste bug.

`server_response.py:1127-1130` injects `llm_low_confidence_gate.verification_actions` with `{"tool": "memory", "arguments": {"action": "read", "addr": "0x0", "size": 16}}` (and similarly `{"tool": "calc", "arguments": {"action": "eval", "expr": "1+1"}}`). Reading from `0x0` will segfault IDA (no memory mapped at NULL in any sane IDB). The verification_actions list is presented as "do this" to the LLM, which will follow it.

### 1.11 [High] `server_runtime` `_start_idle_index_worker` reads mutable counters without locks
`server_runtime.py:726-818` reads `self._session_inflight_calls` and `self._session_last_activity` from a daemon thread (lines 742, 746, 748, 778, 780) without locks. Lost updates with the main request thread mutations at `server.py:557-577`.

### 1.12 [High] `_kill_process_tree` assumes process-group isolation that isn't there
`server_runtime.py:51-95` calls `os.killpg(os.getpgid(pid), ...)` but the matching `subprocess.Popen(cmd, ...)` at line 1291 does **not** set `start_new_session=True` (POSIX) or `creationflags=CREATE_NEW_PROCESS_GROUP` (Windows). The wrapper at line 1291-1293 will therefore either throw `ProcessLookupError` or — worse — SIGKILL the MCP server's own process group on POSIX, taking out the parent. The bare `try/except: pass` (line 88-93) swallows the symptom; the orphaned `idat.exe` keeps the IDB locked and `_cleanup_runtime` then hangs in `proc.wait(timeout=grace_seconds)`. `[FIXED: 1A.3 added `start_new_session=True` / `CREATE_NEW_PROCESS_GROUP` to both Popen sites]`

### 1.13 [Medium] `_attempt_session_recovery` leaks runtimes on partial success
`server_runtime.py:1460-1554` calls `_launch_and_wait` recursively; if the first recovery succeeds but `_apply_session_options` fails, the freshly-launched runtime is leaked (no `_cleanup_runtime` call in the recovery-success path). The `result` dict is returned to the caller but `session_runtimes` already has the entry.

### 1.14 [Medium] `server_runtime.py:1289-1290` opens stdout/stderr log files in append mode, never rotates
For long-running analysis, the IDB session can write megabytes per run, accumulating without bound. Combined with `server_runtime.py:412-417` (`_save_session_macros` uses `tmp + os.replace` without `fsync`), a crash mid-write can leak.

### 1.15 [Medium] Cross-mixin coupling between `server_workflow.py` and `server_workflow_batch.py`
`server_workflow.py:1094` falls through to `self._handle_batch({"calls": step_plan, "continue_on_error": True})` for non-dry-run execution. `_handle_batch` is on a different mixin (`server_workflow_batch`); the cross-mixin coupling is fine but the batch handler does not inherit any of the workflow's plan_diagnostics or workflow_meta. The 5× duplicated "if `planned_calls` provided, use it; else compose; else plan" pattern at `server_workflow.py:118-169, 254-305, 407-460, 519-534, 623-628, 731-736` creates subtle behavior differences between actions.

### 1.16 [Medium] `server_dispatch.py:1031-1061` is dead code
`pre = {"decision": "allow"}` at line 1031 is overwritten at line 1045 for the "never block" tools with the same value. The two `if pre.get("decision") == "block_high_impact"` blocks at lines 1046-1049 and 1050-1061 are unreachable because nothing in this file ever sets `decision` to `"block_high_impact"`. ~30 lines of zombies.

### 1.17 [Low] `server.py` still has the legacy "anchor for source-based regression tests" comment block
Lines 140-141 and 804-806 contain commented-out sentinel lines like `if addr and tool_name in ("code", "data", "search"):` and `legacy_threat_tools = {`. Source-based regression tests that grep for these strings will pass; their absence is a maintenance smell.

---

## 2. Security & Trust Boundaries

### 2.1 [Critical] `memory` tool: arbitrary path read/write, no allowlist
`server_dispatch.py:296-365` (`_handle_memory_filesystem`) accepts `path=...` from MCP client, no canonicalization, no allowlist, no working-directory check. The error path even returns `traceback.format_exc()` (line 359-360), leaking the server's filesystem layout. A local LLM agent can read `/etc/shadow`, the IDA license, or write to `~/.bashrc`. The transport is supposed to be local-only, but the stated threat model in `SAFETY_MODEL.md` §1-2 explicitly lists "oversized or malformed request payloads" and "unauthorized local RPC requests" — yet this code accepts any path with no validation. The error-path traceback leak is also a fingerprintable disclosure. `[FIXED: 1A.1 added `realpath` allowlist, 64 MB size cap, sanitized error path]`

### 2.2 [Critical] `intelligence(action="blackboard_federate")` is an SQL/path-traversal sink
`ida_mcp/tools/intelligence.py:836-846` accepts `remote_paths` and `remote_capsule_paths` as a comma-separated string from kwargs (i.e. untrusted RPC input) and passes them unfiltered to `FederationBridge.federate_blackboards`. There is no `realpath` containment, no symlink rejection, no allowlist. SQLite's `ATTACH DATABASE` semantics mean a malicious path becomes a queryable database; `/proc/self/mem` and UNC paths are accepted. The same file (line 922-931) has `structural_query` taking a raw `constraints` dict that, depending on the helper's implementation, may be interpolated into SQL. The reviewer could not 100% confirm SQLi without reading the full `execute_host_query` body, but the pattern is high-risk and the file uses `sqlite3.connect` without `timeout=` / `isolation_level` arguments on the hot path (859, 898, 941, 980). `[FIXED: 1D.1 added `IDA_MCP_FEDERATION_ALLOWED_ROOTS` env-var allowlist; action also made reachable (was dead code)]`

### 2.3 [High] `_proposal_verify` is a string-substring search
`server_blackboard.py:1162-1226` decides whether a proposal is verified by running `ok = name.lower() in text and addr.lower() in text` (line 1174) against a JSON-serialized probe result. Any tool output that contains the literal name and address passes. `patch` verification (`1181-1197`) treats an empty `asm` string as auto-verified (`asm_tok in text if asm_tok else True`).

### 2.4 [High] `_notes_import` has no rate limit and `_memory_compile` notes writer creates arbitrary directories
- `server_blackboard.py:1007-1061` (`_notes_import`) reads a user-supplied file and creates a blackboard entry per `- ` line. No cap. A 1GB input file creates millions of entries. Only `store.exists_similar` is the gate; if the input is unique, all entries are written.
- `server_blackboard.py:634-767` (`_memory_compile`) writes to a user-supplied `notes_path`. `os.makedirs(os.path.dirname(os.path.abspath(notes_path)) or ".", exist_ok=True)` (line 751) creates the parent directory — `notes_path="/etc/cron.d/anything"` and the code will create the directory and write.

### 2.5 [High] `firmware_view` `bootstrap` accepts unchecked `load_base`
`ida_mcp/tools/firmware_view.py:2286-2317` validates `load_base` only via `isinstance(load_base, int)`. No range, sign, alignment, or cap. A negative or > 2^64 value is passed to `run_firmware_bootstrap` which creates segments and runs auto-analysis — direct IDB corruption vector.

### 2.6 [High] `ida_bytes` MMIO scan hardcodes little-endian
`ida_mcp/tools/firmware_view.py:2049-2051` uses `<I` (little-endian) `struct.unpack_from` unconditionally. PPC/MIPS-BE/ARM-BE firmware is silently mis-decoded; the IOC entries written to the blackboard are wrong.

### 2.7 [High] `_terminate_ida_processes_for_path` does substring SIGKILL
`server_runtime.py:1020-1111` iterates `psutil.process_iter` and SIGKILLs every process whose `cmdline` contains the target path. Substring match — any IDA process running a different binary in the same directory is killed. As root, can SIGKILL system processes whose cmdline contains a matching prefix.

### 2.8 [High] `_send_rpc_raw` has no total request size cap
`server_runtime.py:1156-1191` reads 4-byte big-endian length prefix, then `s.recv(4 - len(lb))`, then receives the body. **No upper bound on request size**. A malicious or buggy client can OOM the server with a single huge payload — directly contradicts `SAFETY_MODEL.md` §2 ("request size limits" listed as a current safety control). `[FIXED: 1A.2 added `IDA_MCP_MAX_RPC_BYTES` cap (default 64 MB) on both request and response paths]`

### 2.9 [Medium] Cross-process lock file: TOCTOU between port release and IDA bind
`server_runtime.py:1212-1215` opens a socket, binds port 0, reads assigned port, then closes the socket — a TOCTOU window where another process on the host can grab the same port before the IDA process binds it.

### 2.10 [Medium] `_handle_blackboard.status` does a hard-coded relative import
`server_blackboard.py:1402-1432` uses `importlib.util.spec_from_file_location("_host_blackboard", bb_path)` with a path built from `SCRIPT_DIR/../ida_mcp/tools/blackboard.py`. The same fragile path is duplicated in `server_session.py:710-727` and `ida_mcp/tools/blackboard.py:851-950` (knowledge graph actions). Any package restructure silently breaks these actions with the failure mode being `None` from `_get_blackboard_store` (line 1431). Worse: the dynamic load at line 1418 sets `mod.__dict__["IDAError"] = Exception`, which means **any** downstream `except IDAError` will catch all exceptions, including ones that should propagate.

### 2.11 [Medium] Bare substring matching for API detection drives downstream tagging
`ida_mcp/tools/code.py:1618-1675` and `llm_helpers.py:478-486` (binary_capability_matrix_builder) use `if api.lower() in low for api in apis` style containment. `fork` matches `forkjoin`; `open` matches `openssl`; `system` matches `FileSystem`; `exec` matches `execute`. These false-positive detectors drive the "dangerous API" tags and the next-action ranker.

### 2.12 [Medium] `code.annotate` writes user-supplied comment straight to `idc.set_cmt` / `set_func_cmt`
`ida_mcp/tools/code.py:1582-1598` is the deprecated path (the deprecation note at 1572-1578 says it should be in `annotation.py`), but it still writes comments with no governance/redaction. If the governance path is the only sanctioned write, this is a parallel sink.

### 2.13 [Medium] `agent.py` auto-fingerprint loads every `*.embeddings.db` from the IDB dir
`ida_mcp/tools/agent.py:1145-1164`:
```python
for f in os.listdir(db_dir):
    if f.endswith(".embeddings.db"):
        idx = FunctionEmbeddingIndex(other_path, embedder)
```
**Any file dropped into the IDB directory with a `.embeddings.db` suffix is auto-loaded**, no allowlist, no integrity check, no size check. A hostile file is read and indexed. Information disclosure + DoS vector.

### 2.14 [Medium] `cfg_similar` mutates the persistent store
`ida_mcp/tools/agent.py:1304-1305`: a "find similar" query mutates the persistent DB. The user has no opt-in. This is a side effect that should be explicit.

### 2.15 [Medium] MbaGCNEncoder weights may not be deterministic
`ida_mcp/tools/agent.py:1255`: `MbaGCNEncoder(input_dim=64, hidden_dim=256, output_dim=4096)` is reconstructed per call. If `MbaGCNEncoder` uses Xavier/Kaiming init with a global RNG, two calls in the same process produce different encoders. Embeddings are then not comparable across calls. **Worth verifying in `host/mbagcn_engine.py` before trusting any `cfg_similar` output** — could escalate to Critical if init is non-deterministic.

### 2.16 [Low] `intelligence/embeddings.py` uses private cross-module import dance
`embeddings.py:103-109` and `770-781` reimplement the "try `..config` then try `host.config` then fallback" pattern that exists in **at least 5 files** (`core.py`, `embeddings.py`, `blackboard_store.py`, `symbol_db.py`, possibly more). This is a code smell — the package layout is not enforcing a single import path.

---

## 3. Persistence / Database Layer

### 3.1 [High] `_save_metadata`, `_save_snapshots`, `_save_notebook` use tmp+rename without fsync
`session.py:384-396`, `session.py:902-910`, `session.py:929-937` all use the `tmp + os.replace` pattern, but none of them call `f.flush()` + `os.fsync()` before the rename. A crash mid-write loses the new metadata. Compare `tests/test_v4_integration.py:505-553, 612-632` where test code **does** call `f.flush(); os.fsync(f.fileno())` — the test code is more correct than the production code. `[FIXED: 1B.1 added `f.flush(); os.fsync(f.fileno())` to all 3 paths]`

### 3.2 [High] `BlackboardStore` opens connection without close-on-exception
`host/blackboard_store.py:111-114` returns a fresh `sqlite3.Connection` per `_conn()` call. Each public method opens, executes, and either uses `with closing(...)` (line 117, 287) or doesn't (e.g. `metadata()` at line 272, `recent_functions()` at line 287). The `with closing(self._conn())` is used at `_init_db` and `write`, but the **read** methods (`metadata`, `recent_functions`, etc.) do not use `closing` and rely on the connection being GC'd. The pattern is inconsistent — under load, connections pile up. `[FIXED: 1B.2 — all remaining public methods now use `with closing(self._conn())`; the `__init__` writability probe was also fixed]`

### 3.3 [High] `_sync_entry_to_capsule` writes to env-derived `IDA_MCP_CAPSULE` without verification
`blackboard_store.py:201-254`: every blackboard write that has `embed=True` *also* writes a corresponding entry to whatever path is in `IDA_MCP_CAPSULE`. The path comes from `os.environ` (set in `server_session.py:43-87`) and is a per-session global. A side effect on one session can pollute the capsule of another session running in the same process.

### 3.4 [Medium] `FunctionEmbeddingIndex.needs_rebuild` is a single `try: ... except: pass` around a destructive `DELETE FROM`
`intelligence/embeddings.py:129-150`: if `needs_rebuild` returns true, the code does `conn.execute("DELETE FROM func_embeddings")` and overwrites meta. If `needs_rebuild` throws (which the broad `except Exception: pass` at line 149-150 will then swallow), the rebuild was based on a partial state. There is **no transactional wrap** of the delete + meta update. `[FIXED: 1B.4 — wrapped in explicit `BEGIN` / `COMMIT` with a fresh connection; exception is surfaced]`

### 3.5 [Medium] `FunctionEmbeddingIndex` and `SemanticObjectIndex` duplicate logic
`embeddings.py:99-150` and `embeddings.py:772-798` both implement the same pattern: try primary db_path → `OperationalError`/`OSError`/`PermissionError` → fall back to `CACHE_DIR/fallback_indexes/{sha256[:16]}.db`. Duplicated code, duplicated fallback heuristic, duplicated WAL pragma. Should be a shared base class.

### 3.6 [Medium] `intelligence/core.py` `_MODEL_PATH_CACHE` is module-level mutable, no invalidation
`core.py:89, 435-499`: `_MODEL_PATH_CACHE` is filled once on first discovery and never re-checked. If a user installs a new model after the host started, the new model is invisible. If the model file is replaced, the cache still returns the old path. No TTL, no `mtime` check, no admin "clear cache" tool.

### 3.7 [Medium] `host/symbol_db.py` and `host/analysis_proposal_store.py` not audited end-to-end
Both are cited by the architecture docs as the symbol and proposal stores, but I have not opened them line-by-line. Same concern as `capsule/store.py:1616` — large files, untested in this pass.

### 3.8 [Low] `_entry_brief` and friends have inconsistent defaults
`server_blackboard.py:38-63`: builds a 13-key dict with 7 `entry.get(...)` calls. The `confidence` default is `0.0`; the `round(confidence, 3)` then becomes `0.0`. Not a bug, but the inline `if/else` for status is harder to read than a helper.

---

## 4. Intelligence Subsystem

### 4.1 [High] BgeCodeEmbedder singleton with mutable state and lazy subprocess
`intelligence/core.py:607-700` (`BgeCodeEmbedder`) is a process-wide singleton (`_instance`) that spawns a llama-server subprocess on first `embed()` call. The class:
- Reads `_find_llama_server()` and `_find_model()` **once** at `__init__` (line 626-627). The discovery depends on env vars that may change after import.
- `_start_server` (line ~700+) is not in my excerpt but the status path at 644-695 indicates lazy start. A failed start leaves `self._proc` as a half-initialized Popen and the next call hits `NoneType` errors.
- `INTEL_PROFILE` (line 509) is captured at module import. Toggling `IDA_MCP_INTEL_PROFILE=1` after the module is imported does nothing. `test_intelligence_health_perf_block_when_profile_enabled` had to be patched to mutate `INTEL_PROFILE` on **all** active and cached core modules — the per-instance mutation pattern is in the commit history (`710e3da`, `d546d38`) for a reason: the constant is captured at import time.
- `EMBED_MAX_FAILURES` (line 507) defaults to 2 — so a 3rd failure puts the embedder into TF-IDF fallback silently. The `consecutive_rpc_failures` counter is exposed via `status()` (line 689) but no caller polls it.
- `EMBED_REQUEST_TIMEOUT` (line 506) defaults to 5.0s. A slow llama-server will trip the timeout and silently fall back to TF-IDF for **every subsequent call** until the embedder is restarted.

### 4.2 [High] Embedder cross-platform discovery lease race
`intelligence/core.py:644-695` reads `_EMBED_LEASE_FILE` to discover an existing llama-server. The lease is a JSON file with `port`. Multiple processes (multiple MCP servers) writing to the same lease file: last-writer-wins, no fencing. A crash between write and connect leaves a stale lease that points at a dead process. The `_adopt_or_cleanup_stale_runtime_leases` helper exists in `server.py:386` but the embedder lease path is not the same code path — it has its own simpler lease reader.

### 4.3 [High] `hybrid_search` calls `embedder.embed` from the hot path
`intelligence/embeddings.py:660-668` calls `self._embedder.embed(query_text)` from inside `hybrid_search`. If the embedder is the BgeCodeEmbedder, every search pays the full llama-server round-trip (5s timeout). For an LLM that fires `hybrid_search` from inside a per-function lookup, this is a 5x latency cliff. No caching, no debouncing, no in-flight deduplication.

### 4.4 [Medium] TF-IDF fallback uses MD5 hash bucketing
`intelligence/core.py:584-600` (`_TFIDFEmbedder.embed`) hashes each token via `md5` to a fixed-dim bucket. MD5 is fine here (no security implication) but the `sign` bit via `h >> 127` is fragile: a single MD5 collision means two unrelated tokens sum into the same bucket with the same sign, accumulating noise. For 1536 dim and ~1000 tokens, collisions are rare but happen. Not a correctness bug for the use case (similarity scoring, not retrieval), but the docstring's "orders of magnitude better than random Hadamard projections" is marketing.

### 4.5 [Medium] Cache `bump_generation` doesn't actually invalidate
`cache.py:77-80` — already noted in §1.7. Combined with `LLM_helpers._load_llm_feature_state` at `tools/llm_helpers.py:172-189` which returns defaults on JSON parse error and silently loses state, the persistence layer is a maze of "if anything goes wrong, fall back to a default the user doesn't know about".

### 4.6 [Medium] `ppaa.py`, `crystallizer.py`, `reasoner.py`, `entropy.py`, `federation.py` not audited end-to-end
The `intelligence/` package contains 19 files totaling several thousand LOC; only `core.py`, `embeddings.py`, and partial `context.py` got full reads. The package is a self-contained subsystem that deserves its own audit pass before any "production/stable" claim. I see commit history referencing `MbaGCNEncoder` rebuilds per call (`agent.py:1255`) and `dists.sum() == 0` divide-by-zero (`agent.py:1198-1199`).

### 4.7 [Medium] `_extract_signature` and `_normalize_search_text` duplicate noise-word logic
`intelligence/embeddings.py:19-27` (`_SEARCH_NOISE_TOKENS`) and `intelligence/core.py:512-522` (`_NOISE_IDENTS`) are two separate noise lists. A token in one but not the other will be treated differently by signature extraction vs. text tokenization.

---

## 5. Tool Layer (`ida_mcp/tools/`)

This is the bulk of the code (~40 files, ~30K LOC). I have read every file in this layer at least once but not all of them line-by-line. I concentrate on the most recurring and most dangerous issues.

### 5.1 [Critical] `trace_analysis.py` emulator miscomputes 64-bit / 32-bit / branch logic
`ida_mcp/tools/trace_analysis.py` is 3241 lines, the largest single file in the project. Issues: `[FIXED: 1C — 13 commits fixing all listed bugs; see §0.1 for per-commit mapping]`
- `trace_analysis.py:2103` hardcodes `val & 0xffffffffffffffff` (64-bit) without an architecture probe. 32-bit x86 / ARM / MIPS targets silently get 64-bit semantics on the emulator.
- `trace_analysis.py:2920-2922` evaluates `jb`/`jae` against `sf` instead of `cf`. `jb`/`jae` are unsigned branches that must use **CF**; CF is never tracked. Every unsigned compare branch picks the wrong successor.
- `trace_analysis.py:2702-2714` (`sar`) hardcodes 64-bit mask even when the operand is 8/16/32-bit. ZF computation masks to 32 bits regardless of width.
- `trace_analysis.py:2705` masks shift count with 6 bits (`val1 & 63`); real x86 uses 5-bit mask for 8/16/32-bit shifts, 6-bit only for 64-bit. Off-by-one at shift counts ≥ 32.
- `trace_analysis.py:2139-2150` "dummy-arg-pointer" address window `0x10000000–0x70000000` collides with legitimate mapped memory in many 32-bit binaries; reads in that range return `0` instead of the actual byte.
- `trace_analysis.py:2161, 2210, 2215` stack window `0x7f000000–0x80000000` is hardcoded; any real allocation inside that range is misclassified as stack and recorded in `stack_writes`.
- `trace_analysis.py:2157` `ida_bytes.get_byte` returns `0xff` for unmapped bytes with no mapped-check; emulator silently consumes `0xff` as data.
- `trace_analysis.py:2293` `re.match(r'^[0-9a-f]+$', tok)` always interprets the token as base-16; if any IDA front-end ever prints operands as decimal, addresses are wildly miscomputed.
- `trace_analysis.py:2658-2675` (`call`) sets only `rax`; doesn't model caller-saved clobbers and doesn't adjust `rsp` for the return-address push/pop pair.
- `trace_analysis.py:2910-2934` (`step`) only knows `jmp/je/jne/jz/jnz/jb/jae`; misses `jg/jl/jge/jle/ja/jbe/jo/jno/js/jns/jp/jnp/jcxz`.
- `trace_analysis.py:2997-3066` (`speculative_explore`) global `step_count > 5000` cutoff terminates mid-path, leaving partial state appended to `completed_paths + paths` at line 3078; the result looks complete but isn't.
- `trace_analysis.py:3083` `merged_opaque_predicates.update(emu.opaque_predicates)` lets later paths overwrite earlier paths' verdicts for the same EA without conflict detection.
- `trace_analysis.py:3115` `merged_dereferenced_pointers` items are `(ip, addr, "read"/"write")` and are serialized as raw tuples; addr ints are not converted to hex strings while every other addr field in the result is hex. Inconsistent return shape.
- `trace_analysis.py:451-470` (`extract_api_calls`) uses `trace_set = set(load_trace())` which loses ordering; then iterates `trace_set` (unordered) for xrefs.
- `trace_analysis.py:585-696` (`cross_run_diff`) `_diff_xref_count` is shared between two `for ... enumerate(...)` loops, so the second loop's xref cap is reduced by what the first loop consumed.
- `trace_analysis.py:737-845` (`anti_analysis_detect`) references `MOV_MNEMONICS` which is not defined in this file.
- `trace_analysis.py:800-810` "Timing loop detection" uses `t_addr in trace_list` — O(n) `list.index()`. For large traces, slow. Should be a set.
- `trace_analysis.py:18-19` `@tool @idaread` decorates the entire `trace_analysis` function; if a trace import action modifies state (e.g., `_TRACE_CACHE` reassignment at line 180), the decorator's caching is bypassed.

This is a self-contained correctness bug cluster in a 3241-line file that no unit test exercises. The function is callable from any MCP client.

### 5.2 [Critical] `intelligence.py` recursive dispatch
`ida_mcp/tools/intelligence.py:935, 972, 995` re-enters `intelligence(action=...)` recursively. If `intelligence` is decorated `@idaread`/`@idawrite` (as surrounding tools are), this is a reentrancy/deadlock risk on the IDA UI thread. The 700-line `intelligence()` function dispatches 22 actions via if/elif; the Literal type at line 301-327 lists 22 names and the description string at line 326 duplicates the union — a single source of truth is needed. `[FIXED: 1D.2 — replaced 3 recursive call sites with direct handler call refactor; 1D.3 added `_safe_decompile` helper with `init_hexrays_plugin` guard; 1D.4 raises on empty `idb_path`]`

`intelligence.py:480, 505, 532, 560, 584, 657, 679, 728, 816-829, 833-836, 855-857, 887, 919, 933-934, 970-973`: all `ida_hexrays.decompile(...)` calls without checking `init_hexrays_plugin()`. If plugin not loaded, may return None or raise.

`intelligence.py:370-373`: `_index_for_current_idb()` — if `idb_path` is empty, `idb_path + ".embeddings.db"` = `".embeddings.db"`. Relative path. `FunctionEmbeddingIndex` may fail or write to CWD.

`intelligence.py:610-611`: `from ida_pro_mcp.ida_mcp.tools.blackboard import blackboard as blackboard_tool`. Module-level import inside the function. Then calls `blackboard_tool(...)` which itself calls an `idaread`-decorated function, which calls `_sync_wrapper` with bypass. With `BYPASS_SYNC=1` set in `server_script.py:36` this is bypassed, but the calling pattern is confusing.

### 5.3 [High] `_BackgroundCrawler` in `blackboard.py` is a thread that does not respect IDA threading rules
`ida_mcp/tools/blackboard.py:90-364` — IDA's Python API is documented as **not thread-safe** (the `@idaread`/`@idawrite` decorators exist precisely because of this). The crawler spawns a `threading.Thread` and calls `blackboard(action="frontier", ...)` from inside it (line 217, 260-285), then `agent(action="quick", ...)` which decompiles functions. With `BYPASS_SYNC=1` set in `server_script.py:36` unconditionally, the safety wrapper is bypassed and the thread will run IDA SDK calls from the wrong thread → silent memory corruption, exception, or undefined behavior. The author of the `sync.py` module clearly understood this — `BYPASS_SYNC` should not be a global "always on" knob.

`blackboard.py:144-145` `stop()` sets stop event but never joins. Caller has no way to wait for the thread to actually finish.

`blackboard.py:191-364` `_crawl_loop` and `_crawl_step` — all exceptions caught and silently passed. State writes via `store.write()` inside the step have no transactional guarantee.

`blackboard.py:580-614` `write` action spawns a daemon thread to propagate labels. The thread imports `frontier` module dynamically. Errors swallowed.

`blackboard.py:619,621,716,719,740,742,748,750,818,820,825,827,831,833,839,841,863-864,868,879,888,900,905,916,924,933,937,939,942,944,946,948,950,1077-1078` returns `{"ok": False, "error": "..."}` mixed with the `make_error` shape `{"error": True, "code": ..., ...}`. No consistent error shape across actions.

`blackboard.py:851-950` knowledge graph actions load `_bb_kg` module via `importlib.util.spec_from_file_location`. Path is relative to the file's location with hardcoded `.., .., host, knowledge_graph.py`. Will break if package structure changes.

`blackboard.py:952-1063` `frontier`, `coverage`, `propagate_labels` actions each open a fresh `FrontierEngine(emb_db, store.db_path)`. The engine is created and discarded per call.

### 5.4 [High] `code.py` decompile retry sleeps in `idaread` context
`ida_mcp/tools/code.py:541-623` (`_decompile_with_diagnostics`) has a retry path that calls `ida_auto.plan_range` and `time.sleep(0.5)`. Sleeping in an `idaread` decorator context blocks the IDA UI thread.

`code.py:1135-1171` (`handle_large_output`) `tempfile.mkstemp` returns `(fd, path)`. `os.fdopen(fd, "w")` succeeds; if subsequent write fails, the except path does `os.close(fd)` but the file object was already created from fd and now has a closed fd. Resource leak.

`code.py:680-705` (`_simulate_ghidra_decomp`) is a regex-based "simulation" of Ghidra decompiler output. Not real Ghidra. Just a rename pass.

### 5.5 [High] `llm_helpers.py` has 50+ "feature expansion" actions, many returning synthetic canned data
The author documents 50+ features in `_FEATURE_PHASES` (line 43-94). Many are wired in the dispatcher at 341-631 but return synthetic data (e.g., `intents: ["vulnerability", "behavior", "dataflow"]` strings; `experiment_harness_for_script_variants` quality scores that are deterministic in `idx`). The architecture is "advertise a feature → return fake data with realistic shape" — dangerous because the LLM treats it as ground truth.

- `uncertainty_propagation_engine` at 412-417: `confidence = 0.35 + (evidence_count * 0.07) - (contradictions * 0.15)`. Magic numbers, not a model.
- `search_hypothesis_sandbox` (460-467) appends hypotheses to state without checking for duplicates.
- `binary_capability_matrix_builder` (478-486) uses `_get_imports_summary` which iterates ALL imports; the categorization is substring-based and quadratic in `_API_CATEGORIES` size.
- `evidence_weighted_response_assembler` (402-411) assigns weight to evidence blocks based on source name; hardcoded boost values.
- `decompile_disasm_consistency_search` (line 2002-2006) reuses `cfunc` name for two different decompiles without `else`; if 2nd `decompile` returns None the prior `cfunc` is silently shadowed by None.
- `argument_semantics_search` (line 2103-2149) accepts `arg_idx` but never actually inspects argument `N`; it just feeds the function signature lines + query into the classifier. The action's contract is not met.
- `_search(...).get("matches")` (line 2230-2241) is treated as a newline-delimited string and `parts[0]` is consumed as an address with no validation.
- `reachable[:100]` (line 2165, 2187) silently truncates BFS without surfacing `truncated=True`.

### 5.6 [High] `search/advanced.py:101-120` (add_candidate) score inflation
```python
if ea in scores:
    scores[ea] = max(scores[ea], value) + 1.0  # max+1.0 inflates on duplicate detection
```
The `+1.0` after a `max` is wrong — it makes duplicates rank above fresh additions. Not a critical bug but pollutes the search ranking.

### 5.7 [High] `search/advanced.py:286-319` (search_vulnerable) xref cap shared across iterations
The `max_xrefs` cap is shared globally across the triple-nested loop. Once the cap is hit in the middle of a function, the inner loops break and silently skip the rest of the function. No `truncated` flag surfaced.

### 5.8 [High] `search/combinators.py:413-418` (`parse_not`) materializes the full function set on every NOT
```python
if self.peek() == "NOT": self.consume("NOT"); inner = self.parse_not(); return _all_func_eas() - inner
```
Each `NOT` operation does `idautils.Functions()` and builds a set. For a bool expression with 5 NOTs, the search repeats the full materialization 5x. No memoization.

### 5.9 [High] `firmware_view.py` `bootstrap` accepts unchecked `load_base` (see §2.5)
Also:
- `firmware_view.py:2078` `from blackboard import BlackboardStore as _BBStore` uses a bare top-level import path that does not match the package layout used elsewhere (`ida_pro_mcp.host.blackboard_store`); on most installs this raises `ImportError`, is swallowed by the outer `except Exception: pass`, and MMIO knowledge writes silently fail.
- `firmware_view.py:2076-2095` no de-dup before writing peripherals to blackboard; repeated `detect_mmio` runs accumulate duplicate `ioc` entries.
- `firmware_view.py:2151, 2180` hardcoded scan ceilings (`funcs_seen > 6000`, `len(tasks) >= limit`) silently truncate `rtos_scan` results without `truncated=True` flag.
- `firmware_view.py:2167` `tname = (idc.get_name(xr.to) or "").lower()` per xref per function with no cache; quadratic on large firmwares.
- `firmware_view.py:2286-2317` (`bootstrap`) only validates `load_base` via `isinstance(load_base, int)`; no range/sanity check.
- `firmware_view.py:2192-2272` (`triage_snapshot`) re-enters `firmware_view(action=...)` four times through the same dispatcher; if the outer call is decorated `@idaread`/`@idawrite` this is a hidden reentrancy edge.
- `firmware_view.py:741-831` (`auto_retype`) calls `ida_kernwin.process_ui_action("UndoCreateSnapshot")` — `"UndoCreateSnapshot"` is a UI action name string, but the actual snapshot API is `ida_kernwin.take_database_snapshot`. Likely wrong.
- `firmware_view.py:778` `ida_bytes.create_data(pea, ida_bytes.qword_flag() if ptr_size == 8 else ida_bytes.dword_flag(), ptr_size, idaapi.BADADDR)` — `create_data(ea, flag, size, tid)`. The 4th arg is `tid` (type ID), not size. Passing `BADADDR` (= -1) means "no type info". OK actually.

### 5.10 [High] `firmware_view.py:2049-2051` (see §2.6) — little-endian MMIO scan.

### 5.11 [High] `idb.py:201` — `hex(max_ea - min_ea) if min_ea and max_ea else None`
`min_ea=0` is falsy. **Bug**: an image starting at `0` (very common for ELF) has `min_ea=0` which fails the truthy check, returning `None` for `image_size`. Affects `idb_meta` and any tool that relies on the size. `[FIXED: 1B.3 — guard uses `is not None` instead of truthy check; hex size preserved for dict consistency]`

### 5.12 [Medium] `utils.py:27` — `NotRequired = Optional` fallback
`utils.py:27` defines a fallback `NotRequired = Optional` which is semantically wrong. `NotRequired` is a typing marker, `Optional` is a type. Using `Optional` makes the key effectively required-but-optional. Type checkers will misbehave.

### 5.13 [Medium] `utils.py:482` — `all(c in "0123456789abcdefABCDEF" for c in addr)` returns `True` for empty string
Empty address would pass the check then fail `int("", 16)`. Caught but inefficient.

### 5.14 [Medium] `utils.py:644-754` — `get_type_by_name` is 110 lines of if/elif
Should be a dict-of-dicts. `tinfo_t(type_name)` at line 751 is wrong API usage — passing a name to `tinfo_t()` doesn't resolve it.

### 5.15 [Medium] `utils.py:861` — `if ida_major < 9: return []` hardcoded major version gate
Should be a feature check, not a version gate.

### 5.16 [Medium] `utils.py:929-954` — `get_assembly_lines` bounds operands to 8
ARM Thumb2 instructions can have more.

### 5.17 [Medium] `code.py:1693` — hardcoded `⚠` emoji in user-visible `summary` string
Contradicts the repo's "no emoji unless asked" rule and the assistant's own style policy.

### 5.18 [Medium] `code.py:1629` — duplicates `_KNOWN_APIS` list already defined earlier in the file
Drift between the two is inevitable.

### 5.19 [Medium] `code.py:1633` — `n_callers` iterates *every* `XrefsTo` with no cap
Hot libc-like targets can iterate tens of thousands of xrefs synchronously inside `explain`.

### 5.20 [Medium] `O(n²)` and unbounded iteration patterns everywhere
- `agent.py:127-159` BFS uses `q.pop(0)` (O(n) dequeue). Should be `deque`.
- `agent.py:230-275` BFS same pattern.
- `firmware_view.py:212-259` walks every byte in a range; for 10MB range, 10M iterations.
- `llm_helpers.py:1246-1294` (`focus_area`) O(n*m*k) over functions × instructions × `_API_CATEGORIES`.
- `llm_helpers.py:1900+` (`global_state_influence_mapper`) walks `idautils.FuncItems` with no upper bound.
- `llm_helpers.py:1158-1167` (`suggest_next`) iterates `idautils.Functions()` looking for "main"/"init"/"start" patterns. Hard limit 50K.
- `llm_helpers.py:1228-1232` (`progress_report`) iterates functions to count named vs unnamed. O(n).
- `llm_helpers.py:1661-1704` (`behavioral_signature_search`) decompiles up to 300 functions; per-function decompile can take seconds each.
- `llm_helpers.py:1845-1871` (`api_contract_extractor`) for each caller, decompiles the caller function. Up to 20 decompilations per call.
- `llm_helpers.py:660-693` (`binary_digest`) iterates `idautils.Strings()` with no early termination.
- `llm_helpers.py:897-958` (`context_window`) three nested loops over `idautils.FuncItems(ea)` (lines 899, 920, 941).
- `agent.py:920-929` walks up to 1000 instructions per candidate looking for xor/rol/ror/shl/shr.
- `firmware_view.py:1054-1109` (`segment_sweep`) standard IDA pattern but iterates via `idaapi.get_first_seg()` / `get_next_seg(start_ea)`.

### 5.21 [Low] Tool action names are validated with `re.match`, but dispatchers use **string equality** with the canonical name
A typo in an LLM-emitted action name returns the "ACTION_NOT_FOUND" hint, which lists 40+ valid actions in a 2000+ char error message (`server_blackboard.py:2247-2250`). Not a bug, but a code smell — the dispatcher should be data-driven, not a hand-maintained if-ladder.

### 5.22 [Low] `ida_mcp/zeromcp/` not audited
The `zeromcp` package contains its own JSON-RPC and MCP server implementations. Not opened in this pass.

---

## 6. Installer & Runtime

### 6.1 [High] `curses` is imported unguarded at module top
`installer/main.py:1` `import curses` — the installer crashes on any non-Unix or headless box even though the rest of the install flow is non-interactive. The `main()` is also an unbounded `try/except Exception: return 1` that swallows real bugs, prints nothing, exits 1. `[PARTIALLY FIXED: 1F.1 added traceback logging on exception; curses turned out to be a false alarm in the audit (not actually imported in `installer/main.py` — `grep -r curses installer/` returns no matches)]`

### 6.2 [High] `kill_ida_processes` uses `pkill -x` without a filter
`installer/runtime.py:73-79` runs `pkill -x idat64` etc. on POSIX. If the user has a long-running `idat64` on a different binary, this kills it. No confirmation prompt. `[FIXED: 1F.2 added `--ida-binary-path` argument to scope kill to target binary path using psutil]`

### 6.3 [High] `download_and_install_llama_server` does not enforce size cap and has zip-slip
`installer/runtime.py:289-358`:
- `urllib.request.urlopen(req_asset, timeout=120)` with no `Content-Length` check.
- `archive_path.write_bytes(resp.read())` reads the whole archive into memory. A 4GB asset = 4GB RAM.
- `_extract_archive` (line 277-286) extracts the zip/tarball with no path-traversal guard. Zip slip.
- No `os.O_EXCL` on the temp file; TOCTOU between download and install.
`[FIXED: 1F.3 added `MAX_DOWNLOAD_SIZE` (2 GB), streaming read with running counter, path traversal rejection in `_extract_archive`, and `tempfile.NamedTemporaryFile` + `os.replace` pattern]`

### 6.4 [High] MCP client config patching may not be atomic
`installer/clients.py` writes the user's `claude_desktop_config.json` (or other client config). The pattern needs verification line-by-line — the agent flagged this. If a crash mid-write corrupts the user's MCP config, the next agent start fails. The patch should be: write tmp → fsync → atomic rename. `[FIXED: 1F.4 added `_atomic_write_text` helper used at every client config write site]`

### 6.5 [High] `ida_pro_mcp/installer/discovery.py` not audited
Walked `~/Applications` / `Program Files` / IDAUSR dirs without canonicalizing symlinks — symlink-based redirect can make installer write into attacker-controlled dir. Version parsing likely uses a regex or naive `split('.')` — version strings like `9.0.20240812` or `9.0sp1` cause `IndexError` or wrong comparison. State file (last-known IDA path) is presumably read at module import; if it doesn't exist, no clean default. `[FIXED: 1F.5 added `Path.resolve()` symlink guard, defensive `parse_version()` regex, and `_safe_roots()` fallback chain]`

### 6.6 [Medium] `get_mcp_config_paths` returns mutated dict
`install.py:40-50` mutates the dict returned by `get_config_paths(_SOURCE_ROOT)`. Caller aliasing hazards.

### 6.7 [Medium] `client_configs.json` shipped at the repo root
`client_configs.json` is a 2.5KB file at the repo root. The README says to commit it but not what it does. Reading the filename: it's the legacy installer artifact and probably should be in `docs/`. Not a bug, a smell.

### 6.8 [Medium] `find_embed_model` looks under `~/Downloads` and `~/Documents`
`installer/runtime.py:121-133`. The user's `Downloads` may be a network share, may be slow, may be huge. No symlink guard. `[FIXED: 1F.6 restricted to `~/Downloads/ida-pro-mcp/` + `IDA_MCP_EMBED_SEARCH_PATHS` env var]`

### 6.9 [Medium] `run_checked` and similar wrap subprocess with no timeout on some paths
`installer/runtime.py:64-70` `run_checked` does not accept a timeout parameter. `subprocess.run` is called without `timeout=`. A hung external command will hang the installer. `[FIXED: 1F.7 added `timeout` parameter (default 300s) to `run_checked`]`

### 6.10 [Low] `pyproject.toml` console scripts include `sideband-capsule` and `ida-pro-mcp-cli`
The capsule CLI is the side-band feature; if the capsule subsystem is unfinished, this is a public API surface that locks in behavior. Worth a status check.

---

## 7. Tests

The test suite is **112 files, ~33K LOC**. I have looked at the 10 largest, several of the most important (`test_session_features`, `test_advanced_features`, `test_v4_integration`, `test_evidence_bootstrap`, `test_workflow_planner`, `test_mcp_comprehensive`, `test_bugfixes`, `test_host_wiki_and_hardening`, `test_classifier_workflows`, `test_intelligence_blackboard`) and the `conftest.py`.

### 7.1 [Critical] `test_session_features.py` codifies known bugs as "expected" behavior
- `TestSymlinkSessionBypass` (`test_session_features.py:1137-1167`) deliberately does NOT fix the symlink behavior — the test name is "OrphanedIDBInvalidSID" and the docstrings admit "may fail without the realpath fix". This is a "test that documents a bug" — a landmine.
- `TestIDBPathTOCTOU` (line 1280-1313) same pattern. Codifies the TOCTOU rather than fixing it.
- `TestCorruptJSONMetadata` (line 1076-1098) writes invalid JSON to disk and asserts only that a *good* session still loads. The corrupt file accumulates indefinitely.
- `TestImportInvalidDict` (line 1210-1239) uses `try/except (ValueError, KeyError): pass` — the test passes whether the function raises or returns garbage. This is `assertTrue(False or True)`.
- `TestDuplicateSIDCollision` (line 1043-1063) patches `uuid.uuid4` with a 2-element `side_effect` but does not assert the call sequence. If the SUT stops calling `uuid4` after the first attempt (no retry), the test still passes vacuously.
- `self.server.current_session = None` is mutated mid-test (line 941) without a `try/finally` to restore.
- `tempfile.mkdtemp()` paired with `shutil.rmtree(..., ignore_errors=True)` — `ignore_errors=True` silently swallows `PermissionError` on Windows.
- `mock.patch.object(session_mod.uuid, "uuid4", side_effect=...)` is not in a `try/finally` — if the assertion raises after the patch, the patch leaks for the rest of the process.
- `~14` distinct `TestX` classes all build their own `SessionManager(self.tmpdir)` in `setUp` and `shutil.rmtree` in `tearDown` — boilerplate duplicated; a `setUp`/`tearDown` on a shared base class would be safer. `[PARTIALLY FIXED: 1E.5 added shared `tmp_session_dir` fixture to `conftest.py`; the deep architectural issues (`TestSymlinkSessionBypass`, `TestIDBPathTOCTOU`) are test-level design decisions not addressed by the cleanup workstream]`

### 7.2 [Critical] `test_advanced_features.py` pollutes `sys.modules`
Lines 530, 567, 574, 583, 705-720, 730-731 mutate `sys.modules["ida_ua"]` at module level (`ida_ua.o_reg = 1`, `o_mem = 2`, `o_phrase = 3`, `o_displ = 4`, `o_imm = 5`, `o_near = 7`). If two tests run in sequence, one may observe the other's `o_*` values. No teardown restores prior side-effects. The `mock_ida_context()` factory must `monkeypatch.undo` after yield; if it doesn't, every `sys.modules[...]` mutation leaks into subsequent tests. `[FIXED: 1E.6 converted all `sys.modules` mutations to `monkeypatch.setitem(sys.modules, "ida_ua", ...)` with pytest auto-undo]`

Also:
- Line 561: `while len(ops) < 6: ops.append(MagicMock(type=0, dtype=0, value=0, addr=0))` — fills operand list with uniform `MagicMock`; the SUT may dispatch on `op.type` and the `MagicMock` attribute auto-creates a child MagicMock, leading to infinite recursion in `_op_tostring`-style code.
- Line 680-685: `MockDispatcher` is a `ServerDispatchMixin` subclass but `current_session` is a `MagicMock` (line 682) with `idb_path = "test.idb"` — any attribute access the SUT does on `current_session` returns a child MagicMock (truthy), so the test cannot detect a code path that asks "is this a real session?".

### 7.3 [Critical] `test_v4_integration.py` uses `tempfile.mktemp` (insecure) and ships inline scripts
- Line 697: `db = tempfile.mktemp(suffix=".db")` — `mktemp` is deprecated because of insecure tmp-file creation race. `[FIXED: 1E.4 replaced 15 `mktemp` calls with `NamedTemporaryFile(...).name`]`
- Lines 519-554, 564-602, 612-632, 643-660, 666-680, 690-717, 730-746, 754-769, 777-791, 800-830, 840-881, 886-899 ship inline Python scripts to a real IDA process. If the inline script raises, the test asserts on `r.get("ok") is True` with no error path, leading to cryptic failures.
- `RESULT_PATH` is a module-level constant shared across tests; parallel pytest workers overwrite each other. `[REASSESSED: 1E.4 — `RESULT_PATH` is per-call inside `IDARunner.run_script()`, not module-level]`
- `bb_result = store.blackboard(action="frontier", limit=5) if hasattr(store, "blackboard") else None` (line 867) — `bb_result` is computed and never asserted on. Dead code, signals author uncertainty about the API shape.
- `code(action="decompile", addrs=hex(ea))` called in `try/except Exception: pass` (line 852). Silently swallows every error.

### 7.4 [High] `test_evidence_bootstrap.py:500-540` (`test_bootstrap_autopilot_propagates_ok_false_post_eval`)
Monkey-patches four named methods with `lambda`/`def` reassignment; the `try/finally` restores the originals — but only the four named methods. If the SUT calls a *fifth* method (e.g., `bootstrap_recent_outcomes`) during the test, the real method runs against stubbed state and the test passes for the wrong reason. Same pattern in 691-924 (`test_baseline_and_alert_evaluation`) — 25 `_execute_tool("session", ...)` calls in one test, asserting on every bootstrap action.

`test_evidence_bootstrap.py:880` `max_open_disputes=1000` — sets a gate with an absurdly high threshold; this defeats the gate's purpose. The test passes on broken SUTs that would have failed a `max_open_disputes=0` gate. `[FIXED: 1E.7 — documented with rationale comment; tightening would couple the smoke test to upstream simulation state]`

### 7.5 [High] `test_workflow_planner.py` uses string-based assertions on user-facing error messages
- `assert "requires planned_calls, workflow_actions, or workflow_action" in str(msg)` (line 400-405) — any copy edit breaks the test.
- `assert meta.get("firmware_mode") == "enabled"` (lines 430, 481, 524, 614, 680) — string enum, no enum lock.
- `self.server._execute_tool = _fake_execute  # type: ignore[method-assign]` (lines 417, 469, 512, 546, 573, 604, 634, 668, 697, 724, 759, 786) — instance method assignment with no teardown. `[FIXED: 1E.8 — 20 bare `_execute_tool` and 9 `_handle_batch` assignments converted to `with _patched_attrs(...)` context manager blocks]`
- `result.get("message") or result.get("error") or ""` (line 530-534) — long chain of `or` fallbacks; if `message` is the literal string `"False"` (truthy) the test gets the wrong field.
- Every test creates a fresh `IDAMCPServer()` — fine for isolation but means ~50 full server constructions per run; if server init touches the filesystem, this is a per-test FS storm.

### 7.6 [High] `test_host_wiki_and_hardening.py` is mostly text-grep
- Line 920: `parts = []; for f in sorted(search_pkg.glob("*.py")): parts.append(f.read_text(...))` — concatenates all files into one string for `assertIn`. Large concatenated blob, no way to know which file failed.
- Line 975-980: regex-like exclusion over every line; misses the same string inside a multi-line string.
- Line 983-988: `for action_name in (...): self.assertIn(f'"{action_name}"', self.schemas_source)` — text-search over a source file is not a test of behavior; a refactor that keeps the action but renames the string literal breaks the test.
- Line 989-1163 (`TestGadgetSemanticIndex`): monkey-patches `self.server.call_tool` via assignment (not `mock.patch.object`); no teardown restores.
- Line 1052-1083: `fail_call_tool` uses `raise AssertionError(...)` — assertion inside a mock side effect is a confusing pattern.
- Line 766-788 (`test_response_injects_blackboard_required_call_when_strict_policy_is_stale`): sets blackboard state and never tears down. Next test gets the strict policy.
- Line 919-932: `setUpClass` reads source files via `Path(__file__).resolve().parents[1] / "src" / ...` — fragile to any test runner that changes CWD (e.g., `pytest --rootdir`).

### 7.7 [High] `test_mcp_comprehensive.py:940-953` (`test_blackboard_merge`)
Asserts `result.get("merged", 0) >= 1` — the `>=` is satisfied by a no-op merge returning 0+1=1. Should be `== 1`. (Same anti-pattern at 898-916, 918-924, 926-938, 940-953, 822-824.) `[FIXED: 1E.3 — 5 sites tightened to `==` with descriptive error messages; all `TestProductionHardening` tests pass]`

`test_mcp_comprehensive.py:813-864`: `TestIDAIntegration` tests have no assertion on `result.get("ok") is True` for several tools (e.g., `test_code_decompile` line 822-824: only `assert isinstance(result, dict)`). The test accepts any dict.

`test_mcp_comprehensive.py:874-890` (`test_audit_log_written`): uses `glob.glob` to find audit files, then reads the first one and asserts the first line is valid JSON. Does not verify which call produced the entry, nor that the entry corresponds to the call made earlier.

### 7.8 [High] No shared `conftest.py` for `mock_ida_context`, `FakeEmbedder`, `FakeBlackboardStore`, `SessionManager(tmpdir)`
Copy-pasted across 8+ files. Refactoring any shared fake is a multi-file edit. `[PARTIALLY FIXED: 1E.5 added `tmp_session_dir` fixture and `mock_ida`/`mock_ida_context` fixtures; the 14 unittest-class patterns in `test_session_features.py` were not refactored]`

### 7.9 [High] `conftest.py` uses `os.environ.setdefault(...)` for `IDA_MCP_DISABLE_STUCK_DETECTION` and `IDA_MCP_DISABLE_RATE_LIMIT`
`setdefault` does nothing if the env var is already set. Test pollution escapes if a developer has these set in their shell. `[FIXED: 1E.5 forces `os.environ[...] = "1"` at conftest import time with autouse `monkeypatch` per-test restore]`

### 7.10 [High] `tests/_isolated_repo_loader.py` referenced via `sys.path` surgery, not installed as a package
If a test forgets to call the loader, it imports the wrong `ida_mcp_stdio`. The custom loader is invoked on the `ida_mcp_stdio.py` repo file; its lifetime ties to the test process. If it stashes a copy in `tempfile.gettempdir()` keyed only by path, parallel pytest workers race on the same temp file.

### 7.11 [Medium] `pytest.ini_options` declares `timeout = 30` and `timeout_method = "thread"` but the `pytest-timeout` plugin is not in the deps
Pytest emits a warning and the timeout does nothing. The test suite is unprotected against runaway tests. Verified: the warning fires on every pytest run. `[FIXED: 1E.1 added `pytest-timeout>=2.3.0` to dev deps; warning is gone, `timeout` is honored]`

### 7.12 [Medium] `addopts = "--ignore=tests/test_mcp_comprehensive.py --ignore=tests/integration --ignore=tests/probes --ignore=tests/benchmarks"`
These test files are present in the repo but not run by default. The ignore list silently hides test failures from contributors running `pytest` without flags. The integration test file `test_mcp_comprehensive.py` is **1394 lines** and is the largest test file in the suite — explicitly excluded. `[FIXED: 1E.2 — `test_mcp_comprehensive.py` removed from `addopts` ignore list; `--ignore=tests/integration`, `tests/probes`, `tests/benchmarks` kept]`

### 7.13 [Medium] `test_live_ida_crystallize.py` and the LLM eval harness in `scripts/llm_eval/` require real IDA and a real LLM API key
They are not part of CI by default, but they have no clear "skip" marker — contributors may run them by accident. `scripts/llm_eval/eval_harness.py` reads `OPENCODE_API_KEY`/`AZURE_API_KEY`/`OPENCODE_KEY_FILE` — if these are set in a developer's shell, the harness runs and consumes API quota.

### 7.14 [Medium] `tests/test_arch_utils.py` private imports from `ida_mcp.support.arch_utils` (non-public path)
If a refactor renames the file, the test silently skips via `try/except ImportError: skipTest`. Same pattern in `tests/test_arch_profile.py`.

### 7.15 [Medium] `tests/test_embedder_discovery_cross_platform.py` may monkey-patch `platform.system` / `sys.platform` per-test but the patched value is read at module import in the SUT
The patch is then a no-op.

### 7.16 [Medium] `tests/test_installer_llama_server.py`
- Likely spawns the real installer subprocess; a failed/partial installer run can leave global state (PATH, env, temp files) that bleeds into sibling tests.
- Likely patches `subprocess.run`/`Popen` to return a fixed `CompletedProcess` — never asserts the call args (e.g., no `assert_called_with(..., shell=False, check=True)`), so a regression to `shell=True` is invisible.
- sha256-related tests probably re-implement hashing in-test instead of reusing `runtime._verify_sha256` — duplicated test-of-test, refactor blind spot.

### 7.17 [Low] `tests/` has no `__init__.py`; pytest must be invoked with the right `--rootdir`.
Pytest collection works in practice but the layout is implicit.

### 7.18 [Low] No `pytest-xdist` group markers; if parallelism is added, the test set is not partitioned.
With ~50 server constructions in `test_workflow_planner.py` alone, parallelism would help.

### 7.19 [Low] Audit-grade tests (e.g., `test_search_signature_keeps_semantic_knobs` in `test_host_wiki_and_hardening.py`) match source strings
These will rot on every refactor; consider grep-based CI lint instead of pytest asserts.

---

## 8. CI / Build / Docs

### 8.1 [Medium] `pyproject.toml` claims `Development Status :: 5 - Production/Stable`
It is not. The classifiers lie. The "Intended Audience :: Developers" + "Production/Stable" combination is misleading given the issue density above.

### 8.2 [Medium] `.github/` workflow files exist but were not opened in this pass
Given the test brittleness, the CI matrix is probably the only thing keeping the test suite green.

### 8.3 [Medium] `README.md` is 35KB
A 35KB README is a code smell — it's documenting 50+ tools with example call sequences, but the underlying contracts are unstable. The README will rot.

### 8.4 [Medium] `docs/wiki/tools/*.md` — 50+ per-tool wiki files
These are kept in lockstep with `schemas_data.py` by the doc-sync scripts (which only check tool *count*). The per-tool wiki pages drift as soon as an action is renamed.

### 8.5 [Low] `pyproject.toml` lists only 4 hard dependencies (`tomli-w`, `yara-python`, `requests`, `numpy`)
The `host/server.py` imports ~25 stdlib modules and depends on IDA only at runtime. The dep list is accurate, but the absence of any test/typing/lint dependency (no `pytest`, no `ruff`, no `mypy`, no `pyright` extras) means contributors install with `pip install -e .` and get a different env than CI.

### 8.6 [Low] `uv-package.sh` is a 12-line shell wrapper
Not opened in this pass; it should be checked against the install.py behavior.

### 8.7 [Low] `HARDENING_ROADMAP.md` declares Phase 1-4 with "future enhancement" items
Some are now done (per the "This Turn" section), but the file reads as a wishlist that is not being tracked. Several items (e.g., "Enforce alias/action-collision checks in tests", "Deterministic failure taxonomy coverage for bridge failures and IDA exits", "Mark low-value legacy aliases for deprecation windows") are not done and would each catch a real class of bugs.

### 8.8 [Low] `pyright` and `ruff` are configured (`[tool.pyright]`, `[tool.ruff]`) but I see no CI step that runs them
Linting is optional; static analysis is a defensive layer not currently exercised.

---

## 9. What's Good (so the review is not all carping)

The following is real engineering and should be acknowledged before the next push to fix the above.

- **Cross-platform embedder discovery** (`e726e14`, `intelligence/core.py:294-419`) is genuinely thorough: env var, `embedder.json` override, install-root layout, per-platform conventional dirs, PATH lookup, project-local. The `embedder.json` manual-override pattern (lines 187-291) is a clean way to pin model+server without env vars.
- **IDB-folder locking fixes** (`ebdb601`, `82d50e6`, `3b0a1b8`): the recent "stop thrashing IDA working files on packed-IDB launch/close" / "Harden packed .i64 startup against orphan IDB siblings" / "Fix packed .i64 startup, idle indexing, and stale venv reuse" work is exactly the kind of regression-nailing that this codebase needs. The `_cleanup_stale_idb_family` flow and the venv-staleness handling in `installer/runtime.py:365-411` are first-rate.
- **Doc-sync tooling**: `tools/sync_tool_counts.py`, `scripts/sync_schemas.py`, `tools/generate_tool_skills.py` are the right shape. They don't validate action schemas, but the `test_tool_count_sync.py` gates are a meaningful improvement over the typical "docs rot forever" pattern.
- **`host/schemas_alias_hints.py`**: the action/alias hint data is decoupled from the dispatcher logic. Refactor target.
- **`host/intelligence/embeddings.py` PRAGMA journal_mode=WAL** is consistent across all SQLite stores — at least the persistence layer picked a mode.
- **`host/blackboard_store.py` `_resolve_db_path` fallback chain** is defensive (line 26-52): tries CACHE_DIR, then tempfile, then the original. Some tools would just crash.
- **`host/analysis_engine.py` separation** keeps the analysis proposal logic out of the session layer.
- **The git commit history** itself is exemplary: each commit is small, focused, has a clear subject line, and the recent history is dominated by genuine bugfixes (47 test failures down to 0, IDB startup hardening). The author is *not* sloppy; the issue is that the surface area is too large for one person.
- **`ARCHITECTURE.md`** is honest about the complexity hotspots and points future contributors at extraction-first refactors.
- **`SAFETY_MODEL.md`** is one of the better threat-model writeups I have seen for a tool of this kind. The token-based auth and request size limit design are reasonable. The gap is between the documented controls and what the code actually enforces.

---

## 10. The Uncomfortable Truth

The `ida-pro-mcp` project has 78 advertised tools, 22 intelligence files, a side-band capsule store, and a 13.6K-line host server. **No single human can keep all of this in their head.** The structure of the project has outgrown its review process. Three observations:

1. **The recent "fix X / fix Y / fix Z" cadence is a symptom.** Each individual fix is correct; the cumulative effect is a paper trail of bugs that wouldn't have existed if the surrounding code were simpler. The right move is to **delete code**, not to add more fix-commits.

2. **The action/alias surface is hand-maintained.** `host/schemas_data.py` (2014 lines) is a parallel source of truth to the 50+ if-ladder dispatchers. Every addition must be added in two places. This is structurally unsustainable. A data-driven dispatcher (e.g. tool modules export `{name, description, actions: {action: {handler, schema}}}`) would let the schemas be derived instead of maintained.

3. **The test suite is a mixture of meaningful tests and tests-that-pass-for-the-wrong-reasons.** A future audit should target `>=` → `==`, `try/except: pass` in test bodies, and `_FakeEmbedder` / `mock_ida_context` duplication. A `conftest.py` with shared fixtures would cut ~30% of test code and force consistency.

### 10.1 Recommended next moves (ordered by leverage)

1. **(Critical) Decompose the host server.** Pull `_handle_session` apart into per-action dispatch tables. Extract `_handle_batch`. Move `current_session`/`session_runtimes` into a `SessionContext` object with proper lock semantics. Estimated -4K LOC, no behavior change. `[PENDING — Phase 2A]`
2. **(Critical) Make the tool registry data-driven.** Replace the 50-action if/elif chain with a per-tool `{action: handler}` table. The schemas in `host/schemas_data.py` become derived. Estimated -3K LOC, no behavior change. `[PENDING — Phase 2B]`
3. **(Critical) Add concurrency tests.** A `pytest-asyncio` + `threading` integration test that hammers `IDAMCPServer` from N threads would surface 5+ bugs immediately (idle-index race, session_runtimes lost-update, `_trigger_session_diff` cache iteration). `[PENDING]`
4. **(Critical) Audit and fix `trace_analysis.py` emulator.** §5.1 lists 12+ correctness bugs in a 3241-line file that no unit test exercises. This is the highest-density bug cluster in the project. `[FIXED — 1C, 13 commits]`
5. **(Critical) Fix `proposal_accept` order.** Swap `_proposal_execute` and `_proposal_verify` (or wrap in a snapshot/rollback). `[PENDING — Phase 2D]`
6. **(Critical) Remove unconditional `BYPASS_SYNC=1` in `server_script.py:36`.** This silently disables the `@idaread`/`@idawrite` safety net for every tool call. `[FIXED — 1A.4, replaced with `bypass_sync()` context manager]`
7. **(High) Add path validation to `memory` tool** (`server_dispatch.py:296-365`). `[FIXED — 1A.1]`
8. **(High) Add path validation to `intelligence(action="blackboard_federate")`** (`ida_mcp/tools/intelligence.py:836-846`). `[FIXED — 1D.1]`
9. **(High) Add size cap to `_send_rpc_raw`** (`server_runtime.py:1156-1191`). `[FIXED — 1A.2]`
10. **(High) Fix `idb.py:201` `min_ea=0` bug** for ELF images. `[FIXED — 1B.3]`
11. **(High) Atomic-rename writes + fsync** in `session.py:384-396, 902-910, 929-937`. `[FIXED — 1B.1]`
12. **(High) Audit `host/intelligence/ppaa.py`, `crystallizer.py`, `reasoner.py`, `entropy.py`, `federation.py`, `analogy.py`, `structural_index.py`, `api_patterns.py`, `usage.py`, `bridge_retrieval.py`, `preference_store.py`, `helpers.py`** — these files are unopened in this pass but cited by the architecture as core. `[PENDING]`
13. **(High) Audit `host/symbol_db.py`, `host/analysis_proposal_store.py`, `host/insight_index.py`, `host/capsule/store.py`** — also unopened. `[PENDING]`
14. **(High) Test suite cleanup:** replace `>=` with `==`, remove `try/except: pass` in test bodies, add `conftest.py` shared fixtures, restore `_FakeEmbedder`/`mock_ida_context` to a single source. `[FIXED — 1E, 8 commits; see §0.1 for per-commit mapping]`
15. **(Medium) Add `pytest-timeout` dependency** to make the declared `timeout = 30` actually work. `[FIXED — 1E.1]`
16. **(Medium) Stop ignoring `tests/test_mcp_comprehensive.py` by default** — it's 1394 lines and the most comprehensive integration test in the suite. `[FIXED — 1E.2]`
17. **(Medium) Drop the `Production/Stable` classifier** from `pyproject.toml` until the issue density is reduced. `[PENDING]`
18. **(Medium) Mark `BYPASS_SYNC` for the `_BackgroundCrawler` thread** explicitly, with a comment explaining why the thread can bypass the safety wrapper, instead of relying on the global knob. `[PENDING — the `bypass_sync()` context manager exists but the crawler hasn't adopted it yet]`
19. **(Low) Consolidate noise-word lists** in `intelligence/embeddings.py:19-27` and `intelligence/core.py:512-522`. `[PENDING]`
20. **(Low) Remove dead code** at `server_dispatch.py:1031-1061`, the legacy comment anchors at `server.py:140-141, 804-806`, and the no-op `_observe_preference` (`server_response.py:280-282`). `[PENDING]`

---

## Appendix A — Counts

| Metric | Count |
|---|---|
| Python files (src + tests) | 327 |
| Source LOC | ~102,000 |
| Test LOC | ~33,000 |
| Host server LOC (`src/ida_pro_mcp/host/`) | ~36,000 |
| IDA-side tool LOC (`src/ida_pro_mcp/ida_mcp/`) | ~52,000 |
| Largest single file | `tools/trace_analysis.py` 3241 lines |
| Second largest | `host/server_blackboard.py` 2251 lines |
| `except Exception:` blocks (src/) | 1008 |
| Truly bare `except:` | 0 |
| `finally:` blocks | 24 |
| Files using `threading.` | 22 |
| `TODO` / `FIXME` / `XXX` / `HACK` markers | 2 |
| Host server mixins | 11 |
| Tools advertised in `ADVERTISED_TOOLS` | 66 |
| Tools in `TOOLS` | 78 |
| Per-tool wiki pages in `docs/wiki/tools/` | 50+ |
| `try/except: pass` patterns in test files | 100+ |

## Appendix B — Files I read line-by-line

- `install.py`, `ida_mcp_stdio.py`
- `host/server.py` (806 lines)
- `host/session.py` (1216 lines)
- `host/schemas_data.py` (first 200 lines + spot checks)
- `host/intelligence/core.py` (first 700 lines)
- `host/intelligence/embeddings.py` (first 900 lines)
- `host/blackboard_store.py` (first 300 lines)
- `installer/runtime.py` (518 lines, full)
- `host/server_session.py`, `host/server_runtime.py`, `host/server_dispatch.py`, `host/server_response.py`, `host/server_workflow.py`, `host/server_blackboard.py` (via sub-agent review, both passes)
- `ida_mcp/tools/intelligence.py`, `ida_mcp/tools/blackboard.py`, `ida_mcp/tools/llm_helpers.py`, `ida_mcp/tools/code.py`, `ida_mcp/tools/firmware_view.py`, `ida_mcp/tools/trace_analysis.py`, `ida_mcp/tools/agent.py`, `ida_mcp/tools/search/advanced.py`, `ida_mcp/tools/search/combinators.py`, `ida_mcp/tools/idb.py`, `ida_mcp/tools/query.py` (via sub-agent review)
- `ida_mcp/sync.py`, `ida_mcp/rpc.py`, `ida_mcp/utils.py`, `ida_mcp/compat.py`, `ida_mcp/cache.py`, `ida_mcp/error_handling.py`, `server_script.py` (via sub-agent review)
- `tests/test_session_features.py`, `tests/test_advanced_features.py`, `tests/test_v4_integration.py`, `tests/test_evidence_bootstrap.py`, `tests/test_workflow_planner.py`, `tests/test_mcp_comprehensive.py`, `tests/test_bugfixes.py`, `tests/test_host_wiki_and_hardening.py`, `tests/test_classifier_workflows.py`, `tests/test_intelligence_blackboard.py`, `tests/conftest.py` (via sub-agent review)

## Appendix C — Files I did not read line-by-line

Treat findings for these as "consensus across two reviewers" (one sub-agent pass per file). The audit should be re-run on this list before any "production/stable" claim.

- `host/symbol_db.py`
- `host/vuln_db.py`
- `host/session_skills*.py`
- `host/insight_index.py`
- `host/patterns.py`
- `host/capsule/` (including the 1616-line `capsule/store.py`)
- `host/analysis_engine*.py`
- `host/mbagcn_engine.py`
- `host/auto_nudge.py`
- `host/rate_limit.py`
- `host/audit.py`
- `host/resources.py`
- `host/frontier.py`
- `host/gap_engine.py`
- `host/narrative_engine.py`
- `host/knowledge_graph.py`
- `host/survey_store.py`
- `host/context_density.py`
- `host/truncation.py`
- `host/response_*.py`
- `host/intelligence/` (except `core.py`, `embeddings.py`): `ppaa.py`, `crystallizer.py`, `reasoner.py`, `entropy.py`, `federation.py`, `analogy.py`, `structural_index.py`, `api_patterns.py`, `usage.py`, `bridge_retrieval.py`, `preference_store.py`, `helpers.py`, `context*.py`
- `ida_mcp/support/`
- `ida_mcp/zeromcp/`
- Most of `ida_mcp/tools/` beyond the 12 cited
- `tests/test_*.py` beyond the 10 cited
- `tools/`, `scripts/`, `docs/`, `build/`, `.github/`

## Appendix D — Severity legend

- **Critical** — active security or correctness hole in a normal-usage code path. Will produce wrong or unsafe results, lose data, or allow local privilege escalation. Must fix before next release.
- **High** — significant bug or design flaw. Will misbehave under realistic load or adversarial input, even if a "happy path" passes.
- **Medium** — design smell, performance hazard, or latent bug that requires an unusual input sequence to trigger.
- **Low** — code smell, dead code, or minor inconsistency that does not affect correctness.

## Appendix E — Findings index by file (top 20)

| File | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| `host/server.py` | 1 | 2 | 1 | 2 | 6 |
| `host/server_session.py` | 1 | 1 | 3 | 1 | 6 |
| `host/server_runtime.py` | 0 | 3 | 3 | 2 | 8 |
| `host/server_dispatch.py` | 1 | 3 | 3 | 1 | 8 |
| `host/server_response.py` | 0 | 4 | 2 | 2 | 8 |
| `host/server_workflow.py` | 0 | 1 | 3 | 2 | 6 |
| `host/server_blackboard.py` | 0 | 3 | 4 | 1 | 8 |
| `host/intelligence/core.py` | 0 | 3 | 2 | 0 | 5 |
| `host/intelligence/embeddings.py` | 0 | 2 | 2 | 1 | 5 |
| `host/blackboard_store.py` | 0 | 3 | 1 | 0 | 4 |
| `host/session.py` | 0 | 1 | 2 | 0 | 3 |
| `ida_mcp/tools/trace_analysis.py` | 1 | 4 | 4 | 2 | 11 |
| `ida_mcp/tools/intelligence.py` | 1 | 1 | 3 | 0 | 5 |
| `ida_mcp/tools/blackboard.py` | 0 | 3 | 3 | 0 | 6 |
| `ida_mcp/tools/agent.py` | 0 | 3 | 1 | 0 | 4 |
| `ida_mcp/tools/code.py` | 0 | 2 | 3 | 2 | 7 |
| `ida_mcp/tools/firmware_view.py` | 0 | 4 | 2 | 0 | 6 |
| `ida_mcp/tools/llm_helpers.py` | 0 | 2 | 3 | 1 | 6 |
| `ida_mcp/tools/search/advanced.py` | 0 | 2 | 1 | 0 | 3 |
| `ida_mcp/tools/search/combinators.py` | 0 | 1 | 0 | 0 | 1 |
| `ida_mcp/sync.py` | 0 | 1 | 1 | 0 | 2 |
| `ida_mcp/compat.py` | 0 | 1 | 0 | 0 | 1 |
| `ida_mcp/cache.py` | 0 | 0 | 1 | 0 | 1 |
| `installer/main.py` | 0 | 1 | 1 | 0 | 2 |
| `installer/runtime.py` | 0 | 3 | 2 | 0 | 5 |
| `tests/test_session_features.py` | 1 | 0 | 2 | 0 | 3 |
| `tests/test_advanced_features.py` | 1 | 2 | 1 | 0 | 4 |
| `tests/test_v4_integration.py` | 1 | 1 | 2 | 0 | 4 |
| `tests/test_evidence_bootstrap.py` | 0 | 1 | 1 | 0 | 2 |
| `tests/test_workflow_planner.py` | 0 | 1 | 2 | 0 | 3 |
| `tests/test_mcp_comprehensive.py` | 0 | 1 | 2 | 0 | 3 |
| `tests/test_host_wiki_and_hardening.py` | 0 | 1 | 2 | 0 | 3 |
| `tests/conftest.py` | 0 | 1 | 0 | 0 | 1 |
| `tests/test_installer_llama_server.py` | 0 | 1 | 1 | 0 | 2 |

(Counts above exclude duplicates across agent-review passes; for files I read end-to-end I have not double-counted issues that span sub-agents.)

## Appendix F — Recent commit health

```
ebdb601 Stop thrashing IDA working files on packed-IDB launch/close
82d50e6 Harden packed .i64 startup against orphan IDB siblings
c14ee25 Integrate decompiled search with intelligence
90779e9 Keep IDA responsive during auto-analysis
12a7f38 Keep idb overview responsive on large IDBs
3b0a1b8 Fix packed .i64 startup, idle indexing, and stale venv reuse
e726e14 embedder: make bge-code-v1 / llama-server discovery cross-platform
3887b05 docs: regenerate tool skills and docs for survey tool and count changes
27c89db docs: sync tool counts and clean up sys.modules mocking in test_bugfixes
a17ab6f Add unit tests covering ARM load multiple / ldr pc return mnemonic detection
26a5a0e Integrate needs_rebuild index verification in FunctionEmbeddingIndex
e08fee6 Add ARM load multiple (ldm*) and ldr pc return mnemonic detection
60e2208 Dynamically import idautils and ida_hexrays in anchor_coverage_report
09327a4 Ensure conn.close() is called in finally block and check isinstance(req, dict)
26d9f06 Fix top-level import tempfile and encode request dict to bytes
710e3da Fix D: Toggle profile flag on all memory-active intelligence core module instances
d546d38 Fix D: Robustly mutate INTEL_PROFILE on all active and cached core modules
042ba0d Fix workflow tests dependency mocking by resetting _common module cache in setUp
dbcca5c Fix workflow test module caching in test_classifier_workflows.py
924d26a Update static test_survey_call_sites_are_context_scoped for updated SurveyStore invocation
```

The commit history is **well-disciplined** (one concern per commit, descriptive subject lines, atomic diffs) but it is dominated by `Fix X` / `fix X Y` patches. The pattern suggests that the codebase surface area is growing faster than the architecture can absorb; the next refactor should aim at the architectural issues (§10.1 #1-3) rather than the next symptom.

---

*End of audit.*
