"""Regression tests for work order WO-H1 — batch output→input chaining.

Covers the pipeline primitive (paper section 4.2) built on the shared batch
step executor in server_workflow_batch.py:

- a later step's argument binds from a prior step's result via ``step{i}_{key}``
  (top-level field) and ``step{i}.result{path}`` (dotted nested path);
- a step may declare ``output_key`` (default = its index) to name its result
  for later steps; ``output_key`` is metadata and never leaks into tool args;
- an unresolved reference (missing field, forward/out-of-range step, missing
  ``$param`` binding) is a hard INVALID_ARGS error — never a silent empty
  string or a raw passthrough of the reference text;
- ``bindings`` is an optional static ``{param: value}`` map merged before step
  refs (precedence: literal > bindings > step refs);
- a chained batch skips the single-list-RPC fast path (its results must
  accumulate step-by-step); plain batches still try it;
- ``r2`` is excluded from the batch fast path so host-side r2 calls take the
  per-call loop;
- workflow ``execute_plan`` runs through the same shared step executor, so
  plans chain and honor bindings too (with execute_plan's tool admission
  semantics preserved).

Tests are hermetic: a ``ServerWorkflowMixin`` fake with stubbed IO, no live
IDA, and no ``IDAMCPServer`` import (which would pull in the concurrently
in-flight r2 engine). An opaque raw-blob / RISC-V firmware scenario is used to
exercise the find→read→disassemble pipeline on low blob offsets.
"""

from __future__ import annotations

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server_workflow import ServerWorkflowMixin
from ida_pro_mcp.host.server.server_workflow_batch import (
    _BATCH_FAST_PATH_EXCLUDED_TOOLS,
    _NON_ARG_ANNOTATION_KEYS,
)


class _FakeBatchHost(ServerWorkflowMixin):
    """Hermetic batch/workflow host: ServerWorkflowMixin + stubbed IO.

    ``_try_batch_fast_path`` returns None so every batch runs the per-call
    loop, making chaining observable through ``_execute_tool``; the number of
    fast-path attempts is still recorded so tests can assert that chained
    batches never take the fast path.
    """

    current_session = None
    session_runtimes = {}

    def __init__(self, execute=None):
        self.calls: list[tuple[str, dict]] = []
        self.cache_calls: list[tuple[str, dict]] = []
        self.activity_calls: list[tuple[str, dict]] = []
        self.fast_path_attempts = 0
        self._execute = execute or self._default_execute

    @staticmethod
    def _default_execute(tool, args):
        if tool == "search" and args.get("action") == "find":
            return {
                "ok": True,
                "matches": [
                    {"addr": "0x401000", "name": "main"},
                    {"addr": "0x401100", "name": "sub_401100"},
                ],
            }
        if tool == "idb" and args.get("action") == "meta":
            return {"ok": True, "image_base": "0x1000", "arch": "riscv"}
        if tool == "data" and args.get("action") == "read_bytes":
            return {"ok": True, "addr": args.get("addr"), "bytes": "aa bb cc", "total": 3}
        if tool == "code" and args.get("action") == "disasm":
            return {"ok": True, "addr": args.get("addr"), "instructions": "li sp, -16\nj main"}
        return {"ok": True, "tool": tool}

    def _execute_tool(self, tool, args):
        self.calls.append((tool, dict(args)))
        return self._execute(tool, args)

    def _extract_response_options(self, args):
        return dict(args), {}

    def _cache_next_page(self, tool_name, args, payload):
        self.cache_calls.append((tool_name, dict(args)))
        return payload

    def _record_activity(self, tool_name, args, result):
        self.activity_calls.append((tool_name, dict(args)))

    def _try_batch_fast_path(self, calls, continue_on_error):
        # Stub: never take the list-shaped RPC fast path so every batch runs the
        # per-call loop and chaining is observable through _execute_tool.
        self.fast_path_attempts += 1


def _chained_batch(calls, **extra):
    host = _FakeBatchHost()
    result = host._handle_batch(
        {"calls": calls, "continue_on_error": True, **extra}
    )
    return host, result


# ---------------------------------------------------------------------------
# output→input chaining: dotted path and flat field references
# ---------------------------------------------------------------------------


def test_batch_step2_addr_binds_from_step1_first_result_addr():
    """step2's addr = step1's first-result addr via step1.result.matches.0.addr
    (the r2-style find→deref→follow primitive)."""
    host, result = _chained_batch(
        [
            {"name": "search", "arguments": {"action": "find", "query": "main"}},
            {
                "name": "code",
                "arguments": {"action": "disasm", "addr": "step0.result.matches.0.addr"},
            },
        ]
    )
    assert result["ok"] is True, result
    assert result["summary"]["errors"] == 0
    # The second step actually received the first step's first-result addr.
    assert host.calls[1][1]["addr"] == "0x401000"
    # And the envelope surfaces the chained value back to the caller.
    assert result["results"][1]["result"]["addr"] == "0x401000"


def test_batch_flat_step_field_reference():
    """The flat step{i}_{key} form reads a top-level field of a prior result."""
    host, result = _chained_batch(
        [
            {"name": "idb", "arguments": {"action": "meta"}},
            {
                "name": "data",
                "arguments": {"action": "read_bytes", "addr": "step0_image_base", "size": 16},
            },
        ]
    )
    assert result["ok"] is True, result
    assert host.calls[1][1]["addr"] == "0x1000"


def test_batch_chaining_via_declared_output_key():
    """A step that declares output_key names its result; later steps reference
    it by that name instead of step{i}."""
    host, result = _chained_batch(
        [
            {"name": "search", "arguments": {"action": "find", "query": "main"}, "output_key": "symtab"},
            {
                "name": "code",
                "arguments": {"action": "disasm", "addr": "symtab.result.matches.1.addr"},
            },
        ]
    )
    assert result["ok"] is True, result
    # matches.1 is the second match, proving nested-list addressing works.
    assert host.calls[1][1]["addr"] == "0x401100"


def test_batch_output_key_is_metadata_not_a_tool_arg():
    """output_key must be stripped by normalization, never merged into the
    arguments handed to _execute_tool (RPC admission would reject it)."""
    host = _FakeBatchHost()
    name, call_args, err = host._normalize_batch_call(
        {
            "name": "search",
            "arguments": {"action": "find", "query": "x"},
            "output_key": "symtab",
        },
        0,
    )
    assert err is None
    assert name == "search"
    assert call_args == {"action": "find", "query": "x"}
    assert "output_key" not in call_args
    assert "output_key" in _NON_ARG_ANNOTATION_KEYS


def test_batch_literal_strings_pass_through_unresolved():
    """A string that does not match the reference syntax is a literal and is
    passed through untouched (no false resolution of ordinary text)."""
    host, result = _chained_batch(
        [
            {"name": "search", "arguments": {"action": "find", "query": "GetProcAddress CreateThread"}},
        ]
    )
    assert result["ok"] is True
    assert host.calls[0][1]["query"] == "GetProcAddress CreateThread"


# ---------------------------------------------------------------------------
# unresolved references are hard errors, never silent
# ---------------------------------------------------------------------------


def test_batch_unresolved_nested_path_errors():
    """A dotted path that does not exist in the prior result is a clear
    INVALID_ARGS error, and the failing step is NOT executed."""
    host, result = _chained_batch(
        [
            {"name": "search", "arguments": {"action": "find", "query": "main"}},
            {
                "name": "code",
                "arguments": {"action": "disasm", "addr": "step0.result.missing.0.addr"},
            },
        ]
    )
    assert result["summary"]["errors"] == 1
    err = result["results"][1]["result"]
    assert err.get("error") is True
    assert err.get("code") == MCPError.INVALID_ARGS
    assert "unresolved" in err.get("message", "")
    # The bad step never reached _execute_tool.
    assert [t for t, _ in host.calls] == ["search"]


def test_batch_unresolved_flat_field_errors():
    host, result = _chained_batch(
        [
            {"name": "idb", "arguments": {"action": "meta"}},
            {"name": "data", "arguments": {"action": "read_bytes", "addr": "step0_nope"}},
        ]
    )
    assert result["summary"]["errors"] == 1
    err = result["results"][1]["result"]
    assert err.get("code") == MCPError.INVALID_ARGS


def test_batch_forward_and_out_of_range_step_refs_error():
    """step{i} references to a step that has not run (forward) or does not
    exist (out of range) error instead of passing the raw text through."""
    for ref in ("step2_addr", "step1.result.addr"):
        host, result = _chained_batch(
            [
                {"name": "search", "arguments": {"action": "find", "query": "main"}},
                {"name": "code", "arguments": {"action": "disasm", "addr": ref}},
            ]
        )
        assert result["summary"]["errors"] == 1, ref
        err = result["results"][1]["result"]
        assert err.get("code") == MCPError.INVALID_ARGS, (ref, err)
        assert len(host.calls) == 1, (ref, host.calls)


def test_batch_chaining_error_honors_continue_on_error_stop():
    """With continue_on_error=false the unresolved ref halts the batch like any
    other step error (the error entry is still reported)."""
    host = _FakeBatchHost()
    result = host._handle_batch(
        {
            "calls": [
                {"name": "search", "arguments": {"action": "find", "query": "main"}},
                {"name": "code", "arguments": {"action": "disasm", "addr": "step0.result.missing"}},
                {"name": "idb", "arguments": {"action": "meta"}},
            ],
        }
    )
    assert result["summary"]["errors"] == 1
    assert result["summary"]["stopped_on_error"] is True
    assert [t for t, _ in host.calls] == ["search"]


# ---------------------------------------------------------------------------
# bindings: static {param: value} map merged before step refs
# ---------------------------------------------------------------------------


def test_batch_bindings_substitution():
    host, result = _chained_batch(
        [
            {"name": "code", "arguments": {"action": "disasm", "addr": "$base"}},
        ],
        bindings={"base": "0x401000"},
    )
    assert result["ok"] is True, result
    assert host.calls[0][1]["addr"] == "0x401000"


def test_batch_bindings_combine_with_step_refs():
    """Literal > bindings > step refs: a $param binds a literal, and a step ref
    can feed off either without interfering."""
    host, result = _chained_batch(
        [
            {"name": "search", "arguments": {"action": "find", "query": "main"}},
            {"name": "code", "arguments": {"action": "disasm", "addr": "$fallback"}},
            {"name": "data", "arguments": {"action": "read_bytes", "addr": "step0.result.matches.0.addr"}},
        ],
        bindings={"fallback": "0x401000"},
    )
    assert result["ok"] is True, result
    assert host.calls[1][1]["addr"] == "0x401000"
    assert host.calls[2][1]["addr"] == "0x401000"


def test_batch_unresolved_binding_errors():
    host, result = _chained_batch(
        [
            {"name": "code", "arguments": {"action": "disasm", "addr": "$missing"}},
        ],
        bindings={"present": "0x1000"},
    )
    assert result["summary"]["errors"] == 1
    err = result["results"][0]["result"]
    assert err.get("code") == MCPError.INVALID_ARGS
    assert "unresolved binding reference" in err.get("message", "")


def test_batch_non_dict_bindings_errors():
    host = _FakeBatchHost()
    result = host._handle_batch(
        {
            "calls": [{"name": "idb", "arguments": {"action": "meta"}}],
            "bindings": "not-a-map",
        }
    )
    assert result.get("error") is True
    assert result.get("code") == MCPError.INVALID_ARGS


# ---------------------------------------------------------------------------
# fast path interaction + r2 exclusion
# ---------------------------------------------------------------------------


def test_chained_batch_skips_single_rpc_fast_path():
    """A chained batch must not take the list-shaped RPC fast path: its results
    accumulate step-by-step so later steps can bind from earlier ones."""
    host, _ = _chained_batch(
        [
            {"name": "search", "arguments": {"action": "find", "query": "main"}},
            {"name": "code", "arguments": {"action": "disasm", "addr": "step0.result.matches.0.addr"}},
        ]
    )
    assert host.fast_path_attempts == 0


def test_plain_batch_still_tries_fast_path():
    host = _FakeBatchHost()
    host._handle_batch(
        {
            "calls": [
                {"name": "search", "arguments": {"action": "find", "query": "main"}},
            ],
            "continue_on_error": True,
        }
    )
    assert host.fast_path_attempts == 1
    assert len(host.calls) == 1


def test_r2_excluded_from_batch_fast_path():
    """Host-side r2 calls must take the per-call loop (the engine runs as a
    subprocess per call, never in a list-shaped RPC)."""
    assert "r2" in _BATCH_FAST_PATH_EXCLUDED_TOOLS


# ---------------------------------------------------------------------------
# opaque raw-blob / RISC-V firmware scenario
# ---------------------------------------------------------------------------


def test_riscv_raw_blob_chains_meta_to_read_to_disasm():
    """Headerless RISC-V firmware blob at a low base: step1 derives the blob
    offset from step0's meta (flat ref on an output_key), step2 disassembles
    the window step1 read (flat ref on the default step key) — the
    find→deref→follow pipeline on an opaque .bin."""
    host, result = _chained_batch(
        [
            {"name": "idb", "arguments": {"action": "meta"}, "output_key": "meta"},
            {"name": "data", "arguments": {"action": "read_bytes", "addr": "meta_image_base", "size": 16}},
            {"name": "code", "arguments": {"action": "disasm", "addr": "step1_addr"}},
        ]
    )
    assert result["ok"] is True, result
    assert host.calls[0][1] == {"action": "meta"}
    assert host.calls[1][1]["addr"] == "0x1000"
    assert host.calls[2][1]["addr"] == "0x1000"
    assert result["summary"]["ok"] == 3


# ---------------------------------------------------------------------------
# execute_plan runs through the same shared step executor
# ---------------------------------------------------------------------------


def test_execute_plan_chains_step_results_and_bindings():
    host = _FakeBatchHost()
    result = host._handle_workflow(
        {
            "action": "execute_plan",
            "planned_calls": [
                {"name": "search", "arguments": {"action": "find", "query": "main"}, "output_key": "found"},
                {"name": "code", "arguments": {"action": "disasm", "addr": "found.result.matches.0.addr"}},
                {"name": "search", "arguments": {"action": "find", "query": "$query"}},
            ],
            "continue_on_error": True,
            "bindings": {"query": "http url"},
        }
    )
    assert result.get("ok") is True, result
    calls = result["calls"]
    assert calls[0]["arguments"] == {"action": "find", "query": "main"}
    # The chained + bound arguments appear in calls_out (what actually ran).
    assert calls[1]["arguments"]["addr"] == "0x401000"
    assert calls[2]["arguments"]["query"] == "http url"
    # step_results mirrors the resolved args too.
    assert result["step_results"][1]["args"]["addr"] == "0x401000"
    assert result["summary"]["completed_steps"] == 3
    assert result["summary"]["error_steps"] == 0


def test_execute_plan_unresolved_ref_errors_with_envelope():
    host = _FakeBatchHost()
    result = host._handle_workflow(
        {
            "action": "execute_plan",
            "planned_calls": [
                {"name": "search", "arguments": {"action": "find", "query": "main"}},
                {"name": "code", "arguments": {"action": "disasm", "addr": "step0.result.missing"}},
            ],
            "continue_on_error": True,
        }
    )
    step = result["calls"][1]
    assert step["result"].get("error") is True
    assert step["result"].get("code") == MCPError.INVALID_ARGS
    assert result["summary"]["error_steps"] == 1
    # The failing step never reached _execute_tool.
    assert [t for t, _ in host.calls] == ["search"]


def test_execute_plan_delegates_unknown_tool_to_execute():
    """execute_plan preserves its own tool-admission semantics: a plan step
    whose tool name is not in TOOLS still reaches _execute_tool (dispatch
    validates it), matching the pre-chaining loop."""
    host = _FakeBatchHost(execute=lambda tool, args: {"ok": True, "tool": tool})
    result = host._handle_workflow(
        {
            "action": "execute_plan",
            "planned_calls": [{"name": "not_a_tool", "arguments": {"action": "x"}}],
            "continue_on_error": True,
        }
    )
    assert result["summary"]["completed_steps"] == 1
    assert host.calls == [("not_a_tool", {"action": "x"})]


def test_execute_plan_unresolved_binding_is_a_step_error():
    """execute_plan surfaces a missing binding as a per-step INVALID_ARGS
    envelope (top-level ok stays true; the step is reported in error_steps and
    never reached _execute_tool)."""
    host = _FakeBatchHost()
    result = host._handle_workflow(
        {
            "action": "execute_plan",
            "planned_calls": [{"name": "code", "arguments": {"action": "disasm", "addr": "$missing"}}],
            "continue_on_error": True,
            "bindings": {},
        }
    )
    assert result.get("ok") is True, result
    step = result["calls"][0]
    assert step["result"].get("error") is True
    assert step["result"].get("code") == MCPError.INVALID_ARGS
    assert "unresolved binding reference" in step["result"].get("message", "")
    assert result["summary"]["error_steps"] == 1
    assert host.calls == []
