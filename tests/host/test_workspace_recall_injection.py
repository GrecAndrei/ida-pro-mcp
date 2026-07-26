"""Recall must reach the model without the model asking for it.

The previous version wrote findings that only came back if the LLM chose to
call a search tool, which it rarely did. These tests pin the automatic path:
code shown to the model anchors the claims about it, and prior knowledge is
attached to the response.

They call the real ``ServerResponseMixin`` methods against a real store, so a
regression that unwires the injection fails here rather than degrading
silently into a workspace nobody reads.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_pro_mcp.host.server.server_response import ServerResponseMixin  # noqa: E402
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin  # noqa: E402
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore  # noqa: E402


class _Host(ServerResponseMixin, ServerRuntimeMixin):
    """Just enough host to exercise the response hooks against a real store.

    ``ServerRuntimeMixin`` is real, not a stub: ``_prepare_response_payload``
    calls into it, and the end-to-end test below needs the production method
    resolution order so unwiring the injection actually fails a test.
    """

    enable_response_enrichment = False
    current_session = None
    assembler = None
    _pointer_note_min_signal = 1.0
    _pointer_note_pending_signal = 0.0
    _pointer_note_last_shown_at = 0.0
    _pointer_note_min_interval = 0.0

    def __init__(self, store):
        self._store = store

    def _get_blackboard_store(self):
        return self._store


@pytest.fixture()
def host_and_store(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    return _Host(store), store


def test_decompiling_an_address_attaches_what_is_already_known(host_and_store):
    host, store = host_and_store
    store.upsert_finding(
        "Parses a length prefix", addr="0x401000", status="confirmed", confidence=0.8
    )
    store.upsert_finding("Is the length bounded?", addr="0x401000", kind="question")

    payload = {"pseudocode": "int f() { return 1; }"}
    host._inject_workspace_recall("code", payload, {"addrs": "0x401000"})

    recalled = "\n".join(payload["_recall"])
    assert "Parses a length prefix" in recalled
    assert "Is the length bounded?" in recalled


def test_search_results_are_marked_when_they_were_already_dismissed(host_and_store):
    host, store = host_and_store
    store.record_examination("0x401a20", verdict="boring", note="CRT helper.")

    payload = {"matches": [{"addr": "0x401a20"}, {"addr": "0x401b00"}]}
    host._inject_workspace_recall("search", payload, {"query": "str"})

    assert payload["_already_examined"] == {"0x401a20": "boring"}


def test_decompiling_changed_code_marks_prior_claims_stale_in_the_response(host_and_store):
    host, store = host_and_store
    call_args = {"addrs": "0x401000"}

    first = {"pseudocode": "int f() { return recv(s, buf, 64); }"}
    host._capture_code_anchor("code", "decompile", call_args, first)
    entry_id = store.upsert_finding(
        "Reads a fixed 64-byte frame", addr="0x401000", status="confirmed"
    )["entry_id"]

    second = {"pseudocode": "int f() { return recv(s, buf, n); }"}
    host._capture_code_anchor("code", "decompile", call_args, second)

    assert "were marked stale" in second["_stale"]
    assert store.read(entry_id)["stale"] == 1

    # And the staleness reaches the model on the same response.
    host._inject_workspace_recall("code", second, call_args)
    assert "stale" in "\n".join(second["_recall"])


def test_decompiling_unchanged_code_says_nothing(host_and_store):
    host, store = host_and_store
    call_args = {"addrs": "0x401000"}
    for _ in range(2):
        payload = {"pseudocode": "int f() { return 1; }"}
        host._capture_code_anchor("code", "decompile", call_args, payload)
    assert "_stale" not in payload


def test_disassembly_anchors_separately_from_decompilation(host_and_store):
    """The two views of one function must not invalidate each other."""
    host, store = host_and_store
    call_args = {"addrs": "0x401000"}

    host._capture_code_anchor("code", "decompile", call_args, {"pseudocode": "int f(){}"})
    store.upsert_finding("Claim from pseudocode", addr="0x401000")
    host._capture_code_anchor("code", "disasm", call_args, {"disassembly": "push rbp"})

    assert store.list(addr="0x401000")[0]["stale"] == 0


def test_workspace_tools_do_not_recall_into_themselves(host_and_store):
    host, store = host_and_store
    store.upsert_finding("Something", addr="0x401000")

    payload = {"entries": [{"addr": "0x401000"}]}
    host._inject_workspace_recall("blackboard", payload, {"addr": "0x401000"})

    assert "_recall" not in payload
    assert "_already_examined" not in payload


def test_a_recall_failure_is_reported_rather_than_swallowed(host_and_store):
    """A silent no-op is indistinguishable from never having been wired up."""
    host, _ = host_and_store

    class _Broken:
        def recall_lines(self, *a, **k):
            raise RuntimeError("database is locked")

        def examination(self, *a, **k):
            return None

    host._store = _Broken()
    payload = {}
    host._inject_workspace_recall("code", payload, {"addrs": "0x401000"})

    assert payload["_recall_error"] == "RuntimeError: database is locked"


def test_no_store_means_no_annotations_and_no_error(host_and_store):
    host, _ = host_and_store
    host._store = None
    payload = {"pseudocode": "int f(){}"}

    host._capture_code_anchor("code", "decompile", {"addrs": "0x401000"}, payload)
    host._inject_workspace_recall("code", payload, {"addrs": "0x401000"})

    assert payload == {"pseudocode": "int f(){}"}


def test_the_real_response_pipeline_injects_recall(host_and_store):
    """End-to-end through ``_prepare_response_payload``.

    The other tests call the hooks directly, so they would still pass if the
    calls were removed from the dispatch path. This one would not.
    """
    host, store = host_and_store
    store.upsert_finding("Parses a length prefix", addr="0x401000", status="confirmed")
    store.record_examination("0x401b00", verdict="boring", note="Thunk.")

    result = host._prepare_response_payload(
        {"pseudocode": "int f() { return 1; }", "xrefs": [{"addr": "0x401b00"}]},
        {"mode": "compact"},
        tool_name="code",
        call_args={"action": "decompile", "addrs": "0x401000"},
    )

    assert result["_recall"] == ["finding/confirmed: Parses a length prefix — @ 0x401000"]
    assert result["_already_examined"] == {"0x401b00": "boring"}
    # The anchor was captured on the way through, so a later change can
    # invalidate anything written against this body.
    assert store.current_anchor("0x401000")["kind"] == "decompile"


@pytest.mark.parametrize(
    ("call_args", "expected"),
    [
        ({"addrs": "0x401000"}, "0x401000"),
        ({"addr": "0x401000"}, "0x401000"),
        ({"address": "0x401000"}, "0x401000"),
        ({"addrs": ["0x401000", "0x402000"]}, "0x401000"),
        ({"addrs": "0x401000,0x402000"}, "0x401000"),
        ({}, ""),
        ("not-a-dict", ""),
    ],
)
def test_the_subject_address_is_found_whatever_the_spelling(call_args, expected):
    assert ServerResponseMixin._first_addr(call_args) == expected
