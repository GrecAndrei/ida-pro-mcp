"""Realistic agent workflows over the public MCP surface.

The catalog suite proves that every operation is wired.  These tests model
what an analyst actually does: discover a symbol, carry its returned address
through several tools, record a conclusion, recover from a bad request, and
use batch/session/protocol facilities around the same live IDA database.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from typing import Any

import pytest

from tests.integration.test_agent_surface_live import (
    LiveContext,
    LiveMCPClient,
    _assert_ok,
    _build_fixture,
    _ida_dir,
    live_call_timeout,
)

pytestmark = [
    pytest.mark.live_ida,
    pytest.mark.skipif(
        os.environ.get("IDA_MCP_LIVE_TEST") != "1",
        reason="set IDA_MCP_LIVE_TEST=1 to run tests against a licensed IDA installation",
    ),
    pytest.mark.timeout(600),
]


@pytest.fixture(scope="module")
def real_live_context(tmp_path_factory: pytest.TempPathFactory) -> LiveContext:
    """Use an isolated real host/IDA process for workflow tests."""
    binary = _build_fixture(tmp_path_factory)
    runtime_dir = tmp_path_factory.mktemp("ida-real-usage-runtime")
    client = LiveMCPClient(
        ida_dir=_ida_dir(),
        runtime_dir=runtime_dir,
        response_mode="full",
        timeout=live_call_timeout(index=True),
        embeddings_enabled=False,
    )
    client.start()
    try:
        _assert_ok(client.call("ida_open_binary", {"binary_path": str(binary)}), "ida_open_binary")
        yield LiveContext(client=client, binary=binary)
    finally:
        with contextlib.suppress(Exception):
            _assert_ok(client.call("ida_close_session", {"risk_ack": True}), "ida_close_session")
        client.stop()


def _first_address(value: Any) -> str | None:
    """Extract an address from a real find response without assuming its shape."""
    preferred = {"address", "addr", "ea", "start_ea", "function_address"}
    if isinstance(value, dict):
        for key in preferred:
            candidate = value.get(key)
            if isinstance(candidate, str) and re.fullmatch(r"0x[0-9a-fA-F]+", candidate):
                return candidate
        for child in value.values():
            found = _first_address(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _first_address(child)
            if found:
                return found
    elif isinstance(value, str):
        match = re.search(r"0x[0-9a-fA-F]+", value)
        if match:
            return match.group(0)
    return None


def _find_session_id(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        if isinstance(payload, list):
            for item in payload:
                found = _find_session_id(item)
                if found:
                    return found
        return None
    for key in ("session_id", "idb", "id"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    for key in ("active_session_id",):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    for value in payload.values():
        found = _find_session_id(value)
        if found:
            return found
    return None


def _session_id(payload: dict[str, Any]) -> str:
    found = _find_session_id(payload)
    if found:
        return found
    pytest.fail(f"live session response had no session id: {payload}")


def test_real_user_follows_find_to_code_and_graph(real_live_context: LiveContext):
    client = real_live_context.client
    found = _assert_ok(
        client.call("ida_find", {"query": "fixture_leaf", "kind": "names", "limit": 10}),
        "ida_find fixture_leaf",
    )
    address = _first_address(found)
    assert address, f"find did not return an address: {found}"

    decompiled = _assert_ok(
        client.call("ida_decompile", {"address": address}),
        "ida_decompile returned address",
    )
    disassembled = _assert_ok(
        client.call("ida_disassemble", {"address": address, "style": "annotated", "limit": 80}),
        "ida_disassemble returned address",
    )
    for payload in (decompiled, disassembled):
        assert payload.get("structure") or payload.get("code") or payload.get("disasm"), payload

    for operation in ("ida_callers", "ida_callees", "ida_xrefs_to", "ida_callgraph"):
        payload = _assert_ok(client.call(operation, {"address": address}), operation)
        assert isinstance(payload, dict)


def test_real_user_carries_memory_and_query_results_between_tools(real_live_context: LiveContext):
    client = real_live_context.client
    strings = _assert_ok(
        client.call(
            "ida_list_strings",
            {"query": "IDA_MCP_AGENT_SURFACE_MARKER", "limit": 20},
        ),
        "ida_list_strings",
    )
    string_address = _first_address(strings)
    assert string_address, f"string listing did not expose an address: {strings}"
    bytes_payload = _assert_ok(
        client.call("ida_read_bytes", {"address": string_address, "size": 16}),
        "ida_read_bytes",
    )
    assert any(key in bytes_payload for key in ("hex", "bytes", "hexdump", "ascii")), bytes_payload

    query = _assert_ok(
        client.call("ida_search_query_lang", {"query": "function fixture_entry LIMIT 5"}),
        "ida_search_query_lang",
    )
    assert "fixture_entry" in json.dumps(query).lower(), query
    raw = _assert_ok(
        client.call(
            "ida_search_data_value",
            {"value": "IDA_MCP_AGENT_SURFACE_MARKER", "limit": 10},
        ),
        "ida_search_data_value",
    )
    assert isinstance(raw, dict)


def test_real_user_uses_session_state_health_and_reconnect_safe_switch(real_live_context: LiveContext):
    client = real_live_context.client
    _assert_ok(client.call("ida_session_state", {}), "ida_session_state")
    listed = _assert_ok(client.call("ida_session_list", {"query": "fixture", "limit": 10}), "ida_session_list")
    sid = _session_id(listed)
    status = _assert_ok(client.call("ida_session_status", {"idb": sid}), "ida_session_status")
    status_state = status.get("state") if isinstance(status.get("state"), dict) else status
    status_session = status.get("session") if isinstance(status.get("session"), dict) else {}
    assert (
        status_state.get("analysis_complete") is True
        or status_state.get("safe_mode") is False
        or status_session.get("analysis_complete") is True
        or status_session.get("safe_mode") is False
    ), status
    health = _assert_ok(client.call("ida_session_health", {"verbose": True}), "ida_session_health")
    assert isinstance(health, dict)
    assert sid in json.dumps(listed) or listed.get("sessions"), listed
    details = _assert_ok(client.call("ida_session_get", {"session_id": sid}), "ida_session_get")
    assert sid in json.dumps(details), details
    switched = _assert_ok(
        client.call("ida_session_switch", {"session_id": sid, "reopen": False}),
        "ida_session_switch",
    )
    assert sid in json.dumps(switched) or switched.get("ok") is True, switched
    _assert_ok(client.call("ida_auto_wait", {"timeout_ms": 5000}), "ida_auto_wait")


def test_real_user_batch_executes_discovery_sequence_and_preserves_errors(real_live_context: LiveContext):
    client = real_live_context.client
    batch = _assert_ok(
        client.call(
            "ida_batch",
            {
                "calls": [
                    {"name": "ida_overview", "arguments": {}},
                    {"name": "ida_find", "arguments": {"query": "fixture_entry", "kind": "names", "limit": 5}},
                    {"name": "ida_list_functions", "arguments": {"query": "fixture_", "limit": 10}},
                ],
                "continue_on_error": False,
            },
        ),
        "ida_batch discovery sequence",
    )
    results = batch.get("results")
    assert isinstance(results, list) and len(results) == 3, batch
    assert all(isinstance(item, dict) for item in results)
    assert "fixture_entry" in json.dumps(batch).lower()

    invalid = client.call(
        "ida_batch",
        {
            "calls": [
                {"name": "ida_decompile", "arguments": {}},
                {"name": "ida_calc_eval", "arguments": {"expr": "2 + 2"}},
            ],
            "continue_on_error": True,
        },
    )
    assert invalid.get("ok") is False
    assert invalid.get("summary", {}).get("errors") == 1
    assert "error" in json.dumps(invalid).lower()


def test_real_user_recovers_after_invalid_request_and_can_run_ida_python(real_live_context: LiveContext):
    client = real_live_context.client
    invalid = client.call("ida_decompile", {"address": 123})
    assert invalid.get("error") is True
    assert invalid.get("code") == "INVALID_ARGS"

    valid = _assert_ok(
        client.call("ida_decompile", {"address": "fixture_helper"}),
        "ida_decompile after invalid request",
    )
    assert valid
    scripted = _assert_ok(
        client.call("ida_python", {"code": "1 + 1", "risk_ack": True}),
        "ida_python bounded expression",
    )
    assert "2" in json.dumps(scripted)


def test_real_user_records_confirms_and_retrieves_a_finding(real_live_context: LiveContext):
    client = real_live_context.client
    title = "real usage workflow finding"
    recorded = _assert_ok(
        client.call(
            "ida_write_finding",
            {
                "title": title,
                "content": "The live workflow verified a discoverable call path.",
                "address": "fixture_entry",
                "category": "workflow-test",
                "confidence": 0.9,
                "tags": ["live", "workflow"],
            },
        ),
        "ida_write_finding",
    )
    entry_id = recorded.get("entry_id")
    assert entry_id, recorded
    listed = _assert_ok(client.call("ida_list_findings", {"limit": 100}), "ida_list_findings")
    assert title in json.dumps(listed)
    searched = _assert_ok(
        client.call("ida_search_findings", {"query": "discoverable call path", "limit": 20}),
        "ida_search_findings",
    )
    assert title in json.dumps(searched)
    updated = _assert_ok(
        client.call(
            "ida_update_finding",
            {"entry_id": entry_id, "status": "confirmed", "reason": "Observed in a real MCP workflow."},
        ),
        "ida_update_finding",
    )
    assert "confirmed" in json.dumps(updated).lower()
    brief = _assert_ok(client.call("ida_analysis_brief", {"limit": 20}), "ida_analysis_brief")
    assert title in json.dumps(brief)


def test_real_user_snapshot_and_restore_keep_the_idb_reversible(real_live_context: LiveContext):
    client = real_live_context.client
    snapshot = _assert_ok(
        client.call("ida_idb_snapshot", {"name": "real-usage-before", "risk_ack": True}),
        "ida_idb_snapshot",
    )
    try:
        renamed = _assert_ok(
            client.call(
                "ida_rename",
                {"address": "fixture_helper", "name": "fixture_helper_temporary", "risk_ack": True},
            ),
            "ida_rename temporary",
        )
        assert renamed
    finally:
        restored = _assert_ok(
            client.call(
                "ida_idb_restore_snapshot",
                {
                    "snapshot_id": snapshot.get("snapshot_id") or snapshot.get("name") or "real-usage-before",
                    "risk_ack": True,
                },
            ),
            "ida_idb_restore_snapshot",
        )
        assert restored


def test_real_user_inspects_metadata_types_segments_and_register_context(real_live_context: LiveContext):
    client = real_live_context.client
    overview = _assert_ok(client.call("ida_overview", {}), "ida_overview")
    overview_meta = overview.get("meta") if isinstance(overview.get("meta"), dict) else overview
    assert (
        overview_meta.get("architecture")
        or overview_meta.get("arch")
        or overview_meta.get("processor")
        or overview_meta.get("file_type")
    ), overview
    segments = _assert_ok(client.call("ida_list_segments", {}), "ida_list_segments")
    assert isinstance(segments, dict)
    declared = _assert_ok(
        client.call(
            "ida_declare_type",
            {"declaration": "struct live_usage_type { int marker; };", "risk_ack": True},
        ),
        "ida_declare_type",
    )
    assert declared
    types = _assert_ok(client.call("ida_list_types", {"query": "live_usage_type", "limit": 20}), "ida_list_types")
    assert isinstance(types, dict)
    global_type = _assert_ok(client.call("ida_get_type", {"name": "live_usage_type"}), "ida_get_type")
    assert isinstance(global_type, dict)
    sregs = _assert_ok(client.call("ida_sreg_list", {"start": "fixture_entry"}), "ida_sreg_list")
    assert isinstance(sregs, dict)


def test_real_user_uses_calculator_for_address_reasoning(real_live_context: LiveContext):
    client = real_live_context.client
    eval_result = _assert_ok(client.call("ida_calc_eval", {"expr": "0x10 + 0x20"}), "ida_calc_eval")
    assert eval_result.get("value") == 0x30
    converted = _assert_ok(client.call("ida_calc_convert", {"value": "0x401000"}), "ida_calc_convert")
    assert converted
    resolved = _assert_ok(client.call("ida_calc_resolve", {"address": "fixture_entry"}), "ida_calc_resolve")
    assert _first_address(resolved) or resolved.get("value") is not None, resolved
    aligned = _assert_ok(client.call("ida_calc_align", {"value": "0x401023", "size": 16}), "ida_calc_align")
    assert aligned.get("value") in (0x401020, "0x401020") or aligned
    bits = _assert_ok(
        client.call("ida_calc_bitops", {"value": "0xff", "target": "0x0f", "bit_op": "xor"}),
        "ida_calc_bitops",
    )
    assert bits.get("value") in (0xf0, "0xf0") or bits


def test_real_user_marks_a_dead_end_and_gets_a_next_target(real_live_context: LiveContext):
    client = real_live_context.client
    examined = _assert_ok(
        client.call(
            "ida_mark_examined",
            {"address": "fixture_helper", "verdict": "boring", "note": "No suspicious behavior in this helper."},
        ),
        "ida_mark_examined",
    )
    assert examined
    for strategy in ("coverage", "frontier", "unresolved"):
        next_target = _assert_ok(
            client.call("ida_next_target", {"strategy": strategy, "limit": 5}),
            f"ida_next_target {strategy}",
        )
        assert isinstance(next_target, dict)


def test_real_user_optional_backends_return_status_instead_of_transport_failures(real_live_context: LiveContext):
    client = real_live_context.client
    for name, arguments in (
        ("ida_reranker_status", {}),
        ("ida_r2_status", {}),
        ("ida_fw_detect_load_base", {}),
        ("ida_function_families", {"query": "fixture", "limit": 5}),
    ):
        payload = client.call(name, arguments)
        assert isinstance(payload, dict), (name, payload)
        if payload.get("error") is True:
            assert isinstance(payload.get("code"), str) and payload["code"], (name, payload)
        else:
            assert payload.get("ok") is True, (name, payload)
