"""Regression tests for bb05: canonical blackboard response shapers.

Covers the pure ``blackboard_shapes`` module that the host handler composes
into its keep=true MCP responses. Pure-function tests: no live IDA, no server
object, no store — every input is a dict built by a _FakeIda-style fake.

Pinned contracts:
  - list/search return ``{ok, entries, count, summary}`` / ``{ok, query,
    entries, count, summary}`` — search never ``results``.
  - read returns ``{ok, entry, summary}``.
  - write returns ``{ok, entry_id, created, action, gravity, phase}`` with a
    bounded gravity snapshot that fires on create only.
  - next_target/frontier targets carry BOTH ``address`` and ``addr`` keys.
  - coverage returns ``{ok, coverage_pct, total_entries, analyzed, unvisited,
    note}`` with an honest note.
  - crawler_status returns ``{ok, running, pending_proposals,
    addresses_visited, proposals}`` — no ``proposals_pending`` alias.
  - export renders ``ida-findings-v1`` snapshots to JSON and Markdown,
    dropping fingerprint/vector/norm and exposing ``entry_id``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ida_pro_mcp.host.server.blackboard_shapes import (
    COVERAGE_NOTE,
    GRAVITY_MAX_ITEMS,
    STRATEGIES,
    build_export_snapshot,
    clip,
    coverage_response,
    crawler_status_response,
    ensure_dual_keys,
    entry_brief,
    entry_collection_summary,
    frontier_collection_summary,
    frontier_response,
    gravity_snapshot,
    list_response,
    next_target_response,
    proposal_collection_summary,
    read_response,
    search_response,
    snapshot_to_json,
    snapshot_to_markdown,
    strategy_note,
    strip_export_fields,
    target_collection_summary,
    write_response,
)


def _fake_entry(
    *,
    entry_id: str,
    title: str,
    category: str = "parsing",
    addr: str = "0x401000",
    kind: str = "finding",
    status: str = "open",
    confidence: float = 0.5,
    priority: float = 0.5,
    resolved: int = 0,
    contradicted: int = 0,
    stale: int = 0,
    source_type: str = "manual",
    tags: list[str] | None = None,
    content: str = "",
    evidence: list[dict] | None = None,
    **extra: object,
) -> dict:
    """A store-shaped row dict, as ``BlackboardStore._row_to_dict`` produces."""
    return {
        "id": entry_id,
        "entry_id": entry_id,
        "title": title,
        "category": category,
        "addr": addr,
        "kind": kind,
        "status": status,
        "confidence": confidence,
        "priority": priority,
        "resolved": resolved,
        "contradicted": contradicted,
        "stale": stale,
        "source_type": source_type,
        "tags": tags or [],
        "evidence": evidence or [],
        "conflicts_with": [],
        "content": content,
        "updated_at": 1750000000.0,
        **extra,
    }


# ---------------------------------------------------------------------------
# list / search / read
# ---------------------------------------------------------------------------


def test_list_response_shape():
    entries = [_fake_entry(entry_id="a1", title="recv handler"), _fake_entry(entry_id="a2", title="question")]
    out = list_response(entries)
    assert out == {
        "ok": True,
        "entries": entries,
        "count": 2,
        "summary": entry_collection_summary(entries),
    }
    assert out["summary"]["count"] == 2
    assert out["summary"]["briefs"][0]["entry_id"] == "a1"


def test_search_response_uses_entries_never_results():
    entries = [_fake_entry(entry_id="b1", title="frame length")]
    out = search_response("frame length", entries)
    assert out["ok"] is True
    assert out["query"] == "frame length"
    assert out["entries"] == entries
    assert out["count"] == 1
    assert "summary" in out
    # The legacy IDA-side dispatcher returned ``results``; the host shape is
    # ``entries`` and must not leak the old key.
    assert "results" not in out


def test_read_response_shape():
    entry = _fake_entry(entry_id="c1", title="parse_frame", status="confirmed")
    out = read_response(entry)
    assert out["ok"] is True
    assert out["entry"] == entry
    assert out["summary"]["entry_id"] == "c1"
    assert out["summary"]["status"] == "confirmed"


# ---------------------------------------------------------------------------
# write + bounded gravity snapshot
# ---------------------------------------------------------------------------


def test_write_response_shape_and_gravity_fires_on_create_only():
    created = write_response(
        {"entry_id": "d1", "created": True, "version": 1},
        action="write",
        gravity=gravity_snapshot([{"type": "call", "value": "recv"}], note="2 neighbours", entry_id="d1"),
        phase={"phase": "scout", "auto_transition": True},
    )
    assert created == {
        "ok": True,
        "entry_id": "d1",
        "created": True,
        "action": "write",
        "gravity": {"items": [{"type": "call", "value": "recv"}], "note": "2 neighbours", "entry_id": "d1"},
        "phase": {"phase": "scout", "auto_transition": True},
    }

    merged = write_response({"entry_id": "d1", "created": False, "version": 2}, gravity={"items": []})
    assert merged["created"] is False
    # Gravity is pinned to create only: a merge must never fire it.
    assert merged["gravity"] is None


def test_gravity_snapshot_bounds_items():
    items = [{"n": i} for i in range(50)]
    snap = gravity_snapshot(items, note="lots", entry_id="e1")
    assert len(snap["items"]) == GRAVITY_MAX_ITEMS
    assert snap["items"] == items[:GRAVITY_MAX_ITEMS]
    assert snap["note"] == "lots"
    assert snap["entry_id"] == "e1"
    # Non-list input degrades to an empty bounded snapshot.
    assert gravity_snapshot(None) == {"items": [], "note": "", "entry_id": ""}


# ---------------------------------------------------------------------------
# next_target / frontier: dual address+addr keys
# ---------------------------------------------------------------------------


def test_next_target_targets_carry_both_address_and_addr_keys():
    targets = [
        {"address": "0x401000", "title": "recv handler", "reason": "open question", "confidence": 0.4},
        {"addr": "0x402000", "title": "parse_frame", "reason": "open question", "confidence": 0.5},
    ]
    out = next_target_response("unresolved", targets, query="recv")
    assert out["ok"] is True
    assert out["strategy"] == "unresolved"
    assert out["count"] == 2
    assert "strategies" in out
    assert list(out["strategies"]) == list(STRATEGIES)
    assert out["note"]  # strategy note present
    assert out["query_ranking"] == "keyword overlap; candidates are reordered, never dropped"
    # Both spellings survive on every target, including the reorder.
    for target in out["targets"]:
        assert target["address"] == target["addr"]
        assert target["address"] is not None
    assert out["summary"]["count"] == 2
    assert out["summary"]["best_addr"] is not None


def test_next_target_preserves_input_never_mutates_it():
    original = [{"address": "0x401000", "title": "handler", "reason": "x"}]
    snapshot = dict(original[0])
    next_target_response("unresolved", original)
    assert original[0] == snapshot, "shaper must not mutate caller input"
    assert "addr" not in original[0]


def test_next_target_empty_note_signals_positive_signal():
    out = next_target_response("unresolved", [])
    assert out["count"] == 0
    assert out["targets"] == []
    assert "Nothing is open" in out["note"]
    assert out["summary"] == {"count": 0, "briefs": []}


def test_frontier_response_is_a_list_never_a_string():
    results = [
        {"address": "0x403000", "name": "sub_403000", "score": 0.9},
        {"addr": "0x404000", "title": "sub_404000"},
    ]
    out = frontier_response(results)
    assert out["ok"] is True
    assert isinstance(out["frontier"], list)
    assert out["count"] == 2
    assert out["summary"]["count"] == 2
    for row in out["frontier"]:
        assert row["address"] == row["addr"]
    assert out["summary"]["briefs"][0]["addr"] == "0x403000"


def test_frontier_empty_returns_empty_list():
    out = frontier_response([])
    assert out == {"ok": True, "frontier": [], "count": 0, "summary": {"count": 0, "briefs": []}}


def test_ensure_dual_keys_adds_missing_spelling_and_keeps_truthy_value():
    normalized = ensure_dual_keys(
        [{"address": "0x401000"}, {"addr": "0x402000"}, {"address": "0x403000", "addr": "0x403000"}]
    )
    assert normalized == [
        {"address": "0x401000", "addr": "0x401000"},
        {"addr": "0x402000", "address": "0x402000"},
        {"address": "0x403000", "addr": "0x403000"},
    ]


# ---------------------------------------------------------------------------
# coverage
# ---------------------------------------------------------------------------


def test_coverage_response_shape_and_honesty_note():
    out = coverage_response(analyzed=1, total=2)
    assert out["ok"] is True
    assert out["coverage_pct"] == 50.0
    assert out["total_entries"] == 2
    assert out["analyzed"] == 1
    assert out["unvisited"] == 1
    assert out["note"] == COVERAGE_NOTE
    # The note must be honest about what the metric does not measure.
    assert "not that every function" in out["note"]


def test_coverage_empty_workspace_is_zero_not_division_by_zero():
    out = coverage_response(analyzed=0, total=0)
    assert out["coverage_pct"] == 0.0
    assert out["total_entries"] == 0
    assert out["unvisited"] == 0


# ---------------------------------------------------------------------------
# crawler_status
# ---------------------------------------------------------------------------


def test_crawler_status_shape_and_no_proposals_pending_alias():
    proposals = [{"proposal_id": "p1", "addr": "0x401000", "title": "quick", "confidence": 0.65}]
    out = crawler_status_response(
        running=True,
        pending_proposals=1,
        addresses_visited=9,
        proposals=proposals,
    )
    assert out == {
        "ok": True,
        "running": True,
        "pending_proposals": 1,
        "addresses_visited": 9,
        "proposals": proposals,
    }
    # The legacy alias key is deliberately gone.
    assert "proposals_pending" not in out


def test_proposal_collection_summary_shape():
    proposals = [{"proposal_id": "p1", "addr": "0x401000", "title": "quick", "confidence": 0.65}]
    summary = proposal_collection_summary(proposals)
    assert summary["count"] == 1
    assert summary["briefs"][0]["proposal_id"] == "p1"
    assert summary["briefs"][0]["addr"] == "0x401000"


# ---------------------------------------------------------------------------
# export: findings-v1 JSON + Markdown
# ---------------------------------------------------------------------------


def _snapshot_fixture_entries() -> list[dict]:
    return [
        _fake_entry(
            entry_id="f1",
            title="recv handler parses framed input",
            content="Length is read before dispatch.",
            addr="0x401000",
            kind="finding",
            status="confirmed",
            confidence=0.8,
            priority=0.7,
            tags=["parsing", "recv"],
            evidence=[{"type": "call", "value": "recv", "address": "0x401024", "weight": 1.0}],
            fingerprint="deadbeef",
            vector=b"\x00\x01",
            norm=0.9,
        ),
        _fake_entry(
            entry_id="f2",
            title="Is the frame length bounded?",
            addr="0x401000",
            kind="question",
            status="open",
            confidence=0.4,
            priority=0.9,
        ),
        _fake_entry(
            entry_id="f3",
            title="Rejected dead end",
            addr="0x403000",
            kind="finding",
            status="rejected",
            confidence=0.2,
            priority=0.1,
        ),
    ]


def test_export_json_contract_drops_internal_fields():
    snapshot = build_export_snapshot(
        _snapshot_fixture_entries(),
        stats={"total_entries": 3, "resolved": 0, "contradicted": 1, "stale": 0},
        exported_at="2026-08-09T00:00:00+00:00",
    )
    assert snapshot["format"] == "ida-findings-v1"
    assert snapshot["exported_at"] == "2026-08-09T00:00:00+00:00"
    assert snapshot["stats"] == {"total_entries": 3, "resolved": 0, "contradicted": 1, "stale": 0}
    assert len(snapshot["entries"]) == 3

    confirmed = snapshot["entries"][0]
    assert confirmed["entry_id"] == "f1"
    assert confirmed["kind"] == "finding"
    assert confirmed["status"] == "confirmed"
    assert confirmed["addr"] == "0x401000"
    assert confirmed["confidence"] == 0.8
    assert confirmed["tags"] == ["parsing", "recv"]
    assert confirmed["evidence"] == [{"type": "call", "value": "recv", "address": "0x401024", "weight": 1.0}]
    # Internal storage fields are dropped from the public record.
    assert "fingerprint" not in confirmed
    assert "vector" not in confirmed
    assert "norm" not in confirmed

    text = snapshot_to_json(snapshot)
    assert isinstance(text, str)
    assert text.startswith("{")


def test_export_default_exported_at_is_utc_iso():
    snapshot = build_export_snapshot([])
    exported_at = snapshot["exported_at"]
    parsed = datetime.fromisoformat(exported_at)
    assert parsed.tzinfo is not None
    assert parsed.tzinfo.utcoffset(None) is not None or str(parsed.tzinfo) == "UTC"


def test_export_markdown_groups_by_kind_and_status():
    snapshot = build_export_snapshot(
        _snapshot_fixture_entries(),
        stats={"total_entries": 3, "resolved": 0, "contradicted": 1, "stale": 0},
        exported_at="2026-08-09T00:00:00+00:00",
    )
    content = snapshot_to_markdown(snapshot)
    assert content.startswith("# IDA Findings Export")
    assert "## finding (2)" in content
    assert "## question (1)" in content
    assert "### confirmed" in content
    assert "### open" in content
    assert "### rejected" in content
    assert "[0x401000] recv handler parses framed input" in content
    assert "conf=0.80" in content
    assert "priority=0.70" in content
    assert "tags=parsing, recv" in content
    assert "Length is read before dispatch." in content
    assert "evidence: [call] recv @ 0x401024" in content


def test_strip_export_fields_exposes_entry_id_from_id():
    stripped = strip_export_fields({"id": "z9", "title": "t", "fingerprint": "x", "vector": b"v"})
    assert stripped["entry_id"] == "z9"
    assert "fingerprint" not in stripped
    assert "vector" not in stripped
    assert stripped["title"] == "t"


# ---------------------------------------------------------------------------
# entry briefs across the lifecycle (proposed -> confirmed / contradicted -> resolved)
# ---------------------------------------------------------------------------


def test_entry_brief_derives_status_across_lifecycle():
    stages = {
        "proposed": ("proposed", 0, 0, "proposed"),
        "confirmed": ("confirmed", 0, 0, "confirmed"),
        # A contradicted entry carries status='rejected' in its own row (the
        # store refuses to silently overwrite opposed assertions).
        "rejected": ("rejected", 0, 1, "rejected"),
        "resolved": ("resolved", 1, 0, "resolved"),
    }
    for label, (status, resolved, contradicted, expected) in stages.items():
        entry = _fake_entry(
            entry_id=f"life-{label}",
            title=label,
            status=status,
            resolved=resolved,
            contradicted=contradicted,
        )
        brief = entry_brief(entry)
        assert brief["status"] == expected, label


def test_entry_brief_falls_back_to_derived_flags_when_status_missing():
    # Legacy rows with an unknown/empty status column render via the derived
    # resolved/contradicted read-time flags.
    assert entry_brief(_fake_entry(entry_id="x1", title="c", status="", contradicted=1))["status"] == "rejected"
    assert entry_brief(_fake_entry(entry_id="x2", title="r", status="", resolved=1))["status"] == "resolved"
    assert entry_brief(_fake_entry(entry_id="x3", title="o", status=""))["status"] == "open"


def test_lifecycle_renders_in_export_stats_and_markdown():
    entries = [
        _fake_entry(entry_id="p1", title="proposed claim", addr="", status="proposed", kind="hypothesis"),
        _fake_entry(
            entry_id="p2", title="confirmed claim", addr="", status="confirmed", kind="finding",
            resolved=0, contradicted=1,
        ),
        _fake_entry(entry_id="p3", title="resolved claim", addr="", status="resolved", kind="finding", resolved=1),
    ]
    snapshot = build_export_snapshot(
        entries,
        stats={"total_entries": 3, "resolved": 1, "contradicted": 1, "stale": 0},
        exported_at="2026-08-09T00:00:00+00:00",
    )
    assert snapshot["stats"]["resolved"] == 1
    assert snapshot["stats"]["contradicted"] == 1

    content = snapshot_to_markdown(snapshot)
    assert "### proposed" in content
    assert "### confirmed" in content
    assert "### resolved" in content
    assert "[no-addr] proposed claim" in content
    assert "[no-addr] confirmed claim" in content
    assert "[no-addr] resolved claim" in content


def test_write_response_created_flag_tracks_lifecycle():
    created = write_response({"entry_id": "p1", "created": True}, action="write", gravity={"items": []})
    assert created["created"] is True
    assert created["gravity"] == {"items": []}
    merged = write_response({"entry_id": "p1", "created": False}, action="write", gravity={"items": []})
    assert merged["created"] is False
    assert merged["gravity"] is None


# ---------------------------------------------------------------------------
# opaque raw-blob / RISC-V scenario
# ---------------------------------------------------------------------------


def _riscv_raw_blob_entry() -> dict:
    """A RISC-V payload handler at a supervisor-mode address whose content is
    an opaque raw-byte hex dump (null bytes, control chars, high bytes)."""
    blob = "0000: 00 01 02 7f 80 ff 00 0a 1b 2b 3c 00  e9 f1 00 00\n" \
           "0010: de ad be ef 00 00 00 00 00 00 00 00  aa bb cc dd"
    return _fake_entry(
        entry_id="rv1",
        title="riscv_plic_pending_handler",
        addr="0x0c000280",
        category="platform",
        kind="hypothesis",
        status="proposed",
        confidence=0.55,
        source_type="crawler",
        tags=["riscv", "plic", "opaque"],
        content=blob,
        evidence=[{"type": "memory", "value": blob, "address": "0x0c000280", "weight": 1.0}],
    )


def test_riscv_opaque_blob_entry_shapes_without_corruption():
    entry = _riscv_raw_blob_entry()
    brief = entry_brief(entry)
    # Status is preserved through the brief derivation.
    assert brief["status"] == "proposed"
    assert brief["addr"] == "0x0c000280"
    assert brief["content_preview"]  # clipped, not blank, not raising
    # Multi-line raw content is collapsed to a single clipped line.
    assert "\n" not in brief["content_preview"]
    assert len(brief["content_preview"]) <= 181


def test_riscv_opaque_blob_target_keeps_dual_keys_and_summary():
    entry = _riscv_raw_blob_entry()
    target = {
        "address": entry["addr"],
        "title": entry["title"],
        "category": entry["category"],
        "confidence": entry["confidence"],
        "reason": "open hypothesis, blocked on 0x0c000280",
        "entry_id": entry["id"],
    }
    out = next_target_response("unresolved", [target])
    t = out["targets"][0]
    assert t["address"] == "0x0c000280"
    assert t["addr"] == "0x0c000280"
    assert out["summary"]["best_addr"] == "0x0c000280"
    assert out["summary"]["briefs"][0]["addr"] == "0x0c000280"


def test_riscv_opaque_blob_survives_export_round_trip():
    entry = _riscv_raw_blob_entry()
    snapshot = build_export_snapshot([entry], stats={"total_entries": 1, "resolved": 0, "contradicted": 0, "stale": 0})
    exported = snapshot["entries"][0]
    assert exported["addr"] == "0x0c000280"
    assert exported["status"] == "proposed"
    assert "0000: 00 01 02" in exported["content"]
    # Blob content round-trips through JSON without loss or failure.
    text = snapshot_to_json(snapshot)
    assert "0c000280" in text
    assert "riscv_plic_pending_handler" in text
    md = snapshot_to_markdown(snapshot)
    assert "[0x0c000280] riscv_plic_pending_handler" in md


def test_clip_handles_control_chars_and_non_ascii_without_raising():
    text = "raw\x00blob\x1b\x7f\xffdata" + ("x" * 300)
    out = clip(text, limit=50)
    assert isinstance(out, str)
    assert len(out) <= 51
    assert out.endswith("…")
    # Non-string input (e.g. a bytes repr) degrades to str() safely.
    assert isinstance(clip(b"raw-bytes", limit=20), str)
    assert clip(None) == ""


# ---------------------------------------------------------------------------
# misc: strategy_note composition
# ---------------------------------------------------------------------------


def test_strategy_note_composition():
    assert strategy_note("unresolved", has_targets=True).startswith("Open questions")
    assert "Nothing is open" in strategy_note("unresolved", has_targets=False)
    assert strategy_note("bogus", has_targets=True) == ""
    assert strategy_note("bogus", has_targets=False) == "Nothing matched this strategy."


def test_target_collection_summary_prefers_priority_score_then_priority():
    targets = [
        {"addr": "0x401000", "title": "a", "priority_score": 0.95},
        {"addr": "0x402000", "title": "b", "priority": 0.3},
    ]
    summary = target_collection_summary(targets)
    assert "priority=0.950" in summary["briefs"][0]["summary"]
    assert "priority=0.300" in summary["briefs"][1]["summary"]
    assert summary["best_title"] == "a"


def test_frontier_collection_summary_empty_shape():
    assert frontier_collection_summary([]) == {"count": 0, "briefs": []}
