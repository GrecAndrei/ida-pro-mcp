"""Findings must reach the IDB, and the IDB's own annotations must reach back.

The IDB is the artifact an analyst opens. These pin both directions and, more
importantly, the guards: publishing never overwrites a name someone else
applied, never fires without acknowledgement, and never re-adopts its own
output as an independent second opinion.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_pro_mcp.host.errors import is_error_result  # noqa: E402
from ida_pro_mcp.host.server.server_blackboard_idb import ServerBlackboardIdbMixin  # noqa: E402
from ida_pro_mcp.host.stores.blackboard_store import (  # noqa: E402
    BlackboardStore,
    entry_id_in,
    symbol_from_title,
)


class _FakeIda:
    """A tiny IDB: names, comments, and a record of what was asked of it."""

    def __init__(self, names=None, comments=None):
        self.names = dict(names or {})
        self.comments = dict(comments or {})
        self.calls: list[tuple[str, dict]] = []
        self.rename_fails_at: set[str] = set()

    def __call__(self, tool, payload):
        self.calls.append((tool, dict(payload)))
        action = payload.get("action")
        if tool == "batch":
            results = []
            for call in payload.get("calls", []):
                results.append(self(call.get("tool", ""), call))
            return {"ok": True, "results": results}
        if tool == "data" and action == "lookup":
            addr = payload["query"]
            return {"ok": True, "addr": addr, "name": self.names.get(addr, f"sub_{addr[2:]}")}
        if tool == "data" and action == "annotations":
            rows = []
            for addr in sorted(set(self.names) | set(self.comments)):
                name = self.names.get(addr, f"sub_{addr[2:]}")
                row = {"addr": addr, "name": name,
                       "auto_named": name.startswith(("sub_", "j_", "loc_"))}
                if addr in self.comments:
                    row["repeatable_comment"] = self.comments[addr]
                rows.append(row)
            return {"ok": True, "annotations": rows, "total": len(rows)}
        if tool == "modify" and action == "rename":
            if payload["addr"] in self.rename_fails_at:
                return {"error": True, "message": "name already used"}
            self.names[payload["addr"]] = payload["value"]
            return {"ok": True}
        if tool == "modify" and action == "comment":
            self.comments[payload["addr"]] = payload["value"]
            return {"ok": True}
        return {"error": True, "message": f"unsupported {tool}/{action}"}


class _Host(ServerBlackboardIdbMixin):
    def __init__(self, ida=None):
        self._ida = ida
        self.current_session = type("S", (), {"idb_path": "/tmp/t.i64"})() if ida else None

    def call_tool(self, tool, idb_path, **kwargs):
        return self._ida(tool, kwargs)


@pytest.fixture()
def store(tmp_path):
    return BlackboardStore(str(tmp_path / "workspace.db"))


# ---------------------------------------------------------------------------
# Symbol derivation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("title", "expected"),
    [
        ("Packet receive handler", "packet_receive_handler"),
        ("AES-128 key schedule", "aes_128_key_schedule"),
        ("  spaced   out  ", "spaced_out"),
        ("3rd stage loader", "f_3rd_stage_loader"),
        ("!!!", ""),
        ("", ""),
    ],
)
def test_titles_become_c_identifiers_or_nothing(title, expected):
    assert symbol_from_title(title) == expected


# ---------------------------------------------------------------------------
# Publishing
# ---------------------------------------------------------------------------

def test_publishing_writes_a_comment_and_renames_an_auto_named_function(store):
    ida = _FakeIda()
    host = _Host(ida)
    entry = store.upsert_finding(
        "Packet receive handler", content="Parses a length prefix.",
        addr="0x401000", status="confirmed", confidence=0.85,
    )

    result = host._publish_findings(store, {"_risk_ack": True})

    assert result["count"] == 1
    assert ida.names["0x401000"] == "packet_receive_handler"
    comment = ida.comments["0x401000"]
    assert "Packet receive handler (confidence 0.85)" in comment
    assert "Parses a length prefix." in comment
    assert entry_id_in(comment) == entry["entry_id"]
    # Comments are repeatable so they follow the function to its call sites.
    assert any(c[1].get("comment_type") == "repeatable" for c in ida.calls)


def test_publishing_never_overwrites_a_name_someone_else_applied(store):
    ida = _FakeIda(names={"0x401000": "parse_frame"})
    host = _Host(ida)
    store.upsert_finding("Packet receive handler", addr="0x401000", status="confirmed")

    result = host._publish_findings(store, {"_risk_ack": True})

    assert ida.names["0x401000"] == "parse_frame"
    assert "not overwriting an existing symbol" in result["published"][0]["rename_skipped"]
    # The comment still lands: the claim is recorded, just not as the name.
    assert "0x401000" in ida.comments


def test_publishing_requires_acknowledgement(store):
    host = _Host(_FakeIda())
    store.upsert_finding("Anything", addr="0x401000", status="confirmed")

    result = host._publish_findings(store, {})

    assert is_error_result(result)
    assert "risk_ack" in result["message"]


def test_a_dry_run_needs_no_acknowledgement_and_writes_nothing(store):
    ida = _FakeIda()
    host = _Host(ida)
    store.upsert_finding("Packet receive handler", addr="0x401000", status="confirmed")

    result = host._publish_findings(store, {"dry_run": True})

    assert result["dry_run"] is True
    assert result["published"][0]["symbol"] == "packet_receive_handler"
    assert ida.comments == {} and not any(t == "modify" for t, _ in ida.calls)
    assert store.publishable(), "a preview must not mark anything as published"


def test_only_settled_findings_are_eligible(store):
    ida = _FakeIda()
    host = _Host(ida)
    store.upsert_finding("Open question", addr="0x401000", kind="question")
    store.upsert_finding("Unconfirmed", addr="0x402000", status="open")
    store.record_examination("0x403000", verdict="boring")
    store.observe_code("0x404000", "decompile", "a")
    store.upsert_finding("Stale claim", addr="0x404000", status="confirmed")
    store.observe_code("0x404000", "decompile", "b")
    store.upsert_finding("Contested", addr="0x405000", status="confirmed")
    store.upsert_finding("Contested", addr="0x405000", status="rejected")

    result = host._publish_findings(store, {"_risk_ack": True})

    assert result["count"] == 0
    assert ida.comments == {}


def test_publishing_is_idempotent_until_the_finding_changes(store):
    ida = _FakeIda()
    host = _Host(ida)
    entry_id = store.upsert_finding(
        "Packet receive handler", addr="0x401000", status="confirmed"
    )["entry_id"]

    assert host._publish_findings(store, {"_risk_ack": True})["count"] == 1
    assert host._publish_findings(store, {"_risk_ack": True})["count"] == 0

    store.update(entry_id, content="Now with the length check described.")
    assert host._publish_findings(store, {"_risk_ack": True})["count"] == 1

    # And republish=true rewrites regardless.
    assert host._publish_findings(store, {"_risk_ack": True, "republish": True})["count"] == 1


def test_rename_can_be_declined_while_still_commenting(store):
    ida = _FakeIda()
    host = _Host(ida)
    store.upsert_finding("Packet receive handler", addr="0x401000", status="confirmed")

    host._publish_findings(store, {"_risk_ack": True, "rename": False})

    assert "0x401000" in ida.comments
    assert ida.names == {}


def test_a_failed_rename_is_reported_and_not_recorded_as_published(store):
    ida = _FakeIda()
    ida.rename_fails_at.add("0x401000")
    host = _Host(ida)
    entry_id = store.upsert_finding(
        "Packet receive handler", addr="0x401000", status="confirmed"
    )["entry_id"]

    result = host._publish_findings(store, {"_risk_ack": True})

    record = result["published"][0]
    assert "name already used" in record["rename_failed"]
    assert "symbol" not in record
    assert "0x401000" in ida.comments, "the comment still landed"
    assert store.read(entry_id)["published_symbol"] == ""


def test_publishing_without_a_session_is_an_error_not_a_silent_no_op(store):
    host = _Host(None)
    store.upsert_finding("Anything", addr="0x401000", status="confirmed")

    result = host._publish_findings(store, {"_risk_ack": True})

    assert is_error_result(result)
    assert "ida_open_binary" in result["message"]


# ---------------------------------------------------------------------------
# Importing
# ---------------------------------------------------------------------------

def test_existing_names_and_comments_become_findings(store):
    ida = _FakeIda(
        names={"0x401000": "parse_frame"},
        comments={"0x402000": "Decrypts the config blob with a hardcoded key."},
    )
    host = _Host(ida)

    result = host._import_annotations(store, {})

    assert result["created"] == 2
    titles = {e["title"] for e in store.list(category="idb")}
    assert "parse_frame (named in the IDB)" in titles
    assert "Decrypts the config blob with a hardcoded key." in titles
    # Adopted, not verified: this tool cannot tell an analyst's rename from a
    # FLIRT match, and the confidence must say so.
    assert all(e["confidence"] == 0.5 for e in store.list(category="idb"))


def test_importing_skips_annotations_this_tool_wrote(store):
    """Re-adopting our own comment would fabricate a second, independent claim."""
    ida = _FakeIda()
    host = _Host(ida)
    store.upsert_finding("Packet receive handler", addr="0x401000", status="confirmed")
    host._publish_findings(store, {"_risk_ack": True})
    before = store.stats()["total_entries"]

    result = host._import_annotations(store, {})

    assert result["count"] == 0
    assert result["skipped_own_annotations"] == 1
    assert store.stats()["total_entries"] == before


def test_a_round_trip_does_not_multiply_entries(store):
    ida = _FakeIda()
    host = _Host(ida)
    store.upsert_finding("Packet receive handler", addr="0x401000", status="confirmed")

    for _ in range(3):
        host._publish_findings(store, {"_risk_ack": True, "republish": True})
        host._import_annotations(store, {})

    assert store.stats()["total_entries"] == 1


def test_importing_from_an_ida_side_without_the_action_says_so(store):
    class _Old(_FakeIda):
        def __call__(self, tool, payload):
            if payload.get("action") == "annotations":
                return {"error": True, "message": "unknown action"}
            return super().__call__(tool, payload)

    host = _Host(_Old())

    result = host._import_annotations(store, {})

    assert is_error_result(result)
    assert "Reinstall the plugin" in result["message"]


def test_imported_findings_are_recalled_like_any_other(store):
    host = _Host(_FakeIda(comments={"0x402000": "Decrypts the config blob."}))
    host._import_annotations(store, {})

    assert store.recall_lines(["0x402000"]) == [
        "finding/confirmed: Decrypts the config blob. — @ 0x402000"
    ]


def test_publishing_batches_symbol_lookups(store):
    ida = _FakeIda()
    host = _Host(ida)
    store.upsert_finding("Handler one", addr="0x401000", status="confirmed")
    store.upsert_finding("Handler two", addr="0x402000", status="confirmed")

    res = host._publish_findings(store, {"_risk_ack": True})
    assert res["count"] == 2

    batch_calls = [c for c in ida.calls if c[0] == "batch"]
    assert len(batch_calls) == 1
    call_payload = batch_calls[0][1]
    sub_calls = call_payload.get("calls", [])
    assert len(sub_calls) == 2
    assert {sc.get("query") for sc in sub_calls} == {"0x401000", "0x402000"}

