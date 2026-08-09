"""Work order g02: pin the blackboard<->IDB round-trip fixes.

This suite pins the g02 fix batch in ``server_blackboard_idb.py``:

* a failed/errored symbol lookup must never let publish SN_FORCE-rename an
  analyst-applied name -- the old ''-collapse treated "could not read" as
  "auto-named" and clobbered names it never saw;
* multiple confirmed findings at one address must not collide in the single
  repeatable-comment slot: only the first is published, the rest are skipped,
  and nothing is marked published whose comment did not land;
* the "batch symbol lookups" optimization must chunk under the IDA-side
  20-call batch cap instead of silently degenerating to sequential RPCs;
* a modify RPC returning None (or any non-ok result) must surface as a
  failure, never as a fabricated published record;
* the import side counts the three distinct skip reasons separately instead of
  lumping them all into ``skipped_own_annotations``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_pro_mcp.host.server.server_blackboard_idb import (  # noqa: E402
    IDA_BATCH_MAX_CALLS,
    ServerBlackboardIdbMixin,
)
from ida_pro_mcp.host.stores.blackboard_store import (  # noqa: E402
    BlackboardStore,
    entry_id_in,
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
# A failed/ambiguous symbol lookup must never overwrite an analyst's name
# ---------------------------------------------------------------------------


class _LookupErrors(_FakeIda):
    """Lookup for chosen addresses returns an error envelope."""

    def __init__(self, names=None, comments=None, fail_at=None):
        super().__init__(names=names, comments=comments)
        self.fail_at = set(fail_at or ())

    def __call__(self, tool, payload):
        if tool == "data" and payload.get("action") == "lookup":
            if payload.get("query") in self.fail_at:
                return {"error": True, "message": "lookup exploded", "code": "IDA_ERROR"}
        return super().__call__(tool, payload)


class _LookupRaises(_FakeIda):
    """Lookup raises for every address."""

    def __call__(self, tool, payload):
        if tool == "data" and payload.get("action") == "lookup":
            raise RuntimeError("boom")
        return super().__call__(tool, payload)


class _LookupNoNameKey(_FakeIda):
    """Lookup returns ok but with no 'name' key (malformed / ambiguous)."""

    def __call__(self, tool, payload):
        if tool == "data" and payload.get("action") == "lookup":
            return {"ok": True, "addr": payload.get("query")}
        return super().__call__(tool, payload)


def test_a_lookup_error_envelope_never_overwrites_an_analyst_name(store):
    ida = _LookupErrors(names={"0x401000": "parse_frame"}, fail_at={"0x401000"})
    host = _Host(ida)
    store.upsert_finding("Packet receive handler", addr="0x401000", status="confirmed")

    result = host._publish_findings(store, {"_risk_ack": True})

    assert ida.names["0x401000"] == "parse_frame"
    assert result["published"][0]["rename_skipped"] == "could not read current symbol"
    # The claim still lands as a comment; only the name is left alone.
    assert "0x401000" in ida.comments


def test_a_lookup_that_raises_never_overwrites_an_analyst_name(store):
    ida = _LookupRaises(names={"0x401000": "parse_frame"})
    host = _Host(ida)
    store.upsert_finding("Packet receive handler", addr="0x401000", status="confirmed")

    result = host._publish_findings(store, {"_risk_ack": True})

    assert ida.names["0x401000"] == "parse_frame"
    assert result["published"][0]["rename_skipped"] == "could not read current symbol"
    assert "0x401000" in ida.comments


def test_a_lookup_without_a_name_key_never_overwrites_an_analyst_name(store):
    ida = _LookupNoNameKey(names={"0x401000": "parse_frame"})
    host = _Host(ida)
    store.upsert_finding("Packet receive handler", addr="0x401000", status="confirmed")

    result = host._publish_findings(store, {"_risk_ack": True})

    assert ida.names["0x401000"] == "parse_frame"
    assert result["published"][0]["rename_skipped"] == "could not read current symbol"
    assert "0x401000" in ida.comments


def test_a_failed_sub_lookup_inside_a_batch_also_skips_rename(store):
    ida = _LookupErrors(fail_at={"0x401000"})
    host = _Host(ida)
    store.upsert_finding("Handler one", addr="0x401000", status="confirmed")
    store.upsert_finding("Handler two", addr="0x402000", status="confirmed")

    result = host._publish_findings(store, {"_risk_ack": True})

    records = {r["address"]: r for r in result["published"]}
    # The failing address is not renamed and reports why; the healthy address
    # still gets its auto-named symbol replaced.
    assert "0x401000" not in ida.names
    assert records["0x401000"]["rename_skipped"] == "could not read current symbol"
    assert ida.names["0x402000"] == "handler_two"


# ---------------------------------------------------------------------------
# Same-address comment collision
# ---------------------------------------------------------------------------

def test_two_findings_at_one_address_publish_one_comment_and_skip_the_other(store):
    ida = _FakeIda()
    host = _Host(ida)
    top = store.upsert_finding(
        "Top claim", addr="0x401000", status="confirmed", confidence=0.9
    )["entry_id"]
    low = store.upsert_finding(
        "Lower claim", addr="0x401000", status="confirmed", confidence=0.7
    )["entry_id"]

    result = host._publish_findings(store, {"_risk_ack": True})

    # Exactly one comment slot was written, carrying only the winner's marker.
    assert len(ida.comments) == 1
    comment = ida.comments["0x401000"]
    assert entry_id_in(comment) == top
    assert entry_id_in(comment) != low

    assert result["count"] == 1
    assert result["published"][0]["entry_id"] == top
    failed_by_id = {f["entry_id"]: f for f in result["failed"]}
    assert low in failed_by_id
    assert failed_by_id[low]["error"] == "address already published this run"

    # The winner is marked published; the skipped claim is not.
    assert store.read(top)["published_at"] is not None
    assert store.read(low)["published_at"] is None

    # Only the winner's slug was written as the symbol.
    assert ida.names["0x401000"] == "top_claim"


def test_a_comment_that_never_lands_is_not_marked_published(store):
    class _ModifyFailsComment(_FakeIda):
        def __call__(self, tool, payload):
            if tool == "modify" and payload.get("action") == "comment":
                return {"error": True, "message": "comment rejected"}
            return super().__call__(tool, payload)

    ida = _ModifyFailsComment()
    host = _Host(ida)
    entry_id = store.upsert_finding(
        "Packet receive handler", addr="0x401000", status="confirmed"
    )["entry_id"]

    result = host._publish_findings(store, {"_risk_ack": True})

    assert result["count"] == 0
    assert result["failed"][0]["entry_id"] == entry_id
    assert "comment rejected" in result["failed"][0]["error"]
    assert "0x401000" not in ida.comments
    assert store.read(entry_id)["published_at"] is None


# ---------------------------------------------------------------------------
# Batch chunking under the IDA-side 20-call cap
# ---------------------------------------------------------------------------

def test_25_entry_publish_chunks_lookups_to_20_call_sub_batches(store):
    ida = _FakeIda()
    host = _Host(ida)
    for i in range(25):
        store.upsert_finding(f"Handler {i}", addr=f"0x40{i:02x}", status="confirmed")

    result = host._publish_findings(store, {"_risk_ack": True})

    assert result["count"] == 25
    batch_calls = [c for c in ida.calls if c[0] == "batch"]
    # 25 unique addresses must be chunked into ceil(25/20) = 2 batch calls,
    # never one oversized request that the IDA side would reject.
    assert len(batch_calls) == 2
    assert all(len(c[1].get("calls", [])) <= IDA_BATCH_MAX_CALLS for c in batch_calls)
    assert sum(len(c[1].get("calls", [])) for c in batch_calls) == 25
    # Every address still resolved: no sequential fallback loss, all renamed.
    assert len(ida.names) == 25
    assert ida.names["0x4012"] == "handler_18"


def test_every_batch_request_stays_under_the_idb_batch_cap(store):
    """A larger publish never issues a batch RPC with more than 20 sub-calls."""
    ida = _FakeIda()
    host = _Host(ida)
    for i in range(41):
        store.upsert_finding(f"Handler {i}", addr=f"0x50{i:02x}", status="confirmed")

    result = host._publish_findings(store, {"_risk_ack": True, "limit": 41})

    assert result["count"] == 41
    batch_calls = [c for c in ida.calls if c[0] == "batch"]
    assert all(len(c[1].get("calls", [])) <= IDA_BATCH_MAX_CALLS for c in batch_calls)
    assert len(ida.names) == 41


# ---------------------------------------------------------------------------
# A modify RPC returning None must surface as a failure
# ---------------------------------------------------------------------------

class _ModifyReturnsNone(_FakeIda):
    def __call__(self, tool, payload):
        if tool == "modify":
            return None
        return super().__call__(tool, payload)


def test_modify_returning_none_is_reported_as_failed_not_published(store):
    ida = _ModifyReturnsNone()
    host = _Host(ida)
    entry_id = store.upsert_finding(
        "Packet receive handler", addr="0x401000", status="confirmed"
    )["entry_id"]

    result = host._publish_findings(store, {"_risk_ack": True})

    assert result["count"] == 0
    assert result["failed"][0]["entry_id"] == entry_id
    assert result["failed"][0]["error"] == "None"
    assert "0x401000" not in ida.comments
    assert store.read(entry_id)["published_at"] is None


# ---------------------------------------------------------------------------
# Import: the three distinct skip reasons are counted separately
# ---------------------------------------------------------------------------

class _AnnotationsRows(_FakeIda):
    """Serves caller-provided annotation rows verbatim."""

    def __init__(self, rows):
        super().__init__()
        self.rows = list(rows)

    def __call__(self, tool, payload):
        if tool == "data" and payload.get("action") == "annotations":
            return {"ok": True, "annotations": self.rows, "total": len(self.rows)}
        return super().__call__(tool, payload)


def test_import_counts_the_three_skip_reasons_separately(store):
    host = _Host(_AnnotationsRows([
        {"addr": "0x500000", "name": "sub_500000"},                  # auto-named, no comment
        {"addr": "", "name": "parse_frame"},                          # no address
        {"addr": "0x600000", "name": "my_rename",
         "repeatable_comment": "Decrypts the blob."},                 # adopted
        {"addr": "0x700000", "name": "mine",
         "repeatable_comment": "claim [mcp:abc1234]"},                # our own marker
    ]))

    result = host._import_annotations(store, {})

    assert result["count"] == 1
    assert result["imported"][0]["address"] == "0x600000"
    assert result["skipped_no_addr"] == 1
    assert result["skipped_own_annotations"] == 1
    assert result["skipped_no_content"] == 1
    assert store.stats()["total_entries"] == 1


def test_auto_named_rows_without_comment_are_not_counted_as_own_annotations(store):
    ida = _FakeIda(
        names={"0x401000": "sub_401000"},
        comments={"0x402000": "Real analyst note."},
    )
    host = _Host(ida)

    result = host._import_annotations(store, {})

    assert result["count"] == 1
    assert result["imported"][0]["address"] == "0x402000"
    assert result["skipped_no_content"] == 1
    assert "skipped_own_annotations" not in result
