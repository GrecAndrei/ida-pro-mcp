"""The workspace must remember, invalidate, and disagree.

These cover the three behaviours that separate an investigation workspace
from a write-only notebook: negative results are recorded, claims notice when
their code changes, and opposed assertions are never merged away.
"""

from __future__ import annotations

import pytest

from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore, code_digest, normalize_addr


@pytest.fixture()
def store(tmp_path):
    return BlackboardStore(str(tmp_path / "workspace.db"))


# ---------------------------------------------------------------------------
# Negative results
# ---------------------------------------------------------------------------

def test_examining_an_address_is_recorded_so_it_is_not_re_read(store):
    store.record_examination("0x401a20", verdict="boring", note="CRT string helper.")

    prior = store.examination("0X401A20")
    assert prior is not None, "address lookup must be case- and padding-insensitive"
    assert prior["verdict"] == "boring"
    assert prior["note"] == "CRT string helper."


def test_re_examining_replaces_the_verdict_and_keeps_the_history(store):
    first = store.record_examination("0x401000", verdict="boring")
    second = store.record_examination("0x401000", verdict="interesting", note="Reachable from recv.")

    assert second["entry_id"] == first["entry_id"]
    assert second["created"] is False
    assert store.examination("0x401000")["verdict"] == "interesting"
    assert store.coverage() == {"examined": 1, "by_verdict": {"interesting": 1}}

    events = [e["event"] for e in store.workspace_brief()["recent_activity"]]
    assert "examined" in events


def test_examinations_stay_out_of_the_findings_brief(store):
    store.upsert_finding("Parses framed input", kind="finding", status="confirmed")
    store.record_examination("0x401a20", verdict="boring")

    brief = store.workspace_brief()

    assert [item["title"] for item in brief["confirmed"]] == ["Parses framed input"]
    assert brief["counts"]["examined"] == 1
    assert "1 addresses examined and set aside" in brief["brief"]


# ---------------------------------------------------------------------------
# Anchoring and staleness
# ---------------------------------------------------------------------------

def test_a_claim_goes_stale_when_the_code_under_it_changes(store):
    store.observe_code("0x401000", "decompile", "int f() { return recv(s, buf, 64); }")
    entry_id = store.upsert_finding(
        "Reads a fixed 64-byte frame", addr="0x401000", status="confirmed", confidence=0.9
    )["entry_id"]

    assert store.read(entry_id)["stale"] == 0

    result = store.observe_code("0x401000", "decompile", "int f() { return recv(s, buf, n); }")

    assert result["changed"] is True
    assert result["stale_marked"] == 1
    entry = store.read(entry_id)
    assert entry["stale"] == 1
    assert "0x401000" in entry["stale_reason"]
    # Staleness annotates; it must never delete or rewrite the claim.
    assert entry["confidence"] == 0.9
    assert entry["status"] == "confirmed"


def test_reformatting_alone_is_not_drift(store):
    store.observe_code("0x401000", "decompile", "int f() {\n  return 1;\n}")
    entry_id = store.upsert_finding("Returns one", addr="0x401000")["entry_id"]

    result = store.observe_code("0x401000", "decompile", "int f() {    return 1;   }")

    assert result["changed"] is False
    assert store.read(entry_id)["stale"] == 0


def test_revising_a_stale_claim_re_anchors_it(store):
    store.observe_code("0x401000", "decompile", "old body")
    entry_id = store.upsert_finding("Claim", addr="0x401000")["entry_id"]
    store.observe_code("0x401000", "decompile", "new body")
    assert store.read(entry_id)["stale"] == 1

    store.update(entry_id, content="Re-read against the new body.")

    entry = store.read(entry_id)
    assert entry["stale"] == 0
    assert entry["anchor_digest"] == code_digest("new body")


def test_an_examination_goes_stale_too(store):
    """"Boring" is a claim about code, and that code can change."""
    store.observe_code("0x401a20", "decompile", "return strlen(s);")
    store.record_examination("0x401a20", verdict="boring")

    store.observe_code("0x401a20", "decompile", "return system(s);")

    assert store.examination("0x401a20")["stale"] is True


def test_stale_entries_surface_as_their_own_target_strategy(store):
    store.observe_code("0x401000", "decompile", "before")
    store.upsert_finding("Affected claim", addr="0x401000")
    store.observe_code("0x401000", "decompile", "after")

    result = store.targets("stale", limit=5)

    assert result["strategy"] == "stale"
    assert [t["title"] for t in result["targets"]] == ["Affected claim"]
    assert "code at 0x401000 changed" in result["targets"][0]["reason"]


# ---------------------------------------------------------------------------
# Disagreement
# ---------------------------------------------------------------------------

def test_a_rejection_never_silently_overwrites_a_confirmation(store):
    confirmed = store.upsert_finding(
        "Length is validated", addr="0x401000", status="confirmed", confidence=0.9
    )
    rejected = store.upsert_finding(
        "Length is validated", addr="0x401000", status="rejected", confidence=0.2
    )

    assert rejected["entry_id"] != confirmed["entry_id"], "both claims must survive"
    assert rejected["conflict"]["with"] == confirmed["entry_id"]

    # The original keeps its own status and confidence; nothing was merged.
    original = store.read(confirmed["entry_id"])
    assert original["status"] == "confirmed"
    assert original["confidence"] == 0.9
    assert rejected["entry_id"] in original["conflicts_with"]

    ids = {e["id"] for e in store.conflicts()}
    assert ids == {confirmed["entry_id"], rejected["entry_id"]}


def test_conflicts_are_named_in_the_brief_and_drive_the_next_step(store):
    store.upsert_finding("Key is hardcoded", addr="0x402000", status="confirmed")
    store.upsert_finding("Key is hardcoded", addr="0x402000", status="rejected")

    brief = store.workspace_brief()

    assert brief["counts"]["conflicts"] == 2
    assert "Conflicts" in brief["brief"]
    assert "Next: resolve the conflicts" in brief["brief"]


def test_repeated_agreement_does_not_ratchet_confidence_upward(store):
    """Restating a claim is not evidence for it."""
    first = store.upsert_finding("Handles TLV records", addr="0x401000", confidence=0.9)
    store.upsert_finding("Handles TLV records", addr="0x401000", confidence=0.4)

    assert store.read(first["entry_id"])["confidence"] == 0.4


def test_auto_merge_leaves_conflicting_rows_alone(store):
    store.upsert_finding("Key is hardcoded", addr="0x402000", status="confirmed")
    store.upsert_finding("Key is hardcoded", addr="0x402000", status="rejected")

    result = store.auto_merge(addr="0x402000")

    assert result["merged"] == 0
    assert len(store.conflicts()) == 2


# ---------------------------------------------------------------------------
# Recall
# ---------------------------------------------------------------------------

def test_recall_returns_findings_verdicts_and_open_threads_for_an_address(store):
    store.upsert_finding("Parses a length prefix", addr="0x401000", status="confirmed", confidence=0.8)
    store.upsert_finding("Is the length bounded?", addr="0x401000", kind="question")
    store.record_examination("0x401b00", verdict="boring", note="Thunk.")

    recalled = store.recall(["0x401000", "0x401b00"])

    assert [f["title"] for f in recalled["findings"]] == ["Parses a length prefix"]
    assert [q["title"] for q in recalled["open_threads"]] == ["Is the length bounded?"]
    assert recalled["examined"] == [
        {"address": "0x401b00", "verdict": "boring", "note": "Thunk.", "stale": False}
    ]


def test_recall_flags_stale_and_conflicting_entries_it_returns(store):
    store.observe_code("0x401000", "decompile", "before")
    store.upsert_finding("Claim", addr="0x401000", status="confirmed")
    store.upsert_finding("Claim", addr="0x401000", status="rejected")
    store.observe_code("0x401000", "decompile", "after")

    lines = "\n".join(store.recall_lines(["0x401000"], limit=6))

    assert "stale: code changed since this was recorded" in lines
    assert "conflicts with" in lines


def test_recall_ignores_internal_enrichment_rows(store):
    store.upsert_finding("Real claim", addr="0x401000")
    store.write(title="gravity 0x401000", addr="0x401000", source_type="gravity")

    titles = [f["title"] for f in store.recall(["0x401000"])["findings"]]

    assert titles == ["Real claim"]


def test_recall_on_an_unknown_address_is_empty_not_noisy(store):
    store.upsert_finding("Elsewhere", addr="0x401000")

    assert store.recall_lines(["0x999999"]) == []


# ---------------------------------------------------------------------------
# Target strategies
# ---------------------------------------------------------------------------

def test_every_target_carries_a_reason(store):
    store.upsert_finding("Open question", kind="question", addr="0x401000")

    for target in store.targets("unresolved", limit=5)["targets"]:
        assert target["reason"], f"{target} has no reason"


def test_blocked_threads_rank_below_actionable_ones(store):
    blocked = store.upsert_finding("Blocked", kind="task", addr="0x401000", priority=1.0)
    store.update(blocked["entry_id"], depends_on="0x500000")
    store.upsert_finding("Actionable", kind="task", addr="0x402000", priority=0.1)

    titles = [t["title"] for t in store.targets("unresolved", limit=5)["targets"]]

    assert titles == ["Actionable", "Blocked"]
    assert "blocked on 0x500000" in store.targets("unresolved")["targets"][1]["reason"]


def test_a_dependency_that_is_resolved_unblocks_its_thread(store):
    store.upsert_finding("Prerequisite", addr="0x500000", status="resolved")
    dependent = store.upsert_finding("Dependent", kind="task", addr="0x401000")["entry_id"]
    store.update(dependent, depends_on="0x500000")

    target = store.targets("unresolved", limit=5)["targets"][0]

    assert target["title"] == "Dependent"
    assert "dependency 0x500000 is resolved" in target["reason"]


def test_coverage_skips_addresses_already_examined(store):
    store.record_examination("0x402000", verdict="boring")

    def rpc(tool, arguments):
        return {"functions": [
            {"addr": "0x402000", "name": "sub_402000", "xref_count": 30},
            {"addr": "0x403000", "name": "sub_403000", "xref_count": 2},
        ]}

    addresses = [t["address"] for t in store.targets("coverage", limit=5, rpc_fn=rpc)["targets"]]

    assert addresses == ["0x403000"]


def test_frontier_expands_from_confirmed_findings(store):
    store.upsert_finding("Command dispatcher", addr="0x401000", status="confirmed", confidence=0.9)

    def rpc(tool, arguments):
        assert tool == "code"
        if arguments["action"] == "callers":
            return {"callers": [{"addr": "0x400100"}]}
        return {"callees": [{"addr": "0x401500"}]}

    targets = store.targets("frontier", limit=5, rpc_fn=rpc)["targets"]

    assert {t["address"] for t in targets} == {"0x400100", "0x401500"}
    assert all("Command dispatcher" in t["reason"] for t in targets)


def test_frontier_without_a_live_session_returns_nothing_rather_than_guessing(store):
    store.upsert_finding("Confirmed", addr="0x401000", status="confirmed")

    assert store.targets("frontier", limit=5, rpc_fn=None)["targets"] == []


def test_an_unknown_strategy_is_rejected(store):
    with pytest.raises(ValueError, match="strategy must be one of"):
        store.targets("vibes")


def test_a_query_reorders_targets_but_never_drops_them(store):
    store.upsert_finding("Crypto key schedule", kind="question", addr="0x401000")
    store.upsert_finding("Packet length check", kind="question", addr="0x402000")

    result = store.targets("unresolved", limit=5, query="packet length")

    assert [t["title"] for t in result["targets"]] == [
        "Packet length check", "Crypto key schedule",
    ]
    assert result["count"] == 2, "ranking must not hide the weaker match"


# ---------------------------------------------------------------------------
# Address normalisation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("raw", "expected"),
    [("0X401000", "0x401000"), ("0x00401000", "0x401000"), (0x401000, "0x401000"),
     ("  0x401000 ", "0x401000"), ("", ""), (None, "")],
)
def test_addresses_normalise_to_one_spelling(raw, expected):
    assert normalize_addr(raw) == expected
