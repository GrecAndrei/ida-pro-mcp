"""Canonical response shapers for the blackboard host surface.

Pure functions. No IDA, no server state, no store: every function takes
already-retrieved data (entries, targets, stats) and returns the exact dict
the MCP client is contractually promised. The host handler composes these
into its per-action responses so the keep=true response shapes live in one
place and stay stable while the store underneath is rewritten.

The canonical shapes pinned by the keep=true contracts:

``list`` / ``search``
    ``{ok, entries, count, summary}`` / ``{ok, query, entries, count, summary}``
``read``
    ``{ok, entry, summary}``
``write``
    ``{ok, entry_id, created, action, gravity, phase}`` where ``gravity`` is
    a bounded snapshot ``{items, note, entry_id}`` (≤ ``GRAVITY_MAX_ITEMS``
    evidence items) and only fires when the write created a new entry.
``next_target``
    ``{ok, strategy, targets, count, summary, note, strategies}`` — every
    target carries BOTH the ``address`` and the ``addr`` key.
``frontier``
    ``{ok, frontier, count, summary}`` — a list, never a joined string.
``coverage``
    ``{ok, coverage_pct, total_entries, analyzed, unvisited, note}`` — the
    note is honest about what the metric does and does not measure.
``crawler_status``
    ``{ok, running, pending_proposals, addresses_visited, proposals}`` — the
    legacy ``proposals_pending`` alias is deliberately absent.
``export``
    ``ida-findings-v1`` snapshot ``{format, exported_at, stats, entries}``
    rendered to JSON or Markdown; entries drop the internal storage fields
    (fingerprint, vector, norm, …) and expose ``entry_id`` instead of ``id``.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any, Iterable

#: Version stamp of the JSON export format, so consumers can detect
#: incompatible files instead of guessing.
EXPORT_FORMAT_VERSION = "ida-findings-v1"

#: Fields that describe internal storage rather than the investigation, and
#: are therefore not part of an export.
EXPORT_DROP_FIELDS = frozenset(
    {
        "fingerprint",
        "bridges",
        "schema",
        "register",
        "reg_type",
        "norm",
        "call_idx",
        "decayed_at",
        "version",
        "entropy",
        "quantized",
        "q_signs",
        "vector",
    }
)

#: Render order for the Markdown export: kinds first, statuses within a kind.
EXPORT_KIND_ORDER = ("finding", "hypothesis", "question", "task", "decision", "examined")
EXPORT_STATUS_ORDER = ("open", "proposed", "confirmed", "resolved", "rejected")

#: The target strategies the store exposes, in the order they are advertised.
STRATEGIES = ("unresolved", "stale", "conflict", "coverage", "frontier")

#: What each target strategy selects for, stated plainly in the response so
#: the model can judge whether the suggestion is worth taking.
STRATEGY_NOTES = {
    "unresolved": "Open questions, hypotheses, and tasks, plus findings recorded but never verified.",
    "stale": "Claims whose underlying code changed after they were written.",
    "conflict": "Entries that contradict another entry and must be reconciled.",
    "coverage": "Frequently-called functions with no finding and no examination.",
    "frontier": "Unexamined callers and callees of confirmed findings.",
}

#: Appended when a strategy matched nothing, so an empty result reads as a
#: positive signal (nothing owed) rather than a failure.
STRATEGY_EMPTY_NOTES = {
    "unresolved": " Nothing is open. Try strategy='coverage'.",
    "stale": " No claim has been invalidated by a code change.",
    "conflict": " No contradictions recorded.",
    "coverage": " Every function is already recorded or examined, or no session is open.",
    "frontier": " Nothing is confirmed yet to expand from, or no session is open.",
}

#: Honest framing for the coverage action. It is a workspace-bookkeeping
#: metric, not a claim that every function has been reverse-engineered.
COVERAGE_NOTE = (
    "Coverage counts addresses with a recorded examination or finding; it "
    "measures workspace bookkeeping, not that every function has been "
    "reverse-engineered. A function with one shallow note counts the same "
    "as a fully documented one."
)

#: Statuses the entry brief can express directly.
_BRIEF_STATUSES = frozenset({"open", "proposed", "confirmed", "resolved", "rejected"})

#: Maximum evidence items a gravity snapshot may carry.
GRAVITY_MAX_ITEMS = 12


def clip(text: Any, limit: int = 120) -> str:
    """Collapse whitespace and truncate ``text`` to ``limit`` characters."""
    value = str(text or "").replace("\n", " ").strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "…"


def entry_brief(entry: dict[str, Any]) -> dict[str, Any]:
    """A compact one-line-ish brief for a single entry.

    ``status`` is derived from the raw ``status`` column, falling back to the
    derived ``resolved``/``contradicted`` read-time flags so entries written
    by the legacy lifecycle still render correctly.
    """
    tags = entry.get("tags") or []
    evidence = entry.get("evidence") or []
    addr = str(entry.get("addr") or "").strip()
    title = str(entry.get("title") or "").strip()
    category = str(entry.get("category") or "general").strip()
    confidence = float(entry.get("confidence") or 0.0)
    raw_status = str(entry.get("status") or "").strip().lower()
    if raw_status in _BRIEF_STATUSES:
        status = raw_status
    elif entry.get("resolved"):
        status = "resolved"
    elif entry.get("contradicted"):
        status = "rejected"
    else:
        status = "open"
    tag_list = tags if isinstance(tags, list) else []
    return {
        "entry_id": entry.get("id") or entry.get("entry_id"),
        "addr": addr or None,
        "title": title,
        "category": category,
        "confidence": round(confidence, 3),
        "source_type": str(entry.get("source_type") or "manual"),
        "status": status,
        "tags": tag_list[:8],
        "evidence_count": len(evidence) if isinstance(evidence, list) else 0,
        "summary": clip(
            f"{addr or 'no-addr'} | {category} | {title} | conf={confidence:.2f} | "
            f"{status} | tags={', '.join(tag_list[:4]) if tag_list else 'none'}",
            180,
        ),
        "content_preview": clip(entry.get("content") or "", 180) if entry.get("content") else "",
    }


def entry_collection_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize a list/search result set for the ``summary`` key."""
    categories = Counter(str(e.get("category") or "general") for e in entries)
    source_types = Counter(str(e.get("source_type") or "manual") for e in entries)
    briefs = [entry_brief(e) for e in entries[:10]]
    return {
        "count": len(entries),
        "categories": dict(categories),
        "source_types": dict(source_types),
        "top_titles": [b["title"] for b in briefs[:5] if b.get("title")],
        "briefs": briefs,
    }


def _priority_value(target: dict[str, Any]) -> Any:
    priority = target.get("priority_score")
    if priority is None:
        priority = target.get("priority")
    return priority


def target_collection_summary(targets: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize ``next_target`` targets for the ``summary`` key."""
    if not targets:
        return {"count": 0, "briefs": []}
    briefs = []
    for target in targets[:10]:
        addr = str(target.get("addr") or target.get("address") or "").strip()
        title = str(target.get("title") or target.get("name") or "").strip()
        parts = [addr or "no-addr", title or "unnamed"]
        if target.get("confidence") is not None:
            parts.append(f"conf={float(target.get('confidence') or 0.0):.2f}")
        priority = _priority_value(target)
        if priority is not None:
            parts.append(f"priority={float(priority or 0.0):.3f}")
        if target.get("semantic_similarity") is not None:
            parts.append(f"semantic={float(target.get('semantic_similarity') or 0.0):.3f}")
        if target.get("xref_count") is not None:
            parts.append(f"xrefs={int(target.get('xref_count') or 0)}")
        if target.get("entropy") is not None:
            parts.append(f"entropy={float(target.get('entropy') or 0.0):.2f}")
        briefs.append(
            {
                "addr": addr or None,
                "title": title,
                "category": target.get("category"),
                "summary": " | ".join(parts),
            }
        )
    best = targets[0]
    return {
        "count": len(targets),
        "best_addr": best.get("addr") or best.get("address"),
        "best_title": best.get("title"),
        "briefs": briefs,
    }


def frontier_collection_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize ``frontier`` results for the ``summary`` key."""
    if not results:
        return {"count": 0, "briefs": []}
    briefs = []
    for row in results[:10]:
        addr = str(row.get("addr") or row.get("address") or "").strip()
        name = str(row.get("name") or row.get("title") or "").strip()
        pieces = [addr or "no-addr", name or "unnamed"]
        if row.get("score") is not None:
            pieces.append(f"score={float(row.get('score') or 0.0):.3f}")
        if row.get("proximity") is not None:
            pieces.append(f"prox={float(row.get('proximity') or 0.0):.3f}")
        if row.get("nearest_label_title"):
            pieces.append(f"near={clip(row.get('nearest_label_title'), 40)}")
        briefs.append(
            {
                "addr": addr or None,
                "name": name,
                "summary": " | ".join(pieces),
            }
        )
    return {"count": len(results), "briefs": briefs}


def proposal_collection_summary(proposals: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize crawler proposals for display to the model."""
    if not proposals:
        return {"count": 0, "briefs": []}
    briefs = []
    for p in proposals[:10]:
        briefs.append(
            {
                "proposal_id": p.get("proposal_id"),
                "addr": p.get("addr"),
                "title": p.get("title"),
                "summary": clip(
                    f"{p.get('proposal_id')} | {p.get('addr') or 'no-addr'} | "
                    f"{p.get('title') or ''} | conf={float(p.get('confidence') or 0.0):.2f}",
                    180,
                ),
            }
        )
    return {"count": len(proposals), "briefs": briefs}


def ensure_dual_keys(targets: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Guarantee every target carries BOTH the ``address`` and ``addr`` key.

    The store's ``coverage``/``frontier`` builders emit ``address`` while the
    legacy tool surface and the crawler read ``addr``; ``next_target`` keeps
    both spellings. This normalizer copies each target so callers never get
    their input mutated, and the address value is never ``None`` when the
    other spelling is present.
    """
    out: list[dict[str, Any]] = []
    for target in targets:
        item = dict(target or {})
        address = item.get("address")
        addr = item.get("addr")
        if address is None and addr is not None:
            item["address"] = addr
        elif addr is None and address is not None:
            item["addr"] = address
        out.append(item)
    return out


def strategy_note(strategy: str, has_targets: bool) -> str:
    """Compose the human-readable note for a target strategy.

    The strategy's plain-language description is always present; when nothing
    matched, a second sentence turns the empty result into a positive signal.
    """
    note = STRATEGY_NOTES.get(strategy, "")
    if not has_targets:
        note += STRATEGY_EMPTY_NOTES.get(strategy, " Nothing matched this strategy.")
    return note.strip()


def list_response(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Canonical ``list`` response: ``{ok, entries, count, summary}``."""
    return {
        "ok": True,
        "entries": entries,
        "count": len(entries),
        "summary": entry_collection_summary(entries),
    }


def search_response(query: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Canonical ``search`` response: ``{ok, query, entries, count, summary}``.

    The key is ``entries`` — never ``results``, which the legacy IDA-side
    dispatcher used and which is deliberately dropped here.
    """
    return {
        "ok": True,
        "query": str(query or ""),
        "entries": entries,
        "count": len(entries),
        "summary": entry_collection_summary(entries),
    }


def read_response(entry: dict[str, Any]) -> dict[str, Any]:
    """Canonical ``read`` response: ``{ok, entry, summary}``."""
    return {"ok": True, "entry": entry, "summary": entry_brief(entry)}


def write_response(
    result: dict[str, Any],
    action: str = "write",
    gravity: dict[str, Any] | None = None,
    phase: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Canonical ``write`` response.

    ``result`` is the store write result (``{entry_id, created, ...}``).
    ``gravity`` is a bounded snapshot (see :func:`gravity_snapshot`); when the
    write merged into an existing entry, ``created`` is false and gravity is
    pinned to not fire.
    """
    created = bool(result.get("created"))
    return {
        "ok": True,
        "entry_id": result.get("entry_id"),
        "created": created,
        "action": action,
        "gravity": gravity if created else None,
        "phase": phase,
    }


def gravity_snapshot(
    items: list[Any] | None,
    note: str = "",
    entry_id: str = "",
    max_items: int = GRAVITY_MAX_ITEMS,
) -> dict[str, Any]:
    """Bound a gravity/evidence snapshot to a small, LLM-safe shape.

    Returns ``{items, note, entry_id}`` with at most ``max_items`` items. The
    raw evidence is stored in the machinery table by the handler; this is the
    response-carried view only.
    """
    bounded = items if isinstance(items, list) else []
    return {
        "items": bounded[: max(0, int(max_items))],
        "note": str(note or ""),
        "entry_id": str(entry_id or ""),
    }


def next_target_response(
    strategy: str,
    targets: list[dict[str, Any]],
    strategies: Iterable[str] = STRATEGIES,
    note: str | None = None,
    query: str | None = None,
) -> dict[str, Any]:
    """Canonical ``next_target`` response.

    Every target is normalized to carry BOTH ``address`` and ``addr`` (pinned
    by the keep=true contracts). ``strategies`` lists the available strategy
    names so the model can branch; when ``query`` was supplied the targets
    were reordered (never dropped) and the response says so.
    """
    normalized = ensure_dual_keys(targets)
    if note is None:
        note = strategy_note(strategy, has_targets=bool(normalized))
    payload: dict[str, Any] = {
        "ok": True,
        "strategy": str(strategy or "").strip().lower() or "unresolved",
        "targets": normalized,
        "count": len(normalized),
        "summary": target_collection_summary(normalized),
        "note": str(note or "").strip(),
        "strategies": list(strategies),
    }
    if query and str(query).strip():
        payload["query_ranking"] = "keyword overlap; candidates are reordered, never dropped"
    return payload


def frontier_response(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Canonical ``frontier`` response: ``{ok, frontier, count, summary}``.

    ``frontier`` is always a list — never a joined string, which the legacy
    IDA-side dispatcher produced for one caller.
    """
    normalized = ensure_dual_keys(results)
    return {
        "ok": True,
        "frontier": normalized,
        "count": len(normalized),
        "summary": frontier_collection_summary(normalized),
    }


def coverage_response(
    analyzed: int,
    total: int,
    note: str = COVERAGE_NOTE,
) -> dict[str, Any]:
    """Canonical ``coverage`` response.

    ``analyzed`` is the count of addresses with a recorded examination or
    finding; ``total`` is the workspace entry count. The percentage is rounded
    to one decimal; the note is honest about the metric's limits.
    """
    total = max(0, int(total))
    analyzed = max(0, int(analyzed))
    coverage_pct = round(analyzed / max(1, total) * 100.0, 1) if total else 0.0
    return {
        "ok": True,
        "coverage_pct": coverage_pct,
        "total_entries": total,
        "analyzed": analyzed,
        "unvisited": max(0, total - analyzed),
        "note": str(note or COVERAGE_NOTE),
    }


def crawler_status_response(
    running: bool,
    pending_proposals: int,
    addresses_visited: int,
    proposals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Canonical ``crawler_status`` response.

    The legacy ``proposals_pending`` alias key is deliberately absent; the
    canonical key is ``pending_proposals``. ``proposals`` carries the raw
    proposal dicts (each with a real store ``entry_id`` of a ``proposed``
    finding).
    """
    return {
        "ok": True,
        "running": bool(running),
        "pending_proposals": max(0, int(pending_proposals or 0)),
        "addresses_visited": max(0, int(addresses_visited or 0)),
        "proposals": proposals if isinstance(proposals, list) else [],
    }


# ---------------------------------------------------------------------------
# findings-v1 export renderers
# ---------------------------------------------------------------------------


def strip_export_fields(entry: dict[str, Any]) -> dict[str, Any]:
    """Drop internal storage fields from one entry and expose ``entry_id``.

    The export format is the public investigation record; embedding blobs,
    fingerprints, and decay bookkeeping are not part of it.
    """
    clean = {k: v for k, v in (entry or {}).items() if k not in EXPORT_DROP_FIELDS}
    clean["entry_id"] = str(clean.get("id") or "")
    return clean


def build_export_snapshot(
    entries: list[dict[str, Any]],
    stats: dict[str, Any] | None = None,
    exported_at: str | None = None,
) -> dict[str, Any]:
    """Assemble the ``ida-findings-v1`` snapshot dict.

    ``stats`` is the store's ``stats()`` result (or a dict with at least
    ``total_entries``/``resolved``/``contradicted``/``stale``). Each entry is
    stripped of internal storage fields before being included.
    """
    stats = stats or {}
    return {
        "format": EXPORT_FORMAT_VERSION,
        "exported_at": exported_at or datetime.now(UTC).isoformat(timespec="seconds"),
        "stats": {
            "total_entries": int(stats.get("total_entries") or 0),
            "resolved": int(stats.get("resolved") or 0),
            "contradicted": int(stats.get("contradicted") or 0),
            "stale": int(stats.get("stale") or 0),
        },
        "entries": [strip_export_fields(e) for e in (entries or [])],
    }


def snapshot_to_json(snapshot: dict[str, Any]) -> str:
    """Render an export snapshot as indented JSON."""
    return json.dumps(snapshot, indent=2, ensure_ascii=False)


def snapshot_to_markdown(snapshot: dict[str, Any]) -> str:
    """Render an export snapshot as a human-readable Markdown report.

    Entries are grouped by kind (finding, hypothesis, question, task,
    decision, examined) and then by lifecycle status, with evidence listed
    inline. Unknown kinds and statuses are appended in order so no entry is
    ever dropped from a report.
    """
    lines = ["# IDA Findings Export", ""]
    lines.append(
        f"Exported {snapshot.get('exported_at', '')} · format "
        f"{snapshot.get('format', '')}"
    )
    stats = snapshot.get("stats") or {}
    lines.append(
        f"Entries: {stats.get('total_entries', 0)} · resolved "
        f"{stats.get('resolved', 0)} · contradicted "
        f"{stats.get('contradicted', 0)} · stale {stats.get('stale', 0)}"
    )
    lines.append("")

    by_kind: dict[str, list[dict[str, Any]]] = {}
    for entry in snapshot.get("entries") or []:
        by_kind.setdefault(str(entry.get("kind") or "finding"), []).append(entry)

    for kind in EXPORT_KIND_ORDER:
        group = by_kind.pop(kind, None)
        if group is None:
            continue
        lines.append(f"## {kind} ({len(group)})")
        lines.append("")
        by_status: dict[str, list[dict[str, Any]]] = {}
        for entry in group:
            by_status.setdefault(str(entry.get("status") or "open"), []).append(entry)
        for status in EXPORT_STATUS_ORDER:
            subgroup = by_status.pop(status, None)
            if subgroup is None:
                continue
            lines.append(f"### {status}")
            for entry in subgroup:
                addr = str(entry.get("addr") or "").strip() or "no-addr"
                title = str(entry.get("title") or "").strip() or "(untitled)"
                lines.append(f"- **[{addr}] {title}**")
                meta = [f"conf={float(entry.get('confidence') or 0.0):.2f}"]
                priority = entry.get("priority")
                if priority is not None:
                    meta.append(f"priority={float(priority):.2f}")
                tags = entry.get("tags") or []
                if isinstance(tags, list) and tags:
                    meta.append("tags=" + ", ".join(str(t) for t in tags[:8]))
                source = str(entry.get("source_type") or "manual")
                meta.append(f"source={source}")
                if entry.get("stale"):
                    meta.append("STALE: " + str(entry.get("stale_reason") or ""))
                conflicts = entry.get("conflicts_with") or []
                if isinstance(conflicts, list) and conflicts:
                    meta.append("contradicts=" + ",".join(str(c) for c in conflicts))
                lines.append(f"  - {', '.join(meta)}")
                content = str(entry.get("content") or "").strip()
                if content:
                    lines.append("")
                    lines.append(f"  > {content}")
                evidence = entry.get("evidence") or []
                if isinstance(evidence, list) and evidence:
                    lines.append("")
                    for ev in evidence[:12]:
                        ev_addr = str(ev.get("address") or "")
                        loc = f" @ {ev_addr}" if ev_addr else ""
                        lines.append(
                            f"  - evidence: [{ev.get('type')}] {str(ev.get('value') or '')}{loc}"
                        )
            lines.append("")
        for status, subgroup in by_status.items():
            lines.append(f"### {status}")
            for entry in subgroup:
                lines.append(f"- {str(entry.get('title') or '(untitled)')}")
            lines.append("")
    for kind, group in by_kind.items():
        lines.append(f"## {kind} ({len(group)})")
        lines.append("")
        for entry in group:
            lines.append(f"- {str(entry.get('title') or '(untitled)')}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"
