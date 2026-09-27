"""Round-trip between the investigation workspace and the IDB itself.

The IDB is the artifact an analyst actually opens. A conclusion that lives
only in a side database is a conclusion nobody outside this tool ever sees,
and a name an analyst applied by hand is understanding this tool never had.
Two directions close that loop:

``publish``
    Confirmed, addressed claims are written into the database as repeatable
    comments, and — where the function is still auto-named — as symbols. This
    mutates the IDB, so it is gated behind ``risk_ack`` like every other write.

``import``
    Existing names and comments are adopted as confirmed findings, so a
    session inherits whatever the last analyst left behind.

Each published comment carries an ``[mcp:<id>]`` marker. The import side skips
anything carrying one: adopting our own output back would turn a single claim
into a second, independent-looking corroboration of itself.
"""

from __future__ import annotations

from typing import Any

from ..config import _bounded_int
from ..errors import MCPError, is_error_result, make_error
from ..stores.blackboard_store import entry_id_in, is_auto_name, normalize_addr, symbol_from_title

#: Bound on one publish/import call. Both walk the IDB per item, so an
#: unbounded run would stall the session behind hundreds of round trips.
MAX_BATCH = 200

#: The IDA-side batch tool refuses more than this many calls per request
#: (ida_mcp/tools/batch.py), so a "batch" symbol lookup must be chunked below
#: this bound or the optimization silently degenerates to one sequential RPC
#: per address.
IDA_BATCH_MAX_CALLS = 20

#: Sentinel for "the current name could not be read". Distinct from "" (no
#: name / auto-named): both would otherwise collapse to "" and _plan_rename
#: would SN_FORCE-rename an analyst-applied symbol it never saw.
_UNREADABLE = object()


class ServerBlackboardIdbMixin:
    """Publish findings into the IDB and adopt what is already there."""

    def _idb_rpc(self):
        """Return a callable into the live IDA session, or None."""
        session = getattr(self, "current_session", None)
        idb_ref = str(getattr(session, "idb_path", "") or "") if session else ""
        if not idb_ref:
            return None

        def rpc(tool: str, payload: dict[str, Any]):
            return self.call_tool(tool, idb_ref, **payload)

        return rpc

    def _current_symbol(self, rpc, addr: str) -> str | object:
        """Read the name currently applied at an address.

        Returns the name (possibly "") — or the :data:`_UNREADABLE` sentinel
        when the lookup did not succeed: an RPC exception, an error envelope,
        or a response with no ``name`` key. Callers must never rename based on
        a failed read: treating it as "" would let a blind SN_FORCE rename
        clobber a name an analyst applied by hand.
        """
        try:
            result = rpc("data", {"action": "lookup", "query": addr})
        except Exception:
            return _UNREADABLE
        if not isinstance(result, dict) or is_error_result(result):
            return _UNREADABLE
        if "name" not in result:
            return _UNREADABLE
        return str(result.get("name") or "")

    def _current_symbols_batch(self, rpc, addrs: list[str]) -> dict[str, str | object]:
        """Read names currently applied across many addresses in few round trips.

        Chunks into sub-batches of at most :data:`IDA_BATCH_MAX_CALLS` so the
        batching actually applies: the IDA-side batch tool rejects larger
        requests, which would silently fall back to one sequential RPC per
        address. A failed per-address read maps to the :data:`_UNREADABLE`
        sentinel, never to "".
        """
        if not addrs:
            return {}
        unique_addrs = sorted(set(addrs))
        if len(unique_addrs) == 1:
            addr = unique_addrs[0]
            return {addr: self._current_symbol(rpc, addr)}

        mapping: dict[str, str | object] = {}
        for chunk_start in range(0, len(unique_addrs), IDA_BATCH_MAX_CALLS):
            chunk = unique_addrs[chunk_start:chunk_start + IDA_BATCH_MAX_CALLS]
            if len(chunk) == 1:
                mapping[chunk[0]] = self._current_symbol(rpc, chunk[0])
                continue
            batch_calls = [{"tool": "data", "action": "lookup", "query": addr} for addr in chunk]
            try:
                res = rpc("batch", {"calls": batch_calls})
                if isinstance(res, dict) and not is_error_result(res):
                    results = res.get("results") or res.get("calls") or []
                    if isinstance(results, list) and len(results) == len(chunk):
                        for addr, item in zip(chunk, results, strict=False):
                            if not isinstance(item, dict) or is_error_result(item):
                                mapping[addr] = _UNREADABLE
                                continue
                            sub_res = item.get("result", item)
                            if isinstance(sub_res, dict) and "name" in sub_res:
                                mapping[addr] = str(sub_res.get("name") or "")
                            else:
                                mapping[addr] = _UNREADABLE
                        continue
            except Exception:
                pass
            for addr in chunk:
                mapping[addr] = self._current_symbol(rpc, addr)
        return mapping

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _publish_findings(self, store, args: dict) -> dict:
        rpc = self._idb_rpc()
        if rpc is None:
            return make_error(
                MCPError.SESSION_NOT_FOUND,
                "Publishing writes to the IDB and needs an open session. Call ida_open_binary first.",
            )
        dry_run = bool(args.get("dry_run", False))
        if not dry_run and not args.get("_risk_ack"):
            return make_error(
                MCPError.INVALID_ARGS,
                "Publishing modifies the IDB. Pass risk_ack=true, or dry_run=true to preview.",
            )
        rename = bool(args.get("rename", True))
        limit = _bounded_int(args.get("limit", 25), 25, min_value=1, max_value=MAX_BATCH)

        entries = store.publishable(
            limit=limit, include_published=bool(args.get("republish", False))
        )
        published: list[dict] = []
        skipped: list[dict] = []

        if rename and entries:
            addrs = [str(e.get("addr") or "") for e in entries if e.get("addr")]
            current_symbols = self._current_symbols_batch(rpc, addrs)
        else:
            current_symbols = {}

        # One repeatable-comment slot holds one claim per address. Publishing
        # several entries at the same address would overwrite each other's
        # comment (last wins): the earlier [mcp:<id>] markers would vanish
        # while those entries were still marked published — so they could
        # never be re-adopted by import and never be republished. Publish the
        # first (highest-confidence) entry per address; record the rest as
        # skipped rather than silently losing them.
        handled_addrs: set[str] = set()
        for entry in entries:
            addr = str(entry.get("addr") or "")
            record: dict[str, Any] = {"entry_id": entry.get("id"), "address": addr,
                                      "title": entry.get("title")}
            comment = store.comment_for(entry)
            record["comment"] = comment

            if addr in handled_addrs:
                skipped.append({**record, "error": "address already published this run"})
                continue
            handled_addrs.add(addr)

            symbol = ""
            if rename:
                curr_sym = current_symbols.get(addr)
                symbol, reason = self._plan_rename(rpc, entry, addr, current_symbol=curr_sym)
                if symbol:
                    record["symbol"] = symbol
                elif reason:
                    record["rename_skipped"] = reason

            if dry_run:
                published.append(record)
                continue

            comment_result = self._apply(
                rpc, "comment", addr, comment, comment_type="repeatable"
            )
            if comment_result is not None:
                # The comment never landed: never mark the entry published, or
                # it would silently never be re-attempted.
                skipped.append({**record, "error": comment_result})
                continue
            if symbol:
                rename_result = self._apply(rpc, "rename", addr, symbol)
                if rename_result is not None:
                    # The comment landed; only the symbol failed. Say so
                    # rather than reporting the whole entry as published.
                    record["rename_failed"] = rename_result
                    record.pop("symbol", None)
                    symbol = ""
            store.mark_published(str(entry["id"]), symbol)
            published.append(record)

        payload = {
            "ok": True,
            "action": "publish_findings",
            "dry_run": dry_run,
            "published": published,
            "count": len(published),
            "note": (
                "Preview only; nothing was written." if dry_run else
                "Written to the IDB as repeatable comments"
                + (" and symbols." if rename else ".")
            ),
        }
        if skipped:
            payload["failed"] = skipped
        if not entries:
            payload["note"] = (
                "Nothing to publish. Only confirmed, non-stale, non-conflicting "
                "findings with an address are eligible, and each is published once "
                "unless it changes. Pass republish=true to rewrite them."
            )
        return payload

    def _plan_rename(
        self, rpc, entry: dict, addr: str, current_symbol: str | object | None = None
    ) -> tuple[str, str]:
        """Decide whether to rename, returning (symbol, reason_if_not).

        A name that is not auto-generated is left alone: it is either an
        analyst's own work or a library signature match, and overwriting
        either with a slug of a finding title destroys more than it adds.

        When the current name could not be read, the rename is skipped too:
        SN_FORCE-renaming from a failed lookup can destroy a name we never
        saw. The caller records ``record['rename_skipped']='could not read
        current symbol'`` from the returned reason.
        """
        symbol = symbol_from_title(str(entry.get("title") or ""))
        if not symbol:
            return "", "title yields no usable identifier"
        if current_symbol is None:
            current_symbol = self._current_symbol(rpc, addr)
        if current_symbol is _UNREADABLE:
            return "", "could not read current symbol"
        if current_symbol and not is_auto_name(current_symbol):
            if current_symbol == symbol:
                return "", "already named"
            return "", f"already named {current_symbol!r}; not overwriting an existing symbol"
        return symbol, ""

    def _apply(self, rpc, action: str, addr: str, value: str, **extra) -> str | None:
        """Run one IDB mutation. Returns an error string, or None on success."""
        try:
            result = rpc("modify", {
                "action": action, "addr": addr, "value": value, "_risk_ack": True, **extra
            })
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"[:200]
        if not isinstance(result, dict) or is_error_result(result) or result.get("ok") is not True:
            # Anything that is not an ok dict — an error envelope, a malformed
            # response, or a missing/None result — is a failure. Reporting it
            # as success would fabricate a published record for a write that
            # never happened.
            if isinstance(result, dict):
                detail = result.get("message") or result.get("code") or result
            else:
                detail = result
            return str(detail)[:200]
        return None

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def _import_annotations(self, store, args: dict) -> dict:
        rpc = self._idb_rpc()
        if rpc is None:
            return make_error(
                MCPError.SESSION_NOT_FOUND,
                "Reading IDB annotations needs an open session. Call ida_open_binary first.",
            )
        limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=MAX_BATCH)
        try:
            result = rpc("data", {"action": "annotations", "count": limit,
                                  "offset": _bounded_int(args.get("offset", 0), 0, min_value=0)})
        except Exception as exc:
            return make_error(MCPError.IDA_ERROR, f"Could not read annotations: {exc}")
        if not isinstance(result, dict) or is_error_result(result):
            return make_error(
                MCPError.IDA_ERROR,
                "The IDA side does not support reading annotations. Reinstall the plugin "
                "so `data(action='annotations')` is available.",
            )

        rows = result.get("annotations")
        if not isinstance(rows, list):
            rows = []
        imported: list[dict] = []
        skipped_no_addr = 0
        skipped_own = 0
        skipped_no_content = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            addr = str(row.get("addr") or "")
            name = str(row.get("name") or "")
            comment = str(row.get("repeatable_comment") or row.get("comment") or "")
            # Mirror the store's own adoption gate so the three distinct
            # skip reasons are reported separately instead of being lumped
            # together as "skipped our own output".
            naddr = normalize_addr(addr)
            if not naddr:
                skipped_no_addr += 1
                continue
            if entry_id_in(comment):
                skipped_own += 1
                continue
            if is_auto_name(name) and not comment.strip():
                skipped_no_content += 1
                continue
            outcome = store.adopt_annotation(addr=naddr, name=name, comment=comment)
            if outcome is None:
                # Defensive: the store's gate refused a row this loop did not
                # reproduce. Never count it as our own marker; treat it as
                # "no content worth adopting".
                skipped_no_content += 1
                continue
            imported.append({
                "entry_id": outcome["entry_id"],
                "address": row.get("addr"),
                "name": row.get("name"),
                "created": outcome["created"],
            })

        created = sum(1 for item in imported if item["created"])
        payload = {
            "ok": True,
            "action": "import_annotations",
            "imported": imported,
            "count": len(imported),
            "created": created,
            "merged": len(imported) - created,
            "total_available": result.get("total", len(rows)),
            "note": (
                "Adopted as confirmed findings at confidence 0.5: someone recorded "
                "these deliberately, but this tool did not verify them and cannot "
                "distinguish an analyst's rename from a library signature match."
            ),
        }
        if skipped_own:
            payload["skipped_own_annotations"] = skipped_own
        if skipped_no_addr:
            payload["skipped_no_addr"] = skipped_no_addr
        if skipped_no_content:
            payload["skipped_no_content"] = skipped_no_content
        return payload
