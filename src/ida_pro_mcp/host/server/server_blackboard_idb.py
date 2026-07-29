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
from ..stores.blackboard_store import is_auto_name, symbol_from_title

#: Bound on one publish/import call. Both walk the IDB per item, so an
#: unbounded run would stall the session behind hundreds of round trips.
MAX_BATCH = 200


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

    def _current_symbol(self, rpc, addr: str) -> str:
        """Read the name currently applied at an address."""
        try:
            result = rpc("data", {"action": "lookup", "query": addr})
        except Exception:
            return ""
        if not isinstance(result, dict) or is_error_result(result):
            return ""
        return str(result.get("name") or "")

    def _current_symbols_batch(self, rpc, addrs: list[str]) -> dict[str, str]:
        """Read names currently applied across multiple addresses in a single batch."""
        if not addrs:
            return {}
        unique_addrs = sorted(set(addrs))
        if len(unique_addrs) == 1:
            addr = unique_addrs[0]
            return {addr: self._current_symbol(rpc, addr)}

        batch_calls = [{"tool": "data", "action": "lookup", "query": addr} for addr in unique_addrs]
        try:
            res = rpc("batch", {"calls": batch_calls})
            if isinstance(res, dict) and not is_error_result(res):
                results = res.get("results") or res.get("calls") or []
                if isinstance(results, list) and len(results) == len(unique_addrs):
                    mapping = {}
                    for addr, item in zip(unique_addrs, results, strict=False):
                        if isinstance(item, dict) and not is_error_result(item):
                            sub_res = item.get("result", item)
                            if isinstance(sub_res, dict):
                                mapping[addr] = str(sub_res.get("name") or "")
                            else:
                                mapping[addr] = ""
                        else:
                            mapping[addr] = ""
                    return mapping
        except Exception:
            pass

        return {addr: self._current_symbol(rpc, addr) for addr in unique_addrs}

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

        for entry in entries:
            addr = str(entry.get("addr") or "")
            record: dict[str, Any] = {"entry_id": entry.get("id"), "address": addr,
                                      "title": entry.get("title")}
            comment = store.comment_for(entry)
            record["comment"] = comment

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
        self, rpc, entry: dict, addr: str, current_symbol: str | None = None
    ) -> tuple[str, str]:
        """Decide whether to rename, returning (symbol, reason_if_not).

        A name that is not auto-generated is left alone: it is either an
        analyst's own work or a library signature match, and overwriting
        either with a slug of a finding title destroys more than it adds.
        """
        symbol = symbol_from_title(str(entry.get("title") or ""))
        if not symbol:
            return "", "title yields no usable identifier"
        if current_symbol is None:
            current_symbol = self._current_symbol(rpc, addr)
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
        if isinstance(result, dict) and is_error_result(result):
            # `error` is the boolean flag, not the text; reporting it would
            # hand the caller the string "True" instead of what went wrong.
            detail = result.get("message") or result.get("code") or result
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
        skipped_own = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            comment = str(row.get("repeatable_comment") or row.get("comment") or "")
            outcome = store.adopt_annotation(
                addr=str(row.get("addr") or ""),
                name=str(row.get("name") or ""),
                comment=comment,
            )
            if outcome is None:
                skipped_own += 1
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
        return payload
