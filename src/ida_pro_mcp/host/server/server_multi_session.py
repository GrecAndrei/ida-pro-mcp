#!/usr/bin/env python3
"""Multi-session group management for cross-binary analysis.

Provides the ServerMultiSessionMixin which enables linking multiple IDA sessions
together into a group, resolving cross-binary imports/exports, and forwarding
tool calls (e.g. decompile) to the session that owns a given symbol.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from copy import deepcopy
from typing import Any

from ..config import log_rpc
from ..errors import MCPError, make_error


class SessionGroup:
    """A group of linked sessions for cross-binary analysis."""

    def __init__(self, group_id: str, name: str = ""):
        self.group_id = group_id
        self.name = name or group_id
        self.session_ids: list[str] = []
        # import_name -> {"provider_sid": str, "export_ea": str, "importer_sids": [str]}
        self.links: dict[str, dict[str, Any]] = {}
        self.metadata: dict[str, Any] = {}

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "name": self.name,
            "session_ids": list(self.session_ids),
            "link_count": len(self.links),
            # Return an isolated snapshot. Persistence serializes after
            # releasing the group lock, and callers may retain/inspect the
            # response while another connection mutates the live group.
            "links": deepcopy(self.links),
            "metadata": deepcopy(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SessionGroup":
        """Rebuild a group from a persisted ``to_dict`` snapshot.

        Used to rehydrate ``groups.json`` at host startup so ``group_id``
        references survive a restart (D3-F9). Unknown keys are dropped and
        malformed link rows are skipped defensively.
        """
        group = cls(str(data.get("group_id") or ""), str(data.get("name") or ""))
        raw_sids = data.get("session_ids") or []
        if isinstance(raw_sids, list):
            group.session_ids = [str(s) for s in raw_sids if s]
        links = data.get("links")
        if isinstance(links, dict):
            for name, link in links.items():
                if isinstance(link, dict):
                    group.links[str(name)] = dict(link)
        meta = data.get("metadata")
        if isinstance(meta, dict):
            group.metadata = dict(meta)
        return group


class ServerMultiSessionMixin:
    """Mixin for IDAMCPServer providing multi-session group management.

    Sessions in a group can have their imports and exports cross-linked, allowing
    transparent resolution of inter-binary references and cross-session decompilation.
    """

    _session_groups: dict[str, SessionGroup]
    _multi_session_init_lock = threading.Lock()

    def _init_multi_session(self) -> None:
        """Initialize multi-session state. Call from server __init__.

        ``_session_groups`` is guarded by ``_session_groups_lock``: daemon mode
        serves each connection in its own thread, and the create/remove/list/
        cross_* handlers mutate or iterate the dict (and group.links) without
        any other synchronization, which can raise ``RuntimeError: dictionary
        changed size during iteration`` under concurrent access.

        Groups are persisted to ``cache_dir/groups.json`` on every mutation and
        rehydrated here (first init only) so ``group_id`` references survive a
        host restart (D3-F9).
        """
        with self._multi_session_init_lock:
            first_init = not isinstance(getattr(self, "_session_groups", None), dict)
            if first_init:
                self._session_groups = {}
            if getattr(self, "_session_groups_lock", None) is None:
                self._session_groups_lock = threading.RLock()
            if getattr(self, "_groups_persist_lock", None) is None:
                self._groups_persist_lock = threading.Lock()
        if first_init:
            self._load_groups_from_disk()

    # ------------------------------------------------------------------
    # Group persistence (survive host restarts)
    # ------------------------------------------------------------------

    def _groups_path(self) -> str | None:
        cache_dir = getattr(self, "cache_dir", None)
        if not cache_dir:
            return None
        return os.path.join(str(cache_dir), "groups.json")

    def _load_groups_from_disk(self) -> None:
        path = self._groups_path()
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            log_rpc(f"Failed to load session groups from {path}: {e}")
            return
        raw = data if isinstance(data, list) else data.get("groups", [])
        if not isinstance(raw, list):
            return
        loaded = 0
        with self._session_groups_lock:
            for entry in raw:
                if not isinstance(entry, dict):
                    continue
                try:
                    group = SessionGroup.from_dict(entry)
                except Exception:
                    continue
                if not group.group_id:
                    continue
                self._session_groups[group.group_id] = group
                loaded += 1
        if loaded:
            log_rpc(f"Rehydrated {loaded} session group(s) from {path}")

    def _persist_groups(self) -> None:
        path = self._groups_path()
        if not path:
            return
        self._init_multi_session()
        # Serialize the snapshot through os.replace as one transaction. If a
        # second mutation snapshots while the first writer is still replacing
        # the file, an older snapshot can otherwise win the race and erase the
        # newer group's update.
        with self._groups_persist_lock:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                # Pid-scoped tmp so concurrent hosts sharing one cache never
                # write into each other's temp file; os.replace is atomic.
                tmp = f"{path}.{os.getpid()}.tmp"
                with self._session_groups_lock:
                    payload = [g.to_dict() for g in self._session_groups.values()]
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                    f.flush()
                os.replace(tmp, path)
            except Exception as e:
                log_rpc(f"Failed to persist session groups to {path}: {e}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_group(self, group_id: str) -> SessionGroup | None:
        """Look up a group by ID."""
        self._init_multi_session()
        with self._session_groups_lock:
            return self._session_groups.get(group_id)

    def _require_group(self, args: dict) -> tuple[SessionGroup | None, dict | None]:
        """Extract and validate group_id from args. Returns (group, error)."""
        group_id = str(args.get("group_id") or "").strip()
        if not group_id:
            return None, make_error(MCPError.INVALID_ARGS, "group_id required")
        group = self._get_group(group_id)
        if group is None:
            return None, make_error(
                MCPError.NOT_FOUND,
                f"Session group '{group_id}' not found",
                hint=(
                    "Use multi_session(action='group_list') to see available "
                    "groups. Note: groups are persisted in the host cache and "
                    "survive restarts; if this group predates persistence or "
                    "the cache was cleared it may have been lost on restart."
                ),
            )
        return group, None

    def _drop_sid_from_groups(self, sid: str) -> None:
        """Remove *sid* from every group (membership + link table).

        Called when a session is deleted so groups never retain references to
        nonexistent sessions — otherwise ``cross_*`` operations dispatch to
        sessions that no longer exist.
        """
        if not hasattr(self, "_session_groups"):
            return
        lock = getattr(self, "_session_groups_lock", None)
        if lock is None:
            return
        with lock:
            for group in list(self._session_groups.values()):
                if sid in group.session_ids:
                    group.session_ids = [s for s in group.session_ids if s != sid]
                if any(
                    link.get("provider_sid") == sid
                    for link in group.links.values()
                ):
                    group.links = {
                        name: link for name, link in group.links.items()
                        if link.get("provider_sid") != sid
                    }
                for link in group.links.values():
                    if sid in link.get("importer_sids", []):
                        link["importer_sids"] = [
                            s for s in link["importer_sids"] if s != sid
                        ]
        self._persist_groups()

    def _dispatch_to_session(self, session_id: str, tool: str, tool_args: dict) -> dict:
        """Dispatch a tool call to a specific session's IDA runtime.

        Uses the server's existing call_tool infrastructure which handles
        runtime start, RPC dispatch, and error recovery.
        """
        # call_tool accepts session_id as the idb_path reference
        return self.call_tool(tool, session_id, **tool_args)

    # ------------------------------------------------------------------
    # Public action handler
    # ------------------------------------------------------------------

    def _handle_multi_session(self, action: str, args: dict) -> dict:
        """Dispatch multi-session actions."""
        self._init_multi_session()

        handlers = {
            "group_create": self._ms_group_create,
            "group_list": self._ms_group_list,
            "group_link": self._ms_group_link,
            "group_remove": self._ms_group_remove,
            "cross_resolve": self._ms_cross_resolve,
            "cross_decompile": self._ms_cross_decompile,
            "cross_xrefs": self._ms_cross_xrefs,
            "status": self._ms_status,
        }

        handler = handlers.get(action)
        if handler is None:
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unknown multi_session action: '{action}'",
                hint=f"Valid actions: {', '.join(sorted(handlers.keys()))}",
            )
        return handler(args)

    # ------------------------------------------------------------------
    # Action implementations
    # ------------------------------------------------------------------

    def _ms_group_create(self, args: dict) -> dict:
        """Create a new session group from given session_ids."""
        session_ids = args.get("session_ids") or []
        if not isinstance(session_ids, list):
            return make_error(MCPError.INVALID_ARGS, "session_ids must be a list")
        if len(session_ids) < 2:
            return make_error(
                MCPError.INVALID_ARGS,
                "At least 2 session_ids required to form a group",
            )

        # Validate that all sessions exist
        valid_sids: list[str] = []
        for raw_sid in session_ids:
            sid = str(raw_sid).strip().upper()
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "Empty session_id in list")
            if not self.session_mgr.session_exists(sid):
                return make_error(
                    MCPError.SESSION_NOT_FOUND,
                    f"Session '{sid}' not found",
                    hint="All sessions in the group must exist. Use ida_session_list.",
                )
            valid_sids.append(sid)

        name = str(args.get("name") or "").strip()
        group_id = str(args.get("group_id") or "").strip() or str(uuid.uuid4())[:8]

        with self._session_groups_lock:
            if group_id in self._session_groups:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Group '{group_id}' already exists. Use group_remove first or pick a new id.",
                )

            group = SessionGroup(group_id=group_id, name=name or group_id)
            group.session_ids = valid_sids
            if args.get("metadata") and isinstance(args["metadata"], dict):
                group.metadata = args["metadata"]

            self._session_groups[group_id] = group
        self._persist_groups()
        with self._session_groups_lock:
            snapshot = group.to_dict()
        return {"ok": True, "group": snapshot}

    def _ms_group_list(self, args: dict) -> dict:
        """List all session groups."""
        with self._session_groups_lock:
            groups = [g.to_dict() for g in self._session_groups.values()]
        return {"ok": True, "groups": groups, "count": len(groups)}

    def _ms_group_link(self, args: dict) -> dict:
        """Auto-match imports <-> exports across sessions in a group.

        Calls into each session to retrieve its exports and imports, then
        builds a resolution table mapping import names to provider sessions.
        """
        group, err = self._require_group(args)
        if err:
            return err

        # Snapshot membership under the lock, then perform the potentially
        # slow IDA RPCs without holding it.  A link build can involve many
        # sessions; keeping the lock across those calls previously blocked
        # unrelated group_list/status/remove requests for the whole build.
        with self._session_groups_lock:
            group_id = group.group_id
            session_ids = list(group.session_ids)

        # Gather exports from all sessions.
        # exports_map: symbol_name -> {sid, ea}
        exports_map: dict[str, dict[str, str]] = {}
        export_errors: list[dict[str, str]] = []

        for sid in session_ids:
            result = self._dispatch_to_session(sid, "symbols", {"action": "exports"})
            if isinstance(result, dict) and result.get("error"):
                export_errors.append({"session_id": sid, "error": str(result.get("message", ""))})
                continue
            entries = []
            if isinstance(result, dict):
                entries = result.get("exports") or result.get("entries") or result.get("symbols") or []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name") or "").strip()
                ea = str(entry.get("ea") or entry.get("addr") or entry.get("address") or "")
                if name and name != "":
                    # First provider wins; could be made configurable
                    if name not in exports_map:
                        exports_map[name] = {"provider_sid": sid, "export_ea": ea}

        # Gather imports from all sessions and match against exports.  Keep
        # the result local until every RPC completes so readers never observe
        # a half-built link table.
        import_errors: list[dict[str, str]] = []
        imports_by_sid: dict[str, list[Any]] = {}
        for sid in session_ids:
            result = self._dispatch_to_session(sid, "imports_deep", {"action": "resolve"})
            if isinstance(result, dict) and result.get("error"):
                import_errors.append({"session_id": sid, "error": str(result.get("message", ""))})
                continue
            imports: Any = []
            if isinstance(result, dict):
                imports = result.get("imports") or result.get("entries") or result.get("symbols") or []
            imports_by_sid[sid] = imports if isinstance(imports, list) else []

        built_links: dict[str, dict[str, Any]] = {}
        links_built = 0
        for sid, imports in imports_by_sid.items():
            for imp in imports:
                if not isinstance(imp, dict):
                    continue
                name = str(imp.get("name") or "").strip()
                if not name:
                    continue
                # Match against known exports (skip self-references).
                provider = exports_map.get(name)
                if not provider or provider["provider_sid"] == sid:
                    continue
                link = built_links.setdefault(
                    name,
                    {
                        "provider_sid": provider["provider_sid"],
                        "export_ea": provider["export_ea"],
                        "importer_sids": [],
                    },
                )
                if sid not in link["importer_sids"]:
                    link["importer_sids"].append(sid)
                    links_built += 1

        # Commit only after all RPCs finish. Re-resolve under the lock because
        # a concurrent remove+recreate may have replaced the original object;
        # writing to that stale object would otherwise lose the update. If
        # membership changed, reject the stale result rather than linking a
        # different set of binaries under the new group definition.
        with self._session_groups_lock:
            group = self._session_groups.get(group_id)
            if group is None:
                return make_error(
                    MCPError.NOT_FOUND,
                    f"Session group '{group_id}' not found",
                    hint="The group was removed while linking; re-create it and retry.",
                )
            if list(group.session_ids) != session_ids:
                return make_error(
                    MCPError.CONFLICT,
                    f"Session group '{group_id}' changed while linking",
                    hint="Retry group_link against the current group membership.",
                )
            group.links = built_links
            total_links = len(group.links)

        # Persist the freshly-built link table so cross-session resolution
        # survives a restart without a rebuild.
        self._persist_groups()
        return {
            "ok": True,
            "group_id": group.group_id,
            "links_built": links_built,
            "total_links": total_links,
            "exports_available": len(exports_map),
            "export_errors": export_errors if export_errors else None,
            "import_errors": import_errors if import_errors else None,
        }

    def _ms_group_remove(self, args: dict) -> dict:
        """Remove a session group (does not close sessions)."""
        group_id = str(args.get("group_id") or "").strip()
        if not group_id:
            return make_error(MCPError.INVALID_ARGS, "group_id required")
        with self._session_groups_lock:
            removed = self._session_groups.pop(group_id, None)
        if removed is None:
            return make_error(MCPError.NOT_FOUND, f"Group '{group_id}' not found")
        self._persist_groups()
        return {"ok": True, "removed": removed.to_dict()}

    def _ms_cross_resolve(self, args: dict) -> dict:
        """Resolve an import name to the session + EA that provides it."""
        group, err = self._require_group(args)
        if err:
            return err
        symbol = str(args.get("symbol") or args.get("name") or "").strip()
        if not symbol:
            return make_error(MCPError.INVALID_ARGS, "symbol (or name) required")

        with self._session_groups_lock:
            link = group.links.get(symbol)
            if link is None:
                # Try case-insensitive search
                for lname, ldata in group.links.items():
                    if lname.lower() == symbol.lower():
                        link = ldata
                        symbol = lname
                        break
            link = deepcopy(link) if isinstance(link, dict) else None

        if link is None:
            return make_error(
                MCPError.NOT_FOUND,
                f"Symbol '{symbol}' not linked in group '{group.group_id}'",
                hint="Run multi_session(action='group_link') first to build the resolution table.",
            )
        return {
            "ok": True,
            "symbol": symbol,
            "provider_sid": link["provider_sid"],
            "export_ea": link["export_ea"],
            "importer_sids": link.get("importer_sids", []),
            "group_id": group.group_id,
        }

    def _ms_cross_decompile(self, args: dict) -> dict:
        """Decompile a function from a linked session.

        Accepts either:
          - symbol: resolved via the group link table
          - session_id + addr: direct cross-session decompile
        """
        session_id = str(args.get("session_id") or "").strip()
        addr = args.get("addr") or args.get("address") or args.get("ea")
        symbol = str(args.get("symbol") or args.get("name") or "").strip()

        if not session_id and symbol:
            # Resolve via group link table
            group_id = str(args.get("group_id") or "").strip()
            if not group_id:
                # Find any group that has this symbol
                with self._session_groups_lock:
                    for g in self._session_groups.values():
                        if symbol in g.links or any(
                            k.lower() == symbol.lower() for k in g.links
                        ):
                            group_id = g.group_id
                            break
            if not group_id:
                return make_error(
                    MCPError.NOT_FOUND,
                    f"No group contains a link for symbol '{symbol}'",
                    hint="Provide group_id or use (session_id + addr) directly.",
                )
            group = self._get_group(group_id)
            if group is None:
                return make_error(MCPError.NOT_FOUND, f"Group '{group_id}' not found")

            with self._session_groups_lock:
                link = group.links.get(symbol)
                if link is None:
                    for lname, ldata in group.links.items():
                        if lname.lower() == symbol.lower():
                            link = ldata
                            break
                link = deepcopy(link) if isinstance(link, dict) else None
            if link is None:
                return make_error(
                    MCPError.NOT_FOUND,
                    f"Symbol '{symbol}' not linked in group '{group_id}'",
                )
            session_id = link["provider_sid"]
            addr = link["export_ea"]

        if not session_id:
            return make_error(
                MCPError.INVALID_ARGS,
                "Provide (symbol) or (session_id + addr) to decompile",
            )
        if not addr:
            return make_error(MCPError.INVALID_ARGS, "addr required for cross_decompile")

        # Dispatch decompile to the target session
        decompile_args = {"action": "decompile", "addr": addr}
        result = self._dispatch_to_session(session_id, "code", decompile_args)

        if isinstance(result, dict):
            result["_cross_session"] = {
                "source_session_id": session_id,
                "resolved_from_symbol": symbol or None,
                "addr": addr,
            }
        return result

    def _ms_cross_xrefs(self, args: dict) -> dict:
        """Find all cross-references to a symbol across the group.

        Searches both the link table (which sessions import this symbol) and
        can optionally query each importer session for internal xrefs to the
        import stub.
        """
        group, err = self._require_group(args)
        if err:
            return err
        symbol = str(args.get("symbol") or args.get("name") or "").strip()
        if not symbol:
            return make_error(MCPError.INVALID_ARGS, "symbol (or name) required")

        # Check link table
        with self._session_groups_lock:
            link = group.links.get(symbol)
            if link is None:
                for lname, ldata in group.links.items():
                    if lname.lower() == symbol.lower():
                        link = ldata
                        symbol = lname
                        break
            link = deepcopy(link) if isinstance(link, dict) else None

        if link is None:
            return make_error(
                MCPError.NOT_FOUND,
                f"Symbol '{symbol}' not linked in group '{group.group_id}'",
            )

        xrefs_result: list[dict[str, Any]] = []

        # For each importer session, find xrefs to the import stub
        deep = bool(args.get("deep", False))
        if deep:
            for importer_sid in link.get("importer_sids", []):
                search_result = self._dispatch_to_session(
                    importer_sid, "search", {"action": "find", "query": symbol, "limit": 10}
                )
                if isinstance(search_result, dict) and not search_result.get("error"):
                    matches = search_result.get("results") or search_result.get("matches") or []
                    for m in matches:
                        if isinstance(m, dict):
                            xrefs_result.append({
                                "session_id": importer_sid,
                                "addr": m.get("ea") or m.get("addr"),
                                "context": m.get("text") or m.get("name") or "",
                            })

        return {
            "ok": True,
            "symbol": symbol,
            "provider_sid": link["provider_sid"],
            "export_ea": link["export_ea"],
            "importer_sids": link.get("importer_sids", []),
            "importer_count": len(link.get("importer_sids", [])),
            "xrefs": xrefs_result if deep else None,
            "group_id": group.group_id,
        }

    def _ms_status(self, args: dict) -> dict:
        """Return group status with link statistics."""
        group_id = str(args.get("group_id") or "").strip()

        # If no group_id, return summary of all groups
        if not group_id:
            summaries = []
            with self._session_groups_lock:
                for g in self._session_groups.values():
                    providers = set()
                    importers = set()
                    for link in g.links.values():
                        providers.add(link.get("provider_sid", ""))
                        for imp in link.get("importer_sids", []):
                            importers.add(imp)
                    summaries.append({
                        "group_id": g.group_id,
                        "name": g.name,
                        "session_count": len(g.session_ids),
                        "link_count": len(g.links),
                        "provider_count": len(providers),
                        "importer_count": len(importers),
                    })
            return {"ok": True, "groups": summaries, "total_groups": len(summaries)}

        group, err = self._require_group(args)
        if err:
            return err

        # Detailed stats for a single group
        providers: dict[str, int] = {}
        importers: dict[str, int] = {}
        sample_links = []
        with self._session_groups_lock:
            for link in group.links.values():
                psid = link.get("provider_sid", "")
                providers[psid] = providers.get(psid, 0) + 1
                for imp in link.get("importer_sids", []):
                    importers[imp] = importers.get(imp, 0) + 1

            # Sample links for display
            for name, link in list(group.links.items())[:20]:
                sample_links.append({
                    "symbol": name,
                    "provider_sid": link["provider_sid"],
                    "export_ea": link["export_ea"],
                    "importer_count": len(link.get("importer_sids", [])),
                })
            group_snapshot = group.to_dict()
            total_exports_linked = len(group.links)

        return {
            "ok": True,
            "group": group_snapshot,
            "providers": providers,
            "importers": importers,
            "sample_links": sample_links,
            "total_exports_linked": total_exports_linked,
        }
