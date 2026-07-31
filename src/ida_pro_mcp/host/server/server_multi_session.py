#!/usr/bin/env python3
"""Multi-session group management for cross-binary analysis.

Provides the ServerMultiSessionMixin which enables linking multiple IDA sessions
together into a group, resolving cross-binary imports/exports, and forwarding
tool calls (e.g. decompile) to the session that owns a given symbol.
"""

from __future__ import annotations

import uuid
from typing import Any

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
            "metadata": self.metadata,
        }


class ServerMultiSessionMixin:
    """Mixin for IDAMCPServer providing multi-session group management.

    Sessions in a group can have their imports and exports cross-linked, allowing
    transparent resolution of inter-binary references and cross-session decompilation.
    """

    _session_groups: dict[str, SessionGroup]

    def _init_multi_session(self) -> None:
        """Initialize multi-session state. Call from server __init__."""
        if not hasattr(self, "_session_groups"):
            self._session_groups = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_group(self, group_id: str) -> SessionGroup | None:
        """Look up a group by ID."""
        self._init_multi_session()
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
                hint="Use multi_session(action='group_list') to see available groups.",
            )
        return group, None

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
        return {"ok": True, "group": group.to_dict()}

    def _ms_group_list(self, args: dict) -> dict:
        """List all session groups."""
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

        # Gather exports from all sessions
        # exports_map: symbol_name -> {sid, ea}
        exports_map: dict[str, dict[str, str]] = {}
        export_errors: list[dict[str, str]] = []

        for sid in group.session_ids:
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

        # Gather imports from all sessions and match against exports
        links_built = 0
        import_errors: list[dict[str, str]] = []

        for sid in group.session_ids:
            result = self._dispatch_to_session(sid, "imports_deep", {"action": "resolve"})
            if isinstance(result, dict) and result.get("error"):
                import_errors.append({"session_id": sid, "error": str(result.get("message", ""))})
                continue
            imports = []
            if isinstance(result, dict):
                imports = result.get("imports") or result.get("entries") or result.get("symbols") or []
            for imp in imports:
                if not isinstance(imp, dict):
                    continue
                name = str(imp.get("name") or "").strip()
                if not name:
                    continue
                # Match against known exports (skip self-references)
                provider = exports_map.get(name)
                if provider and provider["provider_sid"] != sid:
                    if name not in group.links:
                        group.links[name] = {
                            "provider_sid": provider["provider_sid"],
                            "export_ea": provider["export_ea"],
                            "importer_sids": [],
                        }
                    link = group.links[name]
                    if sid not in link["importer_sids"]:
                        link["importer_sids"].append(sid)
                        links_built += 1

        return {
            "ok": True,
            "group_id": group.group_id,
            "links_built": links_built,
            "total_links": len(group.links),
            "exports_available": len(exports_map),
            "export_errors": export_errors if export_errors else None,
            "import_errors": import_errors if import_errors else None,
        }

    def _ms_group_remove(self, args: dict) -> dict:
        """Remove a session group (does not close sessions)."""
        group_id = str(args.get("group_id") or "").strip()
        if not group_id:
            return make_error(MCPError.INVALID_ARGS, "group_id required")
        removed = self._session_groups.pop(group_id, None)
        if removed is None:
            return make_error(MCPError.NOT_FOUND, f"Group '{group_id}' not found")
        return {"ok": True, "removed": removed.to_dict()}

    def _ms_cross_resolve(self, args: dict) -> dict:
        """Resolve an import name to the session + EA that provides it."""
        group, err = self._require_group(args)
        if err:
            return err
        symbol = str(args.get("symbol") or args.get("name") or "").strip()
        if not symbol:
            return make_error(MCPError.INVALID_ARGS, "symbol (or name) required")

        link = group.links.get(symbol)
        if link is None:
            # Try case-insensitive search
            for lname, ldata in group.links.items():
                if lname.lower() == symbol.lower():
                    link = ldata
                    symbol = lname
                    break

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

            link = group.links.get(symbol)
            if link is None:
                for lname, ldata in group.links.items():
                    if lname.lower() == symbol.lower():
                        link = ldata
                        break
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
        link = group.links.get(symbol)
        if link is None:
            for lname, ldata in group.links.items():
                if lname.lower() == symbol.lower():
                    link = ldata
                    symbol = lname
                    break

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
        for link in group.links.values():
            psid = link.get("provider_sid", "")
            providers[psid] = providers.get(psid, 0) + 1
            for imp in link.get("importer_sids", []):
                importers[imp] = importers.get(imp, 0) + 1

        # Sample links for display
        sample_links = []
        for name, link in list(group.links.items())[:20]:
            sample_links.append({
                "symbol": name,
                "provider_sid": link["provider_sid"],
                "export_ea": link["export_ea"],
                "importer_count": len(link.get("importer_sids", [])),
            })

        return {
            "ok": True,
            "group": group.to_dict(),
            "providers": providers,
            "importers": importers,
            "sample_links": sample_links,
            "total_exports_linked": len(group.links),
        }
