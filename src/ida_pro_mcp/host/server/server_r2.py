#!/usr/bin/env python3
"""Host-side r2 backend tool handler (Architecture A, Phase 1).

``ServerR2Mixin`` supplies ``_handle_r2`` for the ``r2`` tool namespace
(public ops ``ida_r2_status`` / ``ida_r2_bininfo`` / ``ida_r2_load_hints`` /
``ida_r2_disassemble_hypothesis`` / ``ida_r2_vxrefs``). It resolves the raw
binary path from a session reference WITHOUT the runtime-alive / safe-mode-clear
requirement (r2 only needs ``binary_path`` plus the session's resolved
arch/bitness/base) or from a bare standalone ``binary_path``, applies the same
ownership guard as ``_submit_semantic_index``, and enforces the safe-mode rule
(read ops allowed; IDB-writing paths refused — Phase 1 ships only read ops).
"""

from __future__ import annotations

import os
from typing import Any

from ..config import _bounded_int
from ..errors import MCPError, make_error
from ..r2_engine import R2Engine

# Every Phase-1 r2 action is a read-only subprocess op over the raw file.
# IDB-writing r2 paths (Phase 2+ feedback, apply-to-IDB) are deliberately
# refused — see docs/RIZIN_INTEGRATION.md, "r2 proposes, IDA disposes".
_R2_READ_ONLY_ACTIONS = frozenset(
    {"status", "bininfo", "load_hints", "disassemble_hypothesis", "vxrefs"}
)

_R2_DISASM_MAX_BYTES = 4096


class ServerR2Mixin:
    def _r2_allowed_root_for(self, binary_path: str) -> str | None:
        """Allowed root for r2 target canonicalization.

        Mirrors ``_memory_allow_root``: the explicit ``IDA_MCP_MEMORY_ROOT``
        when set, otherwise the resolved target's own directory (the caller
        already controls that location). Scoped to the r2 target, never the
        shared active session's idb dir.
        """
        env_root = os.environ.get("IDA_MCP_MEMORY_ROOT")
        if env_root:
            try:
                return os.path.realpath(os.path.expanduser(env_root))
            except Exception:
                pass
        if binary_path:
            try:
                return os.path.realpath(os.path.dirname(os.path.abspath(binary_path)))
            except Exception:
                pass
        return None

    def _resolve_r2_target(
        self, args: dict
    ) -> tuple[str | None, dict[str, Any] | None, dict | None]:
        """Resolve the raw binary path + arch context for an r2 op.

        Resolution order:
          1. A session reference (``idb=``): resolved WITHOUT the
             runtime-alive / safe-mode-clear requirement — r2 only needs the
             session's ``binary_path`` and its resolved arch/bitness/base.
             The ownership guard applies, exactly as in ``_submit_semantic_index``.
          2. Standalone mode: an explicit ``binary_path`` plus optional
             ``processor`` / ``bitness`` / ``baseaddr`` args (no session, no IDA).

        Returns ``(binary_path, arch_context, error_envelope_or_None)``.
        """
        session_ref = args.get("idb")
        binary_arg = args.get("binary_path")
        if not session_ref and not binary_arg:
            # Schema contract: binary_path defaults to the connection's active
            # session binary.
            current = self.current_session
            if current is not None:
                session_ref = getattr(current, "session_id", None)
        if session_ref:
            session = self._resolve_session_from_idb_ref(session_ref)
            if not session:
                return None, None, make_error(
                    MCPError.FILE_NOT_FOUND,
                    f"No session found for idb reference: {session_ref}",
                    hint=(
                        "Use session_id, SID_* IDB id, or the binary/idb path. "
                        "r2 operates on the raw file, not the IDB."
                    ),
                )
            ownership_error = self._ensure_client_owns_session(session)
            if ownership_error:
                return None, None, ownership_error
            bp = getattr(session, "binary_path", "") or ""
            if not bp or not os.path.isfile(bp):
                return None, None, make_error(
                    MCPError.R2_BINARY_NOT_FOUND,
                    "The session's binary file is missing; r2 operates on the raw file, not the IDB.",
                    details={
                        "session_id": str(session.session_id),
                        "binary_path": bp,
                    },
                )
            opts = dict(getattr(session, "analysis_options", None) or {})
            arch_context = {
                "processor": opts.get("processor"),
                "bitness": opts.get("bitness"),
                "endian": opts.get("endian"),
                "baseaddr": opts.get("baseaddr") or opts.get("load_base"),
            }
            return bp, arch_context, None
        if binary_arg:
            arch_context = {
                "processor": args.get("processor"),
                "bitness": args.get("bitness"),
                "endian": args.get("endian"),
                "baseaddr": args.get("baseaddr") or args.get("load_base"),
            }
            return str(binary_arg), arch_context, None
        return None, None, make_error(
            MCPError.INVALID_ARGS,
            "r2 requires a session reference (idb=) or an explicit binary_path.",
            hint=(
                "Pass binary_path= plus processor/bitness/baseaddr for standalone "
                "triage, or idb=<session> to reuse a session's binary."
            ),
        )

    def _handle_r2(self, args: dict) -> dict:
        """Host-side handler for the ``r2`` tool namespace."""
        action = str(args.get("action") or "").strip()
        if action not in _R2_READ_ONLY_ACTIONS:
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported r2 action: '{action}'",
                hint=(
                    "r2 actions: status, bininfo, load_hints, "
                    "disassemble_hypothesis, vxrefs. Phase 1 ships read-only ops; "
                    "IDB-writing r2 paths are refused by design."
                ),
            )

        engine = R2Engine()
        if action == "status":
            # No binary / session required — a pure engine feature test.
            return engine.status()

        binary_path, arch_context, err = self._resolve_r2_target(args)
        if err:
            return err
        engine.allowed_root = self._r2_allowed_root_for(binary_path)

        if action == "bininfo":
            return engine.bininfo(binary_path)

        if action == "load_hints":
            return engine.load_hints(binary_path, arch_context)

        if action == "disassemble_hypothesis":
            # addr is a hex address/file offset (schema: addr); also accept
            # offset for direct engine parity.
            addr = args.get("addr") or args.get("offset")
            offset = 0
            if addr is not None:
                try:
                    offset = int(str(addr), 0)
                except (ValueError, TypeError):
                    return make_error(
                        MCPError.ADDRESS_INVALID,
                        "r2 disassemble_hypothesis: addr must be a hex offset",
                    )
            count = args.get("count")
            size = args.get("size")
            if size is not None:
                size = _bounded_int(size, 64, min_value=1, max_value=_R2_DISASM_MAX_BYTES)
            elif count is not None:
                # count = max instructions → a conservative byte window of
                # 4 bytes/instruction, clamped to the op cap.
                size = _bounded_int(
                    count,
                    64,
                    min_value=1,
                    max_value=_R2_DISASM_MAX_BYTES // 4,
                )
                size = min(size * 4, _R2_DISASM_MAX_BYTES)
            else:
                size = 64
            base = _bounded_int(args.get("base"), 0)
            hypotheses = args.get("hypotheses")
            if isinstance(hypotheses, str):
                hypotheses = [
                    h.strip() for h in hypotheses.split(",") if h.strip()
                ]
            elif not isinstance(hypotheses, list):
                hypotheses = None
            return engine.disassemble_hypothesis(
                binary_path,
                offset=offset,
                size=size,
                base=base,
                hypotheses=hypotheses,
                arch_context=arch_context,
            )

        if action == "vxrefs":
            limit = args.get("limit")
            limit = _bounded_int(limit, 0) if limit is not None else None
            return engine.vxrefs(
                binary_path,
                target=args.get("value") if args.get("value") is not None else args.get("target"),
                pointer_width=args.get("pointer_width"),
                endian=args.get("endian"),
                limit=limit,
            )

        return make_error(
            MCPError.ACTION_NOT_FOUND, f"Unsupported r2 action: '{action}'"
        )
