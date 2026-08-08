"""
Server response compaction, filtering, and enrichment helpers.

Extracted from host/server.py to reduce the size of the main JSON-RPC server
class while keeping the same response behavior.
"""

from __future__ import annotations

import contextlib
import json
import time
from typing import Any

from ..config import (
    _COMPACT_DROP,
    _POINTER_NOTE_HEX_RE,
    _POINTER_NOTE_MATH_RE,
    _POINTER_NOTE_MAX_SIGNAL_MULTIPLIER,
    _POINTER_NOTE_SIGNAL_KEYWORDS,
    _POINTER_NOTE_SIGNAL_MAX_DEPTH,
    _POINTER_NOTE_SIGNAL_MAX_DICT_ITEMS,
    _POINTER_NOTE_SIGNAL_MAX_LIST_ITEMS,
    _POINTER_NOTE_SIGNAL_TOOLS_HINT,
    _POINTER_NOTE_SIGNAL_TOOLS_STRONG,
    CONTEXT_DENSITY_COMPACT_THRESHOLD,
    CONTEXT_DENSITY_DEFAULT_BUDGET,
    _coerce_bool,
)
from ..errors import is_error_result
from ..stores.truncation import truncate_response
from .server_response_compact import ServerResponseCompactMixin


class ServerResponseMixin(ServerResponseCompactMixin):
    """Mixin for output compaction, pointer notes, and response enrichment."""

    def _inject_blackboard_policy_followup(
        self, payload: dict, tool_name: str, call_args: Any
    ) -> None:
        if not isinstance(payload, dict):
            return
        if str(tool_name or "").strip().lower() == "blackboard":
            return
        if not getattr(self, "_phase_gates_enabled", False):
            return
        if not hasattr(self, "_bb_policy_state") or not hasattr(self, "_bb_policy_check"):
            return
        try:
            state = self._bb_policy_state()
            if not bool((state or {}).get("strict_mode")):
                return
            check = self._bb_policy_check(state)
            if check.get("ok"):
                return
            reasons = check.get("reasons", [])
            payload.setdefault("blackboard_policy_gate", check)
            payload["must_call_before_answer"] = True
            payload["required_followup_call"] = {
                "tool": "blackboard",
                "action": "working_set",
            }
            # If a fresh write/decision is also required, steer to decision_card.
            if "missing_decision_or_write" in reasons or "stale_decision_or_write" in reasons:
                payload["required_followup_call"] = {
                    "tool": "blackboard",
                    "action": "decision_card",
                }
        except Exception:
            return

    def _inject_blackboard_phase_followup(self, payload: dict, tool_name: str) -> None:
        if not isinstance(payload, dict):
            return
        if str(tool_name or "").strip().lower() == "blackboard":
            return
        if not getattr(self, "_phase_gates_enabled", False):
            return
        if not hasattr(self, "_phase_followup_for_response"):
            return
        try:
            follow = self._phase_followup_for_response(tool_name)
            if not isinstance(follow, dict):
                return
            if follow.get("phase_gate"):
                payload.setdefault("blackboard_phase_gate", follow.get("phase_gate"))
            if follow.get("must_call_before_answer"):
                payload["must_call_before_answer"] = True
            if isinstance(follow.get("required_followup_call"), dict):
                payload["required_followup_call"] = follow["required_followup_call"]
        except Exception:
            return

    def _pointer_note_signal_from_text(self, text: str) -> float:
        if not text:
            return 0.0
        s = text.strip()
        if not s:
            return 0.0
        lowered = s.lower()
        score = 0.0
        hex_matches = list(_POINTER_NOTE_HEX_RE.finditer(s))
        if hex_matches:
            score += 1.0
        if _POINTER_NOTE_MATH_RE.search(s):
            score += 2.0
        if len(hex_matches) >= 2:
            score += 1.0
        if any(k in lowered for k in _POINTER_NOTE_SIGNAL_KEYWORDS):
            score += 1.0
        return score

    def _pointer_note_signal_from_value(self, value: Any, depth: int = 0) -> float:
        if depth > _POINTER_NOTE_SIGNAL_MAX_DEPTH:
            return 0.0
        if isinstance(value, str):
            return self._pointer_note_signal_from_text(value)
        if isinstance(value, int):
            return 0.5 if value >= 0x1000 else 0.0
        if isinstance(value, list):
            return sum(
                self._pointer_note_signal_from_value(v, depth + 1)
                for v in value[:_POINTER_NOTE_SIGNAL_MAX_LIST_ITEMS]
            )
        if isinstance(value, dict):
            score = 0.0
            for idx, (k, v) in enumerate(value.items()):
                if idx >= _POINTER_NOTE_SIGNAL_MAX_DICT_ITEMS:
                    break
                child_score = self._pointer_note_signal_from_value(v, depth + 1)
                if isinstance(k, str):
                    kl = k.lower()
                    if child_score > 0 and any(
                        sig in kl for sig in _POINTER_NOTE_SIGNAL_KEYWORDS
                    ):
                        score += 1.0
                score += child_score
            return score
        return 0.0

    def _compute_pointer_note_signal(
        self, tool_name: str, call_args: Any, payload: Any
    ) -> float:
        score = 0.0
        tn = str(tool_name or "").strip().lower()
        if tn in _POINTER_NOTE_SIGNAL_TOOLS_STRONG:
            score += 2.0
        elif tn in _POINTER_NOTE_SIGNAL_TOOLS_HINT:
            score += 1.0
        if isinstance(call_args, dict):
            for idx, (k, v) in enumerate(call_args.items()):
                if idx >= 20:
                    break
                if isinstance(k, str):
                    kl = k.lower()
                    if kl.startswith("_"):
                        continue
                    if any(sig in kl for sig in _POINTER_NOTE_SIGNAL_KEYWORDS):
                        score += 1.0
                score += self._pointer_note_signal_from_value(v)
        if isinstance(payload, dict):
            payload_focus: dict[str, Any] = {}
            for key in (
                "address",
                "addr",
                "target",
                "query",
                "pattern",
                "matches",
                "items",
            ):
                if key in payload:
                    val = payload.get(key)
                    if val not in (None, "", [], {}):
                        payload_focus[key] = val
            score += self._pointer_note_signal_from_value(payload_focus)
        return min(score, 10.0)

    def _should_include_pointer_note(
        self, tool_name: str, call_args: Any, payload: Any
    ) -> bool:
        if is_error_result(payload):
            return False
        signal = self._compute_pointer_note_signal(tool_name, call_args, payload)
        if signal > 0:
            self._pointer_note_pending_signal = min(
                float(self._pointer_note_min_signal)
                * _POINTER_NOTE_MAX_SIGNAL_MULTIPLIER,
                self._pointer_note_pending_signal + signal,
            )
        else:
            self._pointer_note_pending_signal = max(
                0.0, self._pointer_note_pending_signal - 0.25
            )
            return False
        if self._pointer_note_pending_signal < float(self._pointer_note_min_signal):
            return False
        now = time.time()
        if self._pointer_note_last_shown_at > 0 and (
            now - self._pointer_note_last_shown_at
        ) < float(self._pointer_note_interval_seconds):
            return False
        self._pointer_note_last_shown_at = now
        self._pointer_note_pending_signal = 0.0
        return True

    def _validate_address_lockstep(self, call_args: Any, payload: Any) -> list[dict]:
        """Detect addresses in call_args that do not appear in previous payload output."""
        if not isinstance(call_args, dict):
            return []
        requested = self._collect_hex_addresses(call_args, max_items=12)
        if not requested:
            return []
        available = self._collect_hex_addresses(payload, max_items=50)
        available_set = set(available)
        warnings: list[dict] = []
        for addr in requested:
            if addr not in available_set:
                warnings.append(
                    {
                        "addr": addr,
                        "warning": "This address was not present in the previous tool output. Verify with calc/memory before reasoning.",
                        "suggested_verification": {
                            "tool": "calc",
                            "arguments": {"action": "deref", "addr": addr, "type": "u32"},
                        },
                    }
                )
        return warnings

    # Tools that are the workspace itself, or that carry no address the
    # analyst is reasoning about. Recalling into these is noise or recursion.
    # Agent-surface (public) operations are listed alongside their legacy
    # names so the exemption holds regardless of the configured surface.
    _RECALL_EXEMPT_TOOLS = frozenset(
        {
            "session", "blackboard", "batch", "truncation", "wiki", "workflow",
            "ida_batch", "ida_help",
            "ida_open_binary", "ida_open_background",
            "ida_session_state", "ida_session_status", "ida_session_health",
            "ida_close_session", "ida_session_get", "ida_session_list",
            "ida_session_switch",
        }
    )

    # Tools that render code for an address. The legacy surface names the
    # tool "code"; these are its agent-surface equivalents. Used to gate the
    # code-anchor / address-patch / decompile-digest enrichment.
    _CODE_RENDERING_TOOLS = frozenset(
        {"code", "ida_decompile", "ida_disassemble"}
    )

    # Where rendered code lives in a payload, and which anchor kind it forms.
    _ANCHOR_SOURCES = (
        ("pseudocode", "decompile"),
        ("code", "decompile"),
        ("disassembly", "disassemble"),
    )

    @staticmethod
    def _first_addr(call_args: Any) -> str:
        """Pull the single address a call was about, whatever spelling it used."""
        if not isinstance(call_args, dict):
            return ""
        raw = call_args.get("addrs") or call_args.get("addr") or call_args.get("address") or ""
        if isinstance(raw, (list, tuple)):
            raw = raw[0] if raw else ""
        text = str(raw).strip()
        if "," in text:
            text = text.split(",", 1)[0].strip()
        return text

    def _capture_code_anchor(
        self, tool_name: str, action: str, call_args: Any, payload: dict
    ) -> None:
        """Record the code just rendered, and flag claims that predate it.

        This is what makes a finding able to notice it has gone out of date:
        every time code is shown for an address, its digest is compared with
        the one recorded when claims about that address were written.
        """
        if tool_name not in self._CODE_RENDERING_TOOLS or action not in {
            "decompile",
            "semantic_decompile",
            "disasm",
        }:
            return
        addr = self._first_addr(call_args)
        if not addr:
            return
        store = self._get_blackboard_store()
        if store is None:
            return
        for key, anchor_kind in self._ANCHOR_SOURCES:
            text = payload.get(key)
            if not isinstance(text, str) or not text.strip():
                continue
            result = store.observe_code(addr, anchor_kind, text)
            marked = int(result.get("stale_marked") or 0)
            if marked:
                payload["_stale"] = (
                    f"{marked} recorded item(s) at {addr} were marked stale: the code "
                    "changed since they were written. Re-check before relying on them."
                )
            return

    def _inject_workspace_recall(self, tool_name: str, payload: dict, call_args: Any) -> None:
        """Surface what the workspace already knows, without being asked.

        A memory the model has to remember to query is a memory it will not
        use. Two injections, both bounded:

        ``_recall``
            Prior findings, verdicts, and open questions about the address
            this call was about.
        ``_already_examined``
            For result sets, which of the returned addresses were previously
            read and set aside — so a search does not re-offer work that was
            already dismissed.

        Failures are reported in ``_recall_error`` rather than swallowed: a
        recall path that silently does nothing is indistinguishable from one
        that was never wired up, which is how the previous version decayed.
        """
        if tool_name in self._RECALL_EXEMPT_TOOLS:
            return
        store = self._get_blackboard_store()
        if store is None:
            return
        try:
            asked_about = self._collect_hex_addresses(call_args, max_items=6)
            if asked_about:
                lines = store.recall_lines(asked_about, limit=4)
                if lines:
                    payload["_recall"] = lines

            returned = [
                addr for addr in self._collect_hex_addresses(payload, max_items=50)
                if addr not in set(asked_about)
            ]
            if returned:
                seen = {}
                for addr in returned:
                    prior = store.examination(addr)
                    if prior:
                        seen[addr] = prior["verdict"]
                    if len(seen) >= 10:
                        break
                if seen:
                    payload["_already_examined"] = seen
        except Exception as exc:  # surfaced, not swallowed
            payload["_recall_error"] = f"{type(exc).__name__}: {exc}"[:200]

    def _assemble_and_inject_context(
        self,
        tool_name: str,
        action: str,
        payload: dict,
        addr: str,
        opts: dict | None = None,
    ) -> None:
        """
        Build a context_pack via the intelligence layer (bge-code-v1) and inject
        it into the payload so the LLM receives relevant context alongside results.
        Replaces the cartographer + attention_kernel + cognitive_layer pipeline.
        """
        if not isinstance(payload, dict) or is_error_result(payload):
            return
        if tool_name in self._RECALL_EXEMPT_TOOLS:
            return

        try:
            session_id = (
                getattr(self.current_session, "session_id", None)
                if self.current_session else "default"
            )
            idb_path = (
                getattr(self.current_session, "idb_path", None)
                if self.current_session else None
            )
            bb_store = self._get_blackboard_store()
            mode = str((opts or {}).get("mode") or "").strip().lower()
            pack = self.assembler.assemble(
                tool=tool_name,
                action=action,
                payload=payload,
                addr=addr,
                session_id=session_id or "default",
                idb_path=idb_path or "",
                bb_store=bb_store,
                mode=mode,
            )
            if pack:
                mode = str((opts or {}).get("mode") or "").strip().lower()
                # Only inject context_pack in full mode — it's verbose
                if mode == "full":
                    payload["context_pack"] = pack
                else:
                    # Compact mode: the semantic assembler contributes findings
                    # related by meaning or by graph distance. Exact-address
                    # recall has already run, so drop anything it covered
                    # rather than saying it twice.
                    already = "\n".join(payload.get("_recall") or [])
                    related = pack.get("related_findings") or []
                    if related:
                        hints = []
                        for e in related[:3]:
                            title = str(e.get("title") or "").strip()
                            if not title or title in already:
                                continue
                            kind = str(e.get("kind") or "finding").strip()
                            status = str(e.get("status") or "open").strip()
                            parts = [f"{kind}/{status}: {title}"]
                            addr_e = str(e.get("addr") or "").strip()
                            if addr_e:
                                parts.append(f"@ {addr_e}")
                            hints.append(" — ".join(parts))
                        if hints:
                            payload["_context"] = hints
        except Exception:
            pass

    def _collect_hex_addresses(self, value: Any, max_items: int = 8) -> list[str]:
        found: list[str] = []

        def _push(addr_text: str) -> None:
            if not addr_text:
                return
            norm = addr_text.lower()
            if not norm.startswith("0x"):
                return
            if norm in found:
                return
            found.append(norm)

        def _walk(v: Any, depth: int = 0) -> None:
            if len(found) >= max_items or depth > 3:
                return
            if isinstance(v, str):
                for m in _POINTER_NOTE_HEX_RE.finditer(v):
                    _push(m.group(0))
            elif isinstance(v, int):
                if v >= 0x1000:
                    _push(hex(v))
            elif isinstance(v, list):
                for item in v[:12]:
                    _walk(item, depth + 1)
                    if len(found) >= max_items:
                        break
            elif isinstance(v, dict):
                for idx, (_, item) in enumerate(v.items()):
                    if idx >= 24:
                        break
                    _walk(item, depth + 1)
                    if len(found) >= max_items:
                        break

        _walk(value)
        return found[:max_items]

    def _guardrail_mode_from_args(self, call_args: Any) -> str:
        """Resolve per-call guardrail mode: assist|enforce|off.

        Used internally for strict-write gating; not included in LLM responses.
        """
        mode = ""
        if isinstance(call_args, dict):
            mode = str(call_args.get("_guardrail_mode") or "").strip().lower()
        if mode in {"off", "none", "disable", "disabled"}:
            return "off"
        if mode in {"enforce", "strict", "block"}:
            return "enforce"
        return "assist"

    def _apply_output_filters(self, payload: Any, opts: dict) -> Any:
        """Apply universal output filtering (grep, head, tail, skip, path, pluck)."""
        import re as _re

        # Errors carry their own contract (the make_error envelope). Filtering
        # them here can destroy the error body (e.g. output_path on an error
        # dict yields {}); pass them through unchanged like the post-processing
        # pipeline does.
        if is_error_result(payload):
            return payload

        # Path extraction: extract a nested field from a dict
        path = opts.get("output_path")
        if path and isinstance(payload, dict):
            current = payload
            for part in str(path).split("."):
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list) and part.isdigit():
                    idx = int(part)
                    current = current[idx] if 0 <= idx < len(current) else None
                else:
                    current = None
                if current is None:
                    break
            payload = current if current is not None else {}

        # If payload is a list, apply head/tail/skip/grep/pluck
        if isinstance(payload, list):
            skip = opts.get("output_skip")
            if skip is not None:
                with contextlib.suppress(Exception):
                    payload = payload[int(skip):]

            head = opts.get("output_head")
            if head is not None:
                with contextlib.suppress(Exception):
                    payload = payload[:int(head)]

            tail = opts.get("output_tail")
            if tail is not None:
                with contextlib.suppress(Exception):
                    payload = payload[-int(tail):]

            grep = opts.get("output_grep")
            if grep:
                try:
                    pattern = _re.compile(str(grep), _re.IGNORECASE)
                    payload = [x for x in payload if pattern.search(str(x))]
                except Exception:
                    pass

            pluck = opts.get("output_pluck")
            if pluck:
                try:
                    key = str(pluck)
                    payload = [
                        x.get(key) if isinstance(x, dict) else x
                        for x in payload
                    ]
                except Exception:
                    pass

        # If payload is a dict with a list inside, try to apply grep to common list fields
        elif isinstance(payload, dict) and opts.get("output_grep"):
            pattern_str = opts.get("output_grep")
            try:
                pattern = _re.compile(str(pattern_str), _re.IGNORECASE)
                for k, v in list(payload.items()):
                    if isinstance(v, list):
                        payload[k] = [x for x in v if pattern.search(str(x))]
            except Exception:
                pass

        return payload

    def _build_llm_execution_directive(self, payload: dict) -> str | None:
        """Build a compact directive from tool-first gating fields."""
        if not isinstance(payload, dict):
            return None
        must_call = bool(payload.get("must_call_before_answer"))
        req = payload.get("required_followup_call")
        if not isinstance(req, dict):
            req = None
        if not must_call and not req:
            return None

        call_txt = "code.callers"
        if req:
            tool = str(req.get("tool") or "").strip()
            action = str(req.get("action") or "").strip()
            if tool and action:
                call_txt = f"{tool}.{action}"

        if must_call:
            return (
                f"MCP_REQUIRED_CALL: Execute `{call_txt}` before concluding. "
                "Do not finalize claims until new tool evidence is incorporated."
            )
        return (
            f"MCP_RECOMMENDED_CALL: Prefer `{call_txt}` before final answer "
            "and cite returned evidence."
        )

    def _get_session_imagebase(self, session_id: str | None) -> int | None:
        """Resolve the session's real image base, or None when unknown.

        Never fabricates a default: a hardcoded 0x140000000 made every
        32-bit address (e.g. 0x401000) look like an RVA, so the address
        enrichment silently "rebased" legitimate absolute addresses into
        garbage (0x140401000). Only a value actually known for this session
        (runtime cache, session options, or a live RPC answer) is returned.
        """
        if not session_id:
            return None

        # 1. Check runtime cache
        if hasattr(self, "session_runtimes") and isinstance(self.session_runtimes, dict):
            runtime = self.session_runtimes.get(session_id)
            if isinstance(runtime, dict) and "imagebase" in runtime:
                cached = runtime["imagebase"]
                return int(cached) if isinstance(cached, (int, str)) and str(cached) else None

        # 2. Check the target session's recorded options (any session, not
        #    just the current one — the caller may enrich for another session).
        try:
            session = self.session_mgr.get_session(session_id)
        except Exception:
            session = None
        if session is None and self.current_session and self.current_session.session_id == session_id:
            session = self.current_session
        if session is not None:
            raw_base = (getattr(session, "analysis_options", {}) or {}).get("baseaddr")
            if raw_base is not None:
                try:
                    return int(str(raw_base), 0)
                except (ValueError, TypeError):
                    pass

        # 3. Query the target IDA Pro RPC server
        if hasattr(self, "session_runtimes") and isinstance(self.session_runtimes, dict):
            runtime = self.session_runtimes.get(session_id)
            if isinstance(runtime, dict) and "port" in runtime:
                port = runtime.get("port")
                auth_token = runtime.get("auth_token")
                if isinstance(port, int) and port > 0 and hasattr(self, "_send_rpc_raw"):
                    try:
                        res = self._send_rpc_raw(
                            {"tool": "idb", "args": {"action": "meta"}},
                            port,
                            timeout=1.0,
                            auth_token=auth_token
                        )
                        if isinstance(res, dict) and (res.get("ok") or "image_base" in res):
                            img_base_str = res.get("image_base")
                            if img_base_str:
                                try:
                                    val = int(str(img_base_str), 16)
                                    runtime["imagebase"] = val
                                    return val
                                except (ValueError, TypeError):
                                    pass
                    except Exception:
                        pass

        return None

    def _add_address_calculations(self, compacted: dict, session_id: str | None) -> None:
        try:
            serialized = json.dumps(compacted, ensure_ascii=False)
        except Exception:
            serialized = str(compacted)

        matches = _POINTER_NOTE_HEX_RE.findall(serialized)
        if not matches:
            return

        imagebase = self._get_session_imagebase(session_id)
        if imagebase is None:
            # No known image base for this session: rebasing "RVAs" would be
            # pure invention (the old hardcoded 0x140000000 default turned
            # every 32-bit address into a bogus imagebase+offset). Report
            # nothing rather than garbage.
            return

        hex_addrs = sorted(set(matches))
        valid_addrs = []
        for ha in hex_addrs:
            try:
                val = int(ha, 16)
                if val >= 0x1000:
                    valid_addrs.append((ha, val))

            except ValueError:
                pass

        if not valid_addrs:
            return

        calc_dict = {}
        for ha, val in valid_addrs:
            target_val = val
            is_rva = False

            # Only reinterpret a sub-imagebase value as an RVA when the image
            # base itself fits in 32 bits. With a 64-bit base (e.g.
            # 0x140000000) the entire low address space is ambiguous: a
            # legitimate 32-bit absolute address (a stored dword pointer, a
            # constant) is indistinguishable from an RVA, and rebasing it to
            # imagebase+value fabricates a bogus address — the exact garbage
            # this function was rewritten to avoid. For a 32-bit base, values
            # below it are almost always section RVAs. Values at/above the
            # image base are always kept absolute.
            if val < imagebase < 0x1_0000_0000:
                rebased_val = imagebase + val
                target_val = rebased_val
                is_rva = True

            offset = target_val - imagebase
            sign = "+" if offset >= 0 else "-"
            abs_offset = abs(offset)

            addr_info = {
                "decimal": target_val,
                "relative_to_imagebase": f"imagebase {sign} 0x{abs_offset:x}",
                "offset": offset,
                "offset_hex": f"{sign}0x{abs_offset:x}",
                "alignment": {
                    "aligned_4": (target_val % 4 == 0),
                    "aligned_8": (target_val % 8 == 0),
                    "aligned_16": (target_val % 16 == 0),
                }
            }

            if is_rva:
                addr_info["is_rva"] = True
                addr_info["original_rva_hex"] = ha

            calc_dict[ha] = addr_info

        if calc_dict:
            compacted["llm_address_calculation"] = calc_dict
            compacted["llm_address_calculation_imagebase"] = hex(imagebase)

    def _prepare_response_payload(
        self,
        payload: Any,
        opts: dict,
        *,
        tool_name: str = "",
        call_args: Any = None,
    ) -> Any:
        # Per-call truncation overrides are set by dispatch for the executed
        # tool. Consume them once here and clear them so a response that does
        # not run dispatch (a validation error, help response, or a batch
        # aggregate) never inherits a previous call's truncation controls.
        _tc = getattr(self, "_pending_truncation", None) or {}
        self._pending_truncation = {}

        full_mode = opts.get("mode") == "full"
        # The pointer-note signal/throttle is only consumed in full mode
        # (address-lockstep warnings). Compute it there on the pre-filter
        # payload; in compact mode it has no effect on the output, so skip the
        # whole computation rather than mutating shared throttle state.
        include_pointer_note = False
        if full_mode:
            include_pointer_note = self._should_include_pointer_note(
                tool_name, call_args, payload
            )
        action_name = ""
        if isinstance(call_args, dict):
            action_name = str(call_args.get("action") or "")
        if not action_name:
            action_name = str(opts.get("action") or "")
        # Apply universal output filters first
        payload = self._apply_output_filters(payload, opts)
        payload = self._json_safe_value(payload)

        # ---- One-shot analysis-completion notice ----
        # When a background-loaded session's analysis completes, the next
        # response for that session carries the transition warning exactly
        # once ('the agent is auto moved to the new one with a warning').
        # The notice is only consumed when the payload can carry it (a dict);
        # a list/scalar payload leaves it pending for the next response.
        try:
            notices = getattr(self, "_pending_session_notices", None)
            current = getattr(self, "current_session", None)
            if (
                isinstance(notices, dict)
                and current is not None
                and isinstance(payload, dict)
            ):
                notice = notices.pop(current.session_id, None)
                if notice is not None:
                    payload = dict(payload)
                    payload["warning"] = notice
        except Exception:
            pass
        if full_mode:
            if isinstance(payload, dict):
                payload = dict(payload)
                if include_pointer_note:
                    # Address lockstep: warn about unseen addresses
                    lockstep_warnings = self._validate_address_lockstep(call_args, payload)
                    if lockstep_warnings:
                        payload.setdefault("llm_address_lockstep_warnings", lockstep_warnings)
            compacted = payload
        else:
            projected = self._project_top_level_fields(payload, opts)
            compacted = self._compact_value(projected, opts)
            if compacted is _COMPACT_DROP:
                compacted = {}
            compacted = self._compact_batch_result(compacted, opts)
            budget = int(opts.get("char_budget", 0) or 0)
            if budget > 0 and isinstance(compacted, dict):
                # Check per-call truncation overrides
                if _tc.get("no_truncate"):
                    pass  # skip truncation
                else:
                    _budget = _tc.get("max_tokens") or budget
                    _sid = ""
                    if getattr(self, "current_session", None) is not None:
                        _sid = str(getattr(self.current_session, "session_id", "") or "")
                    _owner = ""
                    if hasattr(self, "_truncation_owner_id"):
                        _owner = self._truncation_owner_id()
                    compacted = truncate_response(
                        compacted,
                        max_tokens=_budget,
                        trunc_offset=_tc.get("trunc_offset"),
                        trunc_limit=_tc.get("trunc_limit"),
                        session_id=_sid,
                        owner_id=_owner,
                    )

        # ---- Context Density Auto-Compaction Middleware ----
        # Skip if the caller explicitly requests raw output, or in "full"
        # response mode (where _extract_response_options sets char_budget=0 as
        # a "no budget" sentinel — passing that 0 would degenerate-truncate
        # what the caller asked to be complete).
        raw_requested = False
        if isinstance(call_args, dict):
            raw_requested = _coerce_bool(call_args.get("raw"), False)
        if (
            not raw_requested
            and opts.get("mode") == "compact"
            and compacted is not None
        ):
            try:
                serialized_size = len(
                    json.dumps(compacted, ensure_ascii=False, separators=(",", ":"))
                )
                if serialized_size > CONTEXT_DENSITY_COMPACT_THRESHOLD:
                    compacted = self._context_density_optimizer.compact_response(
                        compacted,
                        budget_tokens=opts.get(
                            "char_budget"
                        ) or CONTEXT_DENSITY_DEFAULT_BUDGET,
                    )
            except Exception:
                # Fail-safe: never let compaction break the response path
                pass
        # ------------------------------------------------------

        if isinstance(compacted, dict):
            compacted = dict(compacted)

            # ---- Real gating: blackboard policy + phase + must_call ----
            # (Only fires when the blackboard has a strict policy or a phase
            # gate. The shotgun _next_calls / suggested / prefetch / 7-phase
            # ghost chain have all been removed in a previous cleanup pass.)
            try:
                self._inject_blackboard_policy_followup(compacted, tool_name, call_args)
                self._inject_blackboard_phase_followup(compacted, tool_name)
                directive = self._build_llm_execution_directive(compacted)
                if directive:
                    compacted.setdefault("llm_execution_directive", directive)
            except Exception:
                pass

            # ---- Address Patching: annotate rip-relative in disasm/pseudo ----
            try:
                if tool_name in self._CODE_RENDERING_TOOLS and action_name in ("decompile", "semantic_decompile", "disasm"):
                    from .response_enrichment import patch_addresses
                    if "pseudocode" in compacted:
                        pseudo_key = "pseudocode"
                    elif "code" in compacted:
                        pseudo_key = "code"
                    else:
                        pseudo_key = "disassembly"
                    if pseudo_key in compacted:
                        # patch_addresses' LEA/generic base+offset branches only
                        # fire when the base register is in base_registers, so
                        # feed it the session's real imagebase (rip-relative in
                        # x86-64 pseudo/disasm). _get_session_imagebase never
                        # fabricates a default, so unknown sessions stay plain.
                        _patch_sid = ""
                        if getattr(self, "current_session", None) is not None:
                            _patch_sid = str(getattr(self.current_session, "session_id", "") or "")
                        _imgbase = self._get_session_imagebase(_patch_sid or None)
                        _base_registers = {"rip": _imgbase} if _imgbase else None
                        compacted[pseudo_key] = patch_addresses(compacted[pseudo_key], _base_registers)
            except Exception:
                pass

            # ---- Auto-Digest: API calls, patterns, behavior tags ----
            # Skipped in safe mode: the agent must do everything manually
            # while auto-analysis is still running.
            _safe_mode_fn = getattr(self, "_safe_mode_active", None)
            _safe_mode_active = bool(
                _safe_mode_fn(
                    getattr(self.current_session, "session_id", "") or ""
                )
                if callable(_safe_mode_fn)
                else False
            )
            if self.enable_response_enrichment and not _safe_mode_active:
                try:
                    if tool_name in self._CODE_RENDERING_TOOLS and action_name in ("decompile", "semantic_decompile"):
                        from .response_enrichment import digest_decompiled
                        if "pseudocode" in compacted:
                            pseudo_key = "pseudocode"
                        elif "code" in compacted:
                            pseudo_key = "code"
                        else:
                            pseudo_key = "output"
                        if pseudo_key in compacted and isinstance(compacted[pseudo_key], str):
                            addr = (call_args or {}).get("addr", "") if isinstance(call_args, dict) else ""
                            schema_attrs = None
                            try:
                                if addr and hasattr(self, '_insight_index') and self._insight_index:
                                    func_data = self._insight_index.get_function(addr) if hasattr(self._insight_index, 'get_function') else None
                                    if func_data:
                                        schema_attrs = func_data
                            except Exception:
                                pass
                            digest = digest_decompiled(compacted[pseudo_key], schema_attrs=schema_attrs)
                            if digest and any(digest.values()):
                                compacted["_digest"] = digest
                except Exception:
                    pass

            # ---- Session Resume: first 2 calls only ----
            # Also skipped in safe mode: resume summarizes prior analysis,
            # which is exactly what must not be auto-trusted mid-analysis.
            # The gate is a real per-session counter (previously it read a
            # `_call_seq` arg that was never set, so the resume fired on every
            # enriched response).
            if self.enable_response_enrichment and not _safe_mode_active:
                try:
                    if hasattr(self, 'session_mgr') and self.current_session:
                        from .response_enrichment import build_session_resume
                        sid = self.current_session.session_id
                        with self._session_resume_calls_lock:
                            call_count = self._session_resume_calls.get(sid, 0)
                            self._session_resume_calls[sid] = call_count + 1
                        if call_count < 2:
                            resume = build_session_resume(self.session_mgr, sid)
                            if resume:
                                compacted["_session_resume"] = resume
                except Exception:
                    pass

            # ---- Confidence Gate: warn when result is below 0.5 ----
            try:
                if isinstance(compacted, dict):
                    conf = compacted.get("confidence")
                    if conf is not None:
                        try:
                            conf_val = float(conf)
                            if conf_val < 0.5:
                                compacted.setdefault(
                                    "llm_low_confidence_gate",
                                    {
                                        "confidence": conf_val,
                                        "threshold": 0.5,
                                        "message": "Result confidence is below threshold. Verify before acting.",
                                    },
                                )
                        except Exception:
                            pass
            except Exception:
                pass

            # ---- Workspace: anchor the code shown, then recall what is known ----
            # Order matters: anchoring first means a claim invalidated by this
            # very response is already flagged stale by the time recall reads it.
            if isinstance(compacted, dict) and not is_error_result(compacted):
                try:
                    self._capture_code_anchor(tool_name, action_name, call_args, compacted)
                except Exception as exc:
                    compacted["_anchor_error"] = f"{type(exc).__name__}: {exc}"[:200]
                self._inject_workspace_recall(tool_name, compacted, call_args)

            # ---- Intelligence Layer: assemble real context and inject ----
            try:
                if isinstance(compacted, dict):
                    addr = ""
                    if isinstance(call_args, dict):
                        addr = str(call_args.get("addr") or call_args.get("addrs") or "")
                    self._assemble_and_inject_context(
                        tool_name, action_name, compacted, addr, opts=opts
                    )
            except Exception:
                pass

            # ---- Structural similarity: enrich with agent.cfg_similar ----
            # Gated by enable_response_enrichment (default off) — this fires an
            # in-IDA agent.cfg_similar sub-call per response with an `addr`, which
            # is a hidden round-trip AND bloats every addr response. Opt in via
            # IDA_MCP_RESPONSE_ENRICH=1.
            if self.enable_response_enrichment:
                try:
                    if isinstance(compacted, dict) and addr:
                        similar = self._exec("intelligence", action="similar_functions", addr=addr)
                        if isinstance(similar, dict) and similar.get("ok"):
                            compacted.setdefault("similar_functions", similar.get("results") or [])
                except Exception:
                    pass

            # ---- Address Calculation Enrichment ----
            # Gated by enable_response_enrichment (default off) — injects a
            # per-address llm_address_calculation blob (with cfg_structural_analogies)
            # into every response. Opt in via IDA_MCP_RESPONSE_ENRICH=1.
            if self.enable_response_enrichment:
                try:
                    if isinstance(compacted, dict):
                        session_id = getattr(self.current_session, "session_id", None) if self.current_session else None
                        self._add_address_calculations(compacted, session_id)
                except Exception:
                    pass
        return compacted
