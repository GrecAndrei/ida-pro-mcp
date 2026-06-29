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
        if tool_name in {"session", "blackboard", "batch", "truncation", "wiki",
                         "predictor", "workflow"}:
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
                    # Compact mode: inject the top related blackboard findings as a
                    # terse recall hint — title, category, and address — so past
                    # findings reach the LLM without it having to query for them.
                    related = pack.get("related_findings") or []
                    if related:
                        hints = []
                        for e in related[:3]:
                            title = str(e.get("title") or "").strip()
                            if not title:
                                continue
                            parts = [title]
                            cat = str(e.get("category") or "").strip()
                            if cat and cat != "general":
                                parts.append(cat)
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
        """Resolve per-call guardrail mode: assist|enforce|off."""
        mode = ""
        if isinstance(call_args, dict):
            mode = str(call_args.get("_guardrail_mode") or "").strip().lower()
        if mode in {"off", "none", "disable", "disabled"}:
            return "off"
        if mode in {"enforce", "strict", "block"}:
            return "enforce"
        return "assist"

    def _guardrail_reason_tags(self, tool_name: str, call_args: Any, payload: Any) -> list[str]:
        tags: list[str] = []
        tn = str(tool_name or "").lower()
        if tn in {"code", "graph", "ctree", "static_trace", "memory", "calc"}:
            tags.append("address-heavy-tool")
        if isinstance(call_args, dict):
            keys = {str(k).lower() for k in call_args}
            if {"addr", "address", "target"} & keys:
                tags.append("explicit-address-arg")
            if {"offset", "offsets", "base", "size"} & keys:
                tags.append("offset-arithmetic")
        addrs = self._collect_hex_addresses(call_args)
        if len(addrs) < 2:
            addrs.extend([a for a in self._collect_hex_addresses(payload) if a not in addrs])
        if len(addrs) >= 2:
            tags.append("multiple-hex-addresses")
        return tags

    def _apply_output_filters(self, payload: Any, opts: dict) -> Any:
        """Apply universal output filtering (grep, head, tail, skip, path, pluck)."""
        import re as _re

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

    def _get_session_imagebase(self, session_id: str | None) -> int:
        if not session_id:
            return 0x140000000

        # 1. Check runtime cache
        if hasattr(self, "session_runtimes") and isinstance(self.session_runtimes, dict):
            runtime = self.session_runtimes.get(session_id)
            if isinstance(runtime, dict) and "imagebase" in runtime:
                return runtime["imagebase"]

        # 2. Check current session options
        session = getattr(self, "current_session", None)
        if session and session.session_id == session_id:
            raw_base = (getattr(session, "analysis_options", {}) or {}).get("baseaddr")
            if raw_base is not None:
                try:
                    return int(str(raw_base), 0)
                except ValueError:
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
                                    val = int(img_base_str, 16)
                                    runtime["imagebase"] = val
                                    return val
                                except ValueError:
                                    pass
                    except Exception:
                        pass

        return 0x140000000

    def _add_address_calculations(self, compacted: dict, session_id: str | None) -> None:
        try:
            serialized = json.dumps(compacted, ensure_ascii=False)
        except Exception:
            serialized = str(compacted)

        matches = _POINTER_NOTE_HEX_RE.findall(serialized)
        if not matches:
            return

        imagebase = self._get_session_imagebase(session_id)

        idb_path = None
        if self.current_session:
            idb_path = self.current_session.idb_path

        ppaa = None
        if idb_path:
            # Cache the PPAAEngine instance to avoid recreating it on every compacted response
            if not hasattr(self, "_ppaa_cache") or getattr(self, "_ppaa_cache_idb", None) != idb_path:
                from ..intelligence.ppaa import PPAAEngine
                self._ppaa_cache = PPAAEngine(idb_path)
                self._ppaa_cache_idb = idb_path
            ppaa = self._ppaa_cache

        hex_addrs = sorted(set(matches))
        valid_addrs = []
        for ha in hex_addrs:
            try:
                val = int(ha, 16)
                if val >= 0x1000:
                    valid_addrs.append((ha, val))
                elif ppaa:
                    rebased_val = imagebase + val
                    # Smarter threshold: accept values < 0x1000 if they actually exist in metadata indexes
                    if (ppaa.query_function_metadata(val) or
                        ppaa.query_function_metadata(rebased_val) or
                        ppaa.query_string_metadata(val) or
                        ppaa.query_string_metadata(rebased_val)):
                        valid_addrs.append((ha, val))
            except ValueError:
                pass

        if not valid_addrs:
            return

        calc_dict = {}
        for ha, val in valid_addrs:
            target_val = val
            is_rva = False

            # Check if val is likely an RVA (i.e. smaller than imagebase)
            if val < imagebase and ppaa:
                rebased_val = imagebase + val
                # Check if the rebased address matches any function or string in SchemaBoot
                if ppaa.query_function_metadata(rebased_val) or ppaa.query_string_metadata(rebased_val):
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

            if ppaa:
                meta = ppaa.query_function_metadata(target_val)
                if meta:
                    inferred = {
                        "name": meta["name"],
                        "segment": meta["segment"],
                        "size": meta["size"],
                        "is_library": meta["is_library"],
                    }
                    inferred["behavior_tags"] = []

                    if meta.get("reconstructed_structs"):
                        inferred["reconstructed_structs"] = meta["reconstructed_structs"]
                        c_structs = []
                        for struct_desc in meta["reconstructed_structs"]:
                            base_reg = struct_desc.get("base_register", "struct")
                            fields_lines = []
                            for f in struct_desc.get("fields", []):
                                fields_lines.append(f"    {f['type']} field_{f['offset']:x}; // offset {f['offset_hex']}")
                            struct_decl = f"struct struct_{base_reg} {{\n" + "\n".join(fields_lines) + "\n};"
                            c_structs.append(struct_decl)
                        inferred["synthesized_c_structures"] = c_structs

                    analogy = ppaa.query_symbol_analogy(meta["name"])
                    if analogy:
                        inferred["global_analogy"] = analogy

                    addr_info["inferred_semantics"] = inferred

                    if meta.get("cfg_hash"):
                        analogies = ppaa.query_functions_by_cfg_hash(meta["cfg_hash"], exclude_ea=target_val)
                        if analogies:
                            addr_info["cfg_structural_analogies"] = {
                                "cfg_hash": meta["cfg_hash"],
                                "matches": analogies
                            }

                    if meta.get("entropy", 0.0) > 6.5 and meta.get("string_count", 0) < 2:
                        addr_info["suggested_deobfuscation"] = {
                            "tool": "trace_analysis",
                            "action": "deobfuscate_emulate",
                            "addr": hex(target_val),
                            "reason": f"Function has high entropy ({meta['entropy']:.2f}) and low string references ({meta['string_count']}), suggesting encryption/obfuscation. Auto-emulation can extract hidden constants/strings."
                        }

                    bridges = ppaa.query_related_bridges(target_val)
                    if bridges:
                        addr_info["structural_bridges"] = {
                            "referenced_apis": meta["referenced_apis"][:10],
                            "referenced_strings": [s["text"] for s in meta["referenced_strings"][:10]],
                            "related_nodes": bridges
                        }
                else:
                    # If not a function address, check if it's a string literal address
                    str_meta = ppaa.query_string_metadata(target_val)
                    if str_meta:
                        addr_info["inferred_string"] = {
                            "text": str_meta["string_text"],
                            "referenced_by": str_meta["referencing_function"],
                            "referenced_by_ea": str_meta["referencing_function_ea"],
                        }

                    # Check if it matches a known cryptographic/structural constant
                    const_usages = ppaa.query_constant_usage(target_val)
                    if const_usages:
                        addr_info["inferred_constant_usages"] = const_usages

            calc_dict[ha] = addr_info

        if calc_dict:
            compacted["llm_address_calculation"] = calc_dict

    def _prepare_response_payload(
        self,
        payload: Any,
        opts: dict,
        *,
        tool_name: str = "",
        call_args: Any = None,
    ) -> Any:
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
        full_mode = opts.get("mode") == "full"
        if full_mode:
            if isinstance(payload, dict):
                payload = dict(payload)
                if include_pointer_note:
                    reason_tags = self._guardrail_reason_tags(tool_name, call_args, payload)
                    guardrail_mode = self._guardrail_mode_from_args(call_args)
                    payload.setdefault("llm_guardrail_mode", guardrail_mode)
                    payload.setdefault("llm_guardrail_reason_tags", reason_tags)
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
                compacted = truncate_response(compacted, max_tokens=budget)

        # ---- Context Density Auto-Compaction Middleware ----
        # Skip if the caller explicitly requests raw output.
        raw_requested = False
        if isinstance(call_args, dict):
            raw_requested = _coerce_bool(call_args.get("raw"), False)
        if not raw_requested and compacted is not None:
            try:
                serialized_size = len(
                    json.dumps(compacted, ensure_ascii=False, separators=(",", ":"))
                )
                if serialized_size > CONTEXT_DENSITY_COMPACT_THRESHOLD:
                    compacted = self._context_density_optimizer.compact_response(
                        compacted,
                        budget_tokens=opts.get(
                            "char_budget", CONTEXT_DENSITY_DEFAULT_BUDGET
                        ),
                    )
            except Exception:
                # Fail-safe: never let compaction break the response path
                pass
        # ------------------------------------------------------

        if isinstance(compacted, dict):
            compacted = dict(compacted)
            if include_pointer_note:
                reason_tags = self._guardrail_reason_tags(tool_name, call_args, compacted)
                guardrail_mode = self._guardrail_mode_from_args(call_args)
                compacted.setdefault("llm_guardrail_mode", guardrail_mode)
                compacted.setdefault("llm_guardrail_reason_tags", reason_tags)

            # ---- Real gating: blackboard policy + phase + must_call ----
            # (Only fires when the blackboard has a strict policy or a phase
            # gate. The shotgun _next_calls / suggested / prefetch / 7-phase
            # ghost chain have all been removed; see HACKING for the
            # history of those features.)
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
                if tool_name == "code" and action_name in ("decompile", "semantic_decompile", "disasm"):
                    from .response_enrichment import patch_addresses
                    if "pseudocode" in compacted:
                        pseudo_key = "pseudocode"
                    elif "code" in compacted:
                        pseudo_key = "code"
                    else:
                        pseudo_key = "disassembly"
                    if pseudo_key in compacted:
                        compacted[pseudo_key] = patch_addresses(compacted[pseudo_key])
            except Exception:
                pass

            # ---- Auto-Digest: API calls, patterns, behavior tags ----
            if self.enable_response_enrichment:
                try:
                    if tool_name == "code" and action_name in ("decompile", "semantic_decompile"):
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
                            digest = digest_decompiled(compacted[pseudo_key], func_addr=addr, schema_attrs=schema_attrs)
                            if digest and any(digest.values()):
                                compacted["_digest"] = digest
                except Exception:
                    pass

            # ---- Session Resume: first 2 calls only ----
            if self.enable_response_enrichment:
                try:
                    if hasattr(self, 'session_mgr') and self.current_session:
                        from .response_enrichment import build_session_resume
                        sid = self.current_session.session_id
                        if call_args and isinstance(call_args, dict):
                            call_count = call_args.get("_call_seq", 0)
                            if not isinstance(call_count, int) or call_count <= 2:
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
                        similar = self._exec("agent", action="cfg_similar", addr=addr, top_k=5)
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
