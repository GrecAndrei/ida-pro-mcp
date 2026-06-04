from __future__ import annotations

import json
from typing import Annotated, Any, Dict, List, Literal, Optional

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ida_pro_mcp.host.survey_store import SurveyStore
except ImportError:
    from host.survey_store import SurveyStore  # type: ignore[import-not-found]


def _require_active_survey(store: SurveyStore, hex_addr: str, *, action: str) -> dict | None:
    current = store.get_survey(hex_addr)
    if not current:
        not_found_code = getattr(MCPError, "NOT_FOUND", MCPError.INVALID_ARGS)
        return make_error(
            not_found_code,
            f"No survey found for address {hex_addr}",
            hint=f"Use survey(action='list') to inspect the scoped backlog before {action}.",
        )
    if current.get("status") != "ACTIVE":
        return make_error(
            MCPError.INVALID_ARGS,
            f"Survey for {hex_addr} is {current.get('status', 'unknown')}, not ACTIVE",
            hint=f"Only ACTIVE surveys can be {action}. Visit dependencies or inspect survey(action='status').",
            details={
                "addr": hex_addr,
                "status": current.get("status"),
                "dependencies": current.get("dependencies", []),
                "deferred_until": current.get("deferred_until", []),
            },
        )
    return current


@tool
@idawrite
def survey(
    action: Annotated[
        Literal["list", "submit", "delay", "status"],
        "Action: list|submit|delay|status"
    ],
    addr: Annotated[Optional[str], "Address of the function or offset related to the survey"] = None,
    renames: Annotated[Optional[dict], "Map of generic variable names to new names (action=submit)"] = None,
    blackboard_publish: Annotated[Optional[list], "List of findings to publish to blackboard (action=submit)"] = None,
    bookmark: Annotated[Optional[str], "Bookmark tag name to apply to the function (action=submit)"] = None,
    delay_until_any: Annotated[Optional[list], "List of addresses the LLM wants to check first (action=delay)"] = None,
    reason: Annotated[Optional[str], "Reason for delaying the survey (action=delay)"] = None,
    **kwargs
) -> dict:
    """
    Manage, delay, list, or submit context-aware surveys for reverse engineering.
    
    Actions:
      - list: Returns a lightweight backlog representation of all surveys.
      - status: Returns the counts of active, deferred, and dormant surveys.
      - delay: Defers active locks until specific other addresses are visited.
      - submit: Resolves the active survey, applying renames and posting findings.
    """
    try:
        store = SurveyStore(context_key=idc.get_idb_path() or "")

        if action == "list":
            surveys = store.list_surveys()
            return {
                "ok": True,
                "surveys": surveys,
                "count": len(surveys)
            }

        elif action == "status":
            surveys = store.list_surveys()
            active = [s for s in surveys if s["status"] == "ACTIVE"]
            deferred = [s for s in surveys if s["status"] == "DEFERRED"]
            dormant = [s for s in surveys if s["status"] == "DORMANT"]
            return {
                "ok": True,
                "active_count": len(active),
                "deferred_count": len(deferred),
                "dormant_count": len(dormant),
                "active_surveys": active
            }

        elif action == "delay":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for delay")
            ea, err = validate_addr(addr)
            if err:
                return err
            
            hex_addr = hex(ea)
            curr = _require_active_survey(store, hex_addr, action="delayed")
            if isinstance(curr, dict) and curr.get("ok") is False:
                return curr
            
            # Detect circular dependencies
            clean_deferred = []
            for dep in (delay_until_any or []):
                try:
                    dep_ea, _ = validate_addr(dep)
                    dep_hex = hex(dep_ea)
                    if dep_hex != hex_addr:
                        dep_survey = store.get_survey(dep_hex)
                        if dep_survey and hex_addr in dep_survey.get("dependencies", []):
                            continue
                        clean_deferred.append(dep_hex)
                except Exception:
                    pass
            
            store.save_survey(
                addr=hex_addr,
                status="DEFERRED",
                variables=curr["variables"],
                dependencies=curr["dependencies"],
                deferred_until=clean_deferred,
                reason=reason or ""
            )
            return {
                "ok": True,
                "message": f"Survey for {hex_addr} deferred. Unlock complete.",
                "deferred_until": clean_deferred
            }

        elif action == "submit":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for submit")
            ea, err = validate_addr(addr)
            if err:
                return err
            
            hex_addr = hex(ea)
            curr = _require_active_survey(store, hex_addr, action="submitted")
            if isinstance(curr, dict) and curr.get("ok") is False:
                return curr
            
            # 1. Apply Renames to IDA Pro variables
            applied_renames = {}
            if renames:
                try:
                    import ida_hexrays
                    import ida_funcs
                    func = ida_funcs.get_func(ea)
                    if func:
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        if cfunc:
                            for old_name, new_name in renames.items():
                                renamed_ok = False
                                for lvar in cfunc.lvars:
                                    if lvar.name == old_name:
                                        if cfunc.rename_lvar(lvar, new_name):
                                            applied_renames[old_name] = new_name
                                            renamed_ok = True
                                            break
                                if renamed_ok:
                                    cfunc.save_user_lvars()
                                    try:
                                        from .types import refresh_decompiler_ctext
                                        refresh_decompiler_ctext(func.start_ea)
                                    except Exception:
                                        pass
                except Exception:
                    pass

            # 2. Publish to Blackboard
            published = []
            if blackboard_publish:
                try:
                    from ida_pro_mcp.host.blackboard_store import BlackboardStore
                    bb = BlackboardStore()
                    for item in blackboard_publish:
                        import uuid
                        uid = str(uuid.uuid4())
                        bb.create_note(
                            uid,
                            category=item.get("category", "general"),
                            title=item.get("title", "Survey finding"),
                            content=item.get("content", ""),
                            confidence=0.9
                        )
                        published.append(item.get("title"))
                except Exception:
                    pass

            # 3. Add Bookmark/Tag in IDA
            bookmarked = False
            if bookmark:
                try:
                    import idc as _idc
                    _idc.set_func_cmt(ea, f"[Survey Tag] {bookmark}", 0)
                    bookmarked = True
                except Exception:
                    pass

            # Save experience to differential db
            try:
                import uuid
                uid = str(uuid.uuid4())
                ida_code = ""
                ghidra_code = ""
                try:
                    import ida_hexrays
                    import ida_funcs
                    func = ida_funcs.get_func(ea)
                    if func:
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        if cfunc:
                            ida_code = str(cfunc)
                            try:
                                from .code import _simulate_ghidra_decomp
                                ghidra_code = _simulate_ghidra_decomp(ida_code, ida_funcs.get_func_name(func.start_ea) or "", func.start_ea)
                            except Exception:
                                pass
                except Exception:
                    pass
                
                store.save_experience(
                    id_val=uid,
                    address=ea,
                    ida_pseudocode=ida_code,
                    ghidra_pseudocode=ghidra_code,
                    llm_rationale="Interactive Survey submission",
                    resolved_source=ida_code,
                    applied_changes={
                        "renames": applied_renames,
                        "blackboard": published,
                        "bookmark": bookmark
                    }
                )
            except Exception:
                pass

            # Clear/delete active survey from store
            store.delete_survey(hex_addr)
            return {
                "ok": True,
                "message": f"Survey for {hex_addr} submitted successfully.",
                "renames_applied": applied_renames,
                "blackboard_published": published,
                "bookmark_applied": bookmarked
            }

    except Exception as e:
        return handle_error(e)
