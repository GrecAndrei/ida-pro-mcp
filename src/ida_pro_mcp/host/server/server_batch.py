from __future__ import annotations

from typing import Any

from ..batch_manager import BatchManager
from ..errors import MCPError, make_error
from ..policy import PolicyDecision, evaluate_policy


_BACKGROUND_ACTIONS = {
    "submit": "_bg_submit",
    "status": "_bg_status",
    "cancel": "_bg_cancel",
    "result": "_bg_result",
    "list": "_bg_list",
    "wait": "_bg_wait",
}


class BackgroundMixin:

    def _background_policy_preflight(self, *, script: Any, tool_call: Any) -> dict | None:
        if script:
            decision = evaluate_policy(
                "background",
                "script",
                mode="assist",
                purpose=None,
                ack=False,
            )
            return make_error(
                getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                "background script execution is not supported; submit a tool_call instead",
                hint="Use background(action='submit', tool_call={'tool':'...', 'args': {...}}).",
                details=decision.to_dict(),
            )

        if tool_call:
            if not isinstance(tool_call, dict):
                return make_error(MCPError.INVALID_ARGS, "tool_call must be an object")
            tool = str(tool_call.get("tool") or tool_call.get("name") or "").strip()
            call_args = tool_call.get("args") or tool_call.get("arguments") or {}
            if not tool:
                return make_error(MCPError.INVALID_ARGS, "tool_call.tool required")
            if not isinstance(call_args, dict):
                return make_error(MCPError.INVALID_ARGS, "tool_call.args must be an object")
            decision = evaluate_policy(
                tool,
                call_args.get("action"),
                mode="assist",
                purpose=call_args.get("_purpose"),
                ack=bool(call_args.get("_risk_ack") or call_args.get("_guardrail_ack")),
            )
            if decision.decision in {PolicyDecision.BLOCK, PolicyDecision.REQUIRE_ACK}:
                return make_error(
                    getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                    "Background tool call requires explicit acknowledgement before queueing",
                    hint="Add _risk_ack=true to tool_call.args after verifying the action is authorized.",
                    details=decision.to_dict(),
                )
        return None

    @property
    def _batch_manager(self) -> BatchManager:
        if not hasattr(self, "_batch_mgr"):
            self._batch_mgr = BatchManager()
        return self._batch_mgr

    def _handle_background(self, args: dict) -> dict:
        action = str(args.get("action") or "list").strip()
        handler_name = _BACKGROUND_ACTIONS.get(action)
        if handler_name is None:
            valid = ", ".join(sorted(_BACKGROUND_ACTIONS.keys()))
            return make_error(
                MCPError.INVALID_ARGS,
                f"Invalid background action '{action}'. Valid: {valid}",
            )
        return getattr(self, handler_name)(args)

    def _bg_submit(self, args: dict) -> dict:
        script = args.get("script")
        tool_call = args.get("tool_call")
        session_id = args.get("session_id")
        if not script and not tool_call:
            return make_error(
                MCPError.INVALID_ARGS,
                "background submit requires 'script' (Python source) or 'tool_call' "
                "(dict with 'tool', 'action', 'args' keys)",
            )
        policy_error = self._background_policy_preflight(script=script, tool_call=tool_call)
        if policy_error:
            return policy_error
        action = "script" if script else "tool_call"

        def _run(task):
            prev_session = getattr(self, "current_session", None)
            try:
                if task.session_id and hasattr(self, "session_mgr"):
                    try:
                        target = self.session_mgr.get_session(task.session_id)
                        if target:
                            self.current_session = target
                    except Exception:
                        pass
                if task.args.get("script"):
                    return make_error(
                        getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                        "background script execution is disabled",
                        hint="Use background tool_call for auditable work.",
                    )
                elif task.args.get("tool_call"):
                    tc = task.args["tool_call"]
                    if hasattr(self, "_execute_tool"):
                        return self._execute_tool(
                            tc.get("tool", "") or tc.get("name", ""),
                            tc.get("args", {}) or tc.get("arguments", {}),
                        )
                    return {"status": "ok", "tool_call": tc}
                return {"status": "unknown"}
            finally:
                self.current_session = prev_session

        task_id = self._batch_manager.submit(
            action=action,
            args={"script": script, "tool_call": tool_call},
            session_id=session_id,
            run_fn=_run,
        )
        return {"task_id": task_id, "state": "pending"}

    def _bg_status(self, args: dict) -> dict:
        task_id = args.get("task_id")
        tasks = self._batch_manager.status(task_id)
        return {"tasks": tasks}

    def _bg_result(self, args: dict) -> dict:
        task_id = args.get("task_id")
        if not task_id:
            return make_error(MCPError.INVALID_ARGS, "task_id required")
        return self._batch_manager.result(str(task_id))

    def _bg_cancel(self, args: dict) -> dict:
        task_id = args.get("task_id")
        if not task_id:
            return make_error(MCPError.INVALID_ARGS, "task_id required")
        return self._batch_manager.cancel(str(task_id))

    def _bg_list(self, args: dict) -> dict:
        state = args.get("state")
        session_id = args.get("session_id")
        tasks = self._batch_manager.list_tasks(state)
        if session_id:
            tasks = [t for t in tasks if t.get("session_id") == session_id]
        return {"tasks": tasks}

    def _bg_wait(self, args: dict) -> dict:
        task_id = args.get("task_id")
        if not task_id:
            return make_error(MCPError.INVALID_ARGS, "task_id required")
        timeout = args.get("timeout")
        if timeout is not None:
            timeout = float(timeout)
        return self._batch_manager.wait(str(task_id), timeout=timeout)
