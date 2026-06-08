from __future__ import annotations

from typing import Any

from .batch_manager import BatchManager
from .errors import MCPError, make_error


_BACKGROUND_ACTIONS = {
    "submit": "_bg_submit",
    "status": "_bg_status",
    "cancel": "_bg_cancel",
    "result": "_bg_result",
    "list": "_bg_list",
    "wait": "_bg_wait",
}


class BackgroundMixin:

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
        if not script and not tool_call:
            return make_error(
                MCPError.INVALID_ARGS,
                "background submit requires 'script' (Python source) or 'tool_call' "
                "(dict with 'tool', 'action', 'args' keys)",
            )
        action = "script" if script else "tool_call"

        def _run(task):
            self._bg_running = True
            try:
                if task.args.get("script"):
                    namespace: dict[str, Any] = {"__builtins__": __builtins__}
                    exec(
                        compile(task.args["script"], "<batch>", "exec"),
                        namespace,
                    )
                    return {"status": "executed"}
                elif task.args.get("tool_call"):
                    tc = task.args["tool_call"]
                    if hasattr(self, "_execute_tool"):
                        return self._execute_tool(tc.get("tool", ""), tc.get("args", {}))
                    return {"status": "ok", "tool_call": tc}
                return {"status": "unknown"}
            finally:
                self._bg_running = False

        task_id = self._batch_manager.submit(
            action=action,
            args={"script": script, "tool_call": tool_call},
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
        tasks = self._batch_manager.list_tasks(state)
        return {"tasks": tasks}

    def _bg_wait(self, args: dict) -> dict:
        task_id = args.get("task_id")
        if not task_id:
            return make_error(MCPError.INVALID_ARGS, "task_id required")
        timeout = args.get("timeout")
        if timeout is not None:
            timeout = float(timeout)
        return self._batch_manager.wait(str(task_id), timeout=timeout)
