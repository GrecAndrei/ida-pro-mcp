"""idalib runtime worker — runs the MCP IDA bridge inside IDA's idalib.

Spawned by the host (``host/server/server_runtime.py``) instead of
``idat -A -Sserver_script.py`` when ``IDA_MCP_RUNTIME=idalib``.  This
process initializes the IDA library, opens the target database, then runs
``server_script.py``'s ``__main__`` so the existing RPC listener, startup
analysis and main-thread tool-dispatch loop execute unmodified.

Contract:

- ``import idapro`` MUST be the first IDA-related import in the process
  (the package refuses to load inside a running IDAPython, and every
  subsequent ``ida_*`` import resolves to the idalib bindings once
  ``idapro`` has put the install's ``python`` dir on ``sys.path``).
- The host sets the same ``IDA_MCP_*`` env as for idat, plus:
  - ``IDA_MCP_IDALIB_PYTHON_DIR`` — directory containing the ``idapro``
    package (``<install>/idalib/python``).
  - ``IDA_MCP_IDALIB_OPEN`` — JSON ``{"file", "args", "existing",
    "skip_analysis", "server_script"}`` describing the database open.
- On the host's shutdown RPC, ``server_script``'s accept loop exits, its
  ``__main__`` block returns, and this worker performs the final
  ``close_database(save=True)`` so the IDB is flushed to the packed .i64.
"""

import json
import os
import runpy
import sys
from typing import NoReturn


def _exit(code: int, message: str) -> NoReturn:
    print(message, file=sys.stderr)
    sys.exit(code)


def main() -> None:
    idalib_python = os.environ.get("IDA_MCP_IDALIB_PYTHON_DIR", "")
    if idalib_python and idalib_python not in sys.path:
        sys.path.insert(0, idalib_python)

    # First IDA-related import — everything after this resolves to the
    # idalib bindings of the activated IDA installation.
    try:
        import idapro  # type: ignore[import-not-found]  # noqa: F401
    except ImportError as exc:
        _exit(3, f"idalib worker: idapro unavailable ({exc}). "
                "Run py-activate-idalib.py for the install and set "
                "IDA_MCP_IDALIB_PYTHON_DIR to <install>/idalib/python.")

    try:
        spec = json.loads(os.environ.get("IDA_MCP_IDALIB_OPEN", "{}"))
    except ValueError as exc:
        _exit(3, f"idalib worker: invalid IDA_MCP_IDALIB_OPEN: {exc}")

    db_file = spec.get("file") or os.environ.get("IDA_MCP_IDB_PATH", "")
    if not db_file:
        _exit(3, "idalib worker: no database file to open "
                "(IDA_MCP_IDALIB_OPEN.file / IDA_MCP_IDB_PATH empty)")
    args = str(spec.get("args") or "").strip()
    run_analysis = not bool(spec.get("skip_analysis"))

    # run_auto_analysis=True blocks through IDA's auto-analysis, so the RPC
    # listener binds only afterwards; the host's startup ping timeout
    # (IDA_MCP_STARTUP_TIMEOUT, default 240s) covers the open.  History is
    # enabled so ida_loader.save_snapshot / ida_undo work per session.
    try:
        rc = idapro.open_database(  # type: ignore[attr-defined]
            db_file, run_analysis, args=args if args else None, enable_history=True
        )
    except Exception as exc:
        _exit(3, f"idalib worker: open_database raised: {exc}")
    if rc != 0:
        hint = ""
        if rc == 2:
            # idalib refuses an -o output that already exists (no prompt in
            # batch). The host only passes -o for new databases, so this
            # usually means a stale .i64 from a killed run: remove it (or
            # open it directly) rather than failing the session.
            hint = (f" (output .i64 exists at -o target: "
                    f"{spec.get('args', '')!r} — remove the stale .i64 or "
                    "open it as an existing IDB)")
        _exit(3, f"idalib worker: open_database failed with rc={rc}{hint}")

    server_script = spec.get("server_script") or os.environ.get(
        "IDA_MCP_SERVER_SCRIPT", ""
    )
    if not server_script:
        _exit(3, "idalib worker: no server_script path configured")
    if not os.path.isfile(server_script):
        _exit(3, f"idalib worker: server_script not found: {server_script}")

    try:
        # Blocks until the host's shutdown RPC stops the accept loop.
        runpy.run_path(server_script, run_name="__main__")
    except SystemExit:
        pass
    except Exception as exc:
        print(f"idalib worker: server_script exited with error: {exc}", file=sys.stderr)
    finally:
        try:
            idapro.close_database(save=True)  # type: ignore[attr-defined]
        except Exception as exc:
            print(f"idalib worker: close_database failed: {exc}", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
