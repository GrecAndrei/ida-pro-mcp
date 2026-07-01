import argparse
import logging
import signal
import sys
from pathlib import Path

import ida_auto

# idapro must go first to initialize idalib
import idapro

from ida_pro_mcp.ida_mcp import MCP_SERVER

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to listen on, default: 127.0.0.1",
    )
    parser.add_argument(
        "--port", type=int, default=8745, help="Port to listen on, default: 8745"
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    parser.add_argument(
        "input_path", type=Path, help="Path to the input file to analyze."
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    logging.basicConfig(level=log_level)

    # reset logging levels that might be initialized in idapythonrc.py
    # which is evaluated during import of idalib.
    logging.getLogger().setLevel(log_level)

    if not args.input_path.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_path}")

    # The input database path is currently provided by CLI arguments.
    logger.info("opening database: %s", args.input_path)
    if idapro.open_database(str(args.input_path), run_auto_analysis=True):
        raise RuntimeError("failed to analyze input file")

    logger.debug("idalib: waiting for analysis...")
    ida_auto.auto_wait()

    # Some stripped ELF binaries (notably Android NDK arm64-v8a libraries)
    # have the loader create 8-byte PLT stubs for dynamic symbols but never
    # enqueue work for .text. IDA's auto-analysis then exits with the queue
    # empty and the code section is left completely unanalyzed
    # (defined_code_bytes == 0 over a non-trivial total). Detect that
    # failure mode and trigger a targeted reanalysis over the eligible
    # executable segments so the runtime starts with a useful IDB.
    try:
        from ida_pro_mcp.ida_mcp.tools.analysis import (
            _auto_reanalyze_text_segments,
            _ensure_entry_point_functions,
        )

        rean = _auto_reanalyze_text_segments(wait_seconds=60.0)
        if rean.get("reanalysis_triggered"):
            logger.info(
                "Auto-reanalysis scheduled %d range(s); functions %d -> %d, "
                "defined_code_bytes %d -> %d (coverage %.1f%% -> %.1f%%)",
                rean.get("scheduled", 0),
                rean.get("functions_before", 0),
                rean.get("functions_after", 0),
                rean.get("defined_code_bytes_before", 0),
                rean.get("defined_code_bytes_after", 0),
                rean.get("coverage_pct_before", 0.0),
                rean.get("coverage_pct_after", 0.0),
            )
        ep = _ensure_entry_point_functions()
        if ep.get("created"):
            logger.info(
                "Created %d entry-point function(s) the auto-analyzer missed: %s",
                len(ep["created"]),
                ", ".join(ep["created"][:8]),
            )
        # Persist the upgraded IDB so subsequent restarts don't re-run
        # the expensive reanalysis. Use ida_diskio.save_database to keep
        # the same on-disk path the loader opened.
        try:
            import ida_diskio
            ida_diskio.save_database("")
        except Exception as exc:
            logger.debug("save_database after auto-reanalysis failed: %s", exc)
    except Exception as exc:
        logger.debug("auto-reanalysis post-step failed (non-fatal): %s", exc)

    # Setup signal handlers to ensure IDA database is properly closed on shutdown.
    # When a signal arrives, our handlers execute first, allowing us to close the
    # IDA database cleanly before the process terminates.
    def cleanup_and_exit(signum, frame):
        logger.info("Closing IDA database...")
        idapro.close_database()
        logger.info("IDA database closed.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    # NOTE: npx -y @modelcontextprotocol/inspector for debugging
    # Keep background disabled: the main thread must service @idaread work,
    # and background mode can deadlock IDA SDK synchronization.
    MCP_SERVER.serve(host=args.host, port=args.port, background=False)


if __name__ == "__main__":
    main()
