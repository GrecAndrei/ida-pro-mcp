#!/usr/bin/env python3
"""Run bounded, opt-in Jev validation without conflating it with live IDA.

The provider checks use structured metadata only.  ``--binary`` optionally
adds ELF-header metadata derived from a caller-supplied real binary; no raw
bytes, decompilation, prompts, completions, or credentials are written to the
report.  Licensed IDA validation remains a separate live-IDA suite.

The benchmark requires ``TYPESAFE_API_KEY`` and explicit Jev pricing in the
process environment (``IDA_MCP_JEV_INPUT_USD_PER_MTOK`` and
``IDA_MCP_JEV_OUTPUT_USD_PER_MTOK``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


_MACHINE_NAMES = {
    3: "x86",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}


def _binary_metadata(path_value: str) -> dict[str, Any]:
    """Return bounded, non-code metadata for a caller-supplied binary."""
    supplied = Path(path_value).expanduser()
    if supplied.is_symlink():
        raise ValueError("--binary must name a regular file")
    path = supplied.resolve()
    if not path.is_file():
        raise ValueError("--binary must name a regular file")
    stat = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        header = stream.read(64)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    result: dict[str, Any] = {
        "format": "unknown",
        "size_bytes": int(stat.st_size),
        "sha256": digest.hexdigest(),
    }
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return result

    elf_class = {1: 32, 2: 64}.get(header[4])
    endian = {1: "little", 2: "big"}.get(header[5])
    result.update({"format": "ELF", "class_bits": elf_class, "endian": endian})
    if endian is None or elf_class is None:
        return result
    order = "<" if endian == "little" else ">"
    machine = struct.unpack_from(f"{order}H", header, 18)[0]
    entry_offset = 24
    entry_size = 4 if elf_class == 32 else 8
    if len(header) >= entry_offset + entry_size:
        entry = struct.unpack_from(f"{order}{'I' if entry_size == 4 else 'Q'}", header, entry_offset)[0]
        result["entry"] = hex(entry)
    result["machine"] = _MACHINE_NAMES.get(machine, f"em_{machine}")
    return result


def _safe_result(value: Any) -> Any:
    """Keep only bounded structured advisory output in the report."""
    if isinstance(value, dict):
        return {
            str(key): _safe_result(item)
            for key, item in value.items()
            if str(key) not in {"request", "response", "body", "content", "state"}
        }
    if isinstance(value, list):
        return [_safe_result(item) for item in value[:64]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def _write_report(path: str, report: dict[str, Any]) -> None:
    out_path = Path(path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="benchmark-results/jev_benchmark.json")
    parser.add_argument(
        "--binary",
        help="optional caller-supplied binary; only bounded ELF metadata is sent",
    )
    parser.add_argument(
        "--ledger",
        help="optional metadata-only usage ledger path; defaults to a temporary file",
    )
    args = parser.parse_args()

    if not os.environ.get("TYPESAFE_API_KEY", "").strip():
        report = {
            "status": "skipped",
            "reason": "TYPESAFE_API_KEY missing",
            "remote_jev": "not_run",
            "licensed_ida": "not_run",
        }
        _write_report(args.out, report)
        print("[jev_benchmark] skipped: TYPESAFE_API_KEY missing", file=sys.stderr)
        return 0

    missing_prices = [
        name
        for name in (
            "IDA_MCP_JEV_INPUT_USD_PER_MTOK",
            "IDA_MCP_JEV_OUTPUT_USD_PER_MTOK",
        )
        if not os.environ.get(name, "").strip()
    ]
    if missing_prices:
        report = {
            "status": "skipped",
            "reason": "explicit Jev pricing is required",
            "missing_pricing": missing_prices,
            "remote_jev": "not_run",
            "licensed_ida": "not_run",
        }
        _write_report(args.out, report)
        print("[jev_benchmark] skipped: explicit Jev pricing is required", file=sys.stderr)
        return 0

    from ida_pro_mcp.host.intelligence.advisory import ask_architecture, ask_behavior
    from ida_pro_mcp.host.intelligence.providers import (
        ProviderError,
        build_provider,
        resolve_provider_config,
    )
    from ida_pro_mcp.host.intelligence.providers.usage_accounting import UsageLedger
    from ida_pro_mcp.host.intelligence.rerank import Reranker

    started = time.monotonic()
    report: dict[str, Any] = {
        "status": "started",
        "remote_jev": "executed",
        "licensed_ida": "not_run",
        "input_scope": "synthetic_metadata",
        "metrics": {},
    }
    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    try:
        binary = _binary_metadata(args.binary) if args.binary else {
            "format": "synthetic",
            "class_bits": 64,
            "endian": "little",
            "machine": "x86_64",
            "entry": "0x401000",
        }
        report["input_scope"] = "real_binary_derived_metadata" if args.binary else "synthetic_metadata"
        report["metrics"]["input_metadata"] = dict(binary)
        env = dict(os.environ)
        env["IDA_MCP_INTELLIGENCE_MODE"] = "jev"
        config = resolve_provider_config(env=env)
        temp_dir = tempfile.TemporaryDirectory(prefix="ida-mcp-jev-")
        ledger_path = args.ledger or str(Path(temp_dir.name) / "provider_usage.sqlite3")
        ledger = UsageLedger(ledger_path)
        provider = build_provider(config, ledger=ledger)
        status = provider.status()
        report["metrics"]["status"] = {
            "ready": status.ready,
            "provider": status.provider_id,
            "model": status.model,
            "capabilities": status.capabilities.names(),
        }
        if not status.ready:
            raise RuntimeError("Jev provider is not ready")

        state = {
            "binary": binary,
            "function": {"name": "entrypoint", "signature": "entrypoint(void)"},
            "evidence": ["bounded entrypoint metadata"],
        }
        behavior_started = time.monotonic()
        behavior = ask_behavior(state, provider=provider, ledger=ledger)
        report["metrics"]["ask_behavior_ms"] = round((time.monotonic() - behavior_started) * 1000, 2)
        report["metrics"]["ask_behavior_result"] = _safe_result(behavior)
        if isinstance(behavior, dict) and behavior.get("error"):
            raise RuntimeError(str(behavior.get("code") or "behavior advisory failed"))

        reranker = Reranker(provider=provider)
        rerank_started = time.monotonic()
        rerank_result = reranker.rerank(
            "network receive and buffer validation",
            [
                "network_receive(const uint8_t*, size_t)",
                "calculate_checksum(const uint8_t*, size_t)",
            ],
        )
        report["metrics"]["rerank_ms"] = round((time.monotonic() - rerank_started) * 1000, 2)
        report["metrics"]["rerank_result"] = _safe_result(rerank_result)
        if rerank_result is None:
            raise RuntimeError("advisory reranking returned no result")

        arch_started = time.monotonic()
        architecture = ask_architecture(
            {"binary": binary, "evidence": ["ELF header metadata only"]},
            provider=provider,
            ledger=ledger,
        )
        report["metrics"]["ask_architecture_ms"] = round((time.monotonic() - arch_started) * 1000, 2)
        report["metrics"]["ask_architecture_result"] = _safe_result(architecture)
        if isinstance(architecture, dict) and architecture.get("error"):
            raise RuntimeError(str(architecture.get("code") or "architecture advisory failed"))

        report["metrics"]["usage"] = _safe_result(ledger.status())
        report["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        report["status"] = "passed"
    except ProviderError as exc:
        report["status"] = "failed"
        report["reason"] = f"{exc.code}: {exc.message}"
    except (OSError, ValueError, RuntimeError) as exc:
        report["status"] = "failed"
        report["reason"] = str(exc)[:512]
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()

    _write_report(args.out, report)
    print(f"[jev_benchmark] completed: {report['status']}", file=sys.stderr)
    return 0 if report["status"] in {"passed", "skipped"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
