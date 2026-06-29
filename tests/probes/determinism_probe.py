#!/usr/bin/env python3
"""
Determinism CI probe: run a canonical call sequence twice and compare stable fields.
Usage: python tests/determinism_probe.py [--binary tests/data/test_binary.exe]
"""
import argparse
import hashlib
import json
import os
import sys

# Must be run from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.tool_sweep_probe import MCPClient, decode_content


def _hashify(obj):
    """Deterministic JSON serialization for hashing."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]


def _stable_subset(resp: dict) -> dict:
    """Extract fields that should be deterministic across runs."""
    if not isinstance(resp, dict):
        return {}
    out = {}
    for key in ("ok", "count", "tool", "action", "results", "findings", "suggestions"):
        if key in resp:
            out[key] = resp[key]
    return out


def run_probe(binary_path: str) -> int:
    env = os.environ.copy()
    sequences = [
        ("session", {"action": "create", "binary_path": binary_path, "force_new": True}),
        ("idb", {"action": "meta"}),
        ("data", {"action": "functions", "count": 5}),
        ("calc", {"action": "eval", "expr": "0x1000 + 0x20"}),
        ("code", {"action": "disasm", "addr": "0x0"}),
    ]

    results_run_a = []
    results_run_b = []

    for run_idx, results_list in enumerate([results_run_a, results_run_b]):
        client = MCPClient(sys.executable, ["-u", "ida_mcp_stdio.py"], env=env)
        try:
            init = client.call(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "determinism-probe", "version": "1.0"},
                },
                timeout=30,
            )
            if "error" in init:
                print(f"[FAIL] Run {run_idx + 1} init error: {init}")
                return 1

            for tool, args in sequences:
                resp = decode_content(
                    client.call("tools/call", {"name": tool, "arguments": args}, timeout=120)
                )
                results_list.append((tool, args.get("action") or args.get("action", ""), resp))
        finally:
            client.stop()

    mismatches = 0
    for (t_a, a_a, r_a), (_t_b, _a_b, r_b) in zip(results_run_a, results_run_b, strict=False):
        stable_a = _stable_subset(r_a)
        stable_b = _stable_subset(r_b)
        h_a = _hashify(stable_a)
        h_b = _hashify(stable_b)
        match = h_a == h_b
        status = "MATCH" if match else "MISMATCH"
        print(f"  {t_a}.{a_a}: {status}  (hash {h_a} vs {h_b})")
        if not match:
            mismatches += 1

    print(f"\nTotal calls: {len(sequences)}  Mismatches: {mismatches}")
    return 0 if mismatches == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="tests/data/test_binary.exe")
    args = parser.parse_args()
    binary_path = os.path.abspath(args.binary)
    if not os.path.exists(binary_path):
        print(f"[FAIL] Binary not found: {binary_path}")
        return 1
    return run_probe(binary_path)


if __name__ == "__main__":
    raise SystemExit(main())
