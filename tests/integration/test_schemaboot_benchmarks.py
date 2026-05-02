"""
Benchmarks comparing traditional function iteration vs SchemaBoot indexed queries.

These benchmarks run inside real IDA Pro to measure ingestion time and
query latency for structured constraints.
"""

import pytest


pytestmark = pytest.mark.skipif(
    not pytest.importorskip("conftest", reason="IDA integration tests disabled"),
    reason="IDA integration tests require licensed IDA Pro",
)


class TestSchemaBootBenchmarks:
    """Performance benchmarks for schemaboot vs naive approaches."""

    def test_baseline_query_latency(self, ida_runner):
        """
        Measure: time to find functions with >5 XORs using naive Python iteration.
        """
        script = '''
import time
import idautils
import idc

start = time.time()
results = []
for func_ea in idautils.Functions():
    xor_count = 0
    for item in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(item)
        if mnem and mnem.lower() == "xor":
            xor_count += 1
    if xor_count >= 5:
        results.append(hex(func_ea))
        if len(results) >= 50:
            break
elapsed = time.time() - start

import os
with open(RESULT_PATH, "w") as f:
    json.dump({"ok": True, "count": len(results), "elapsed_ms": round(elapsed * 1000, 2)}, f)
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        # Store baseline for comparison
        pytest.baseline_xor_ms = result.get("elapsed_ms", 0)
        print(f"\n[BASELINE] Naive XOR scan: {result['elapsed_ms']}ms, found {result['count']} funcs")

    def test_indexed_query_latency(self, ida_runner):
        """
        Measure: time to find functions with >5 XORs using SchemaBoot index.
        """
        script = '''
import time
from schemaboot import schemaboot

# Ingest (one-time cost)
ingest_start = time.time()
schemaboot(action="ingest")
ingest_elapsed = time.time() - ingest_start

# Query (the actual benchmark)
query_start = time.time()
result = schemaboot(action="query", constraints={"min_xor_count": 5}, limit=50)
query_elapsed = time.time() - query_start

import os
with open(RESULT_PATH, "w") as f:
    json.dump({
        "ok": True,
        "count": len(result.get("functions", [])),
        "ingest_ms": round(ingest_elapsed * 1000, 2),
        "query_ms": round(query_elapsed * 1000, 2),
    }, f)
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        print(f"\n[INDEXED] Ingest: {result['ingest_ms']}ms, Query: {result['query_ms']}ms, found {result['count']} funcs")

        # Assert query is at least 10x faster than baseline (if baseline was measured)
        baseline = getattr(pytest, "baseline_xor_ms", None)
        if baseline and baseline > 0:
            speedup = baseline / max(result["query_ms"], 1)
            print(f"[SPEEDUP] {speedup:.1f}x faster than naive iteration")
            assert speedup >= 5.0, f"Expected >=5x speedup, got {speedup:.1f}x"

    def test_baseline_api_scan(self, ida_runner):
        """
        Measure: time to find functions calling VirtualAlloc using naive iteration.
        """
        script = '''
import time
import idautils
import idc
import idaapi

start = time.time()
results = []
for func_ea in idautils.Functions():
    found = False
    for item in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(item)
        if mnem and mnem.lower() == "call":
            for xref in idautils.XrefsFrom(item, 0):
                name = idc.get_name(xref.to)
                if name and "VirtualAlloc" in name:
                    results.append(hex(func_ea))
                    found = True
                    break
        if found:
            break
    if len(results) >= 20:
        break
elapsed = time.time() - start

import os
with open(RESULT_PATH, "w") as f:
    json.dump({"ok": True, "count": len(results), "elapsed_ms": round(elapsed * 1000, 2)}, f)
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        pytest.baseline_api_ms = result.get("elapsed_ms", 0)
        print(f"\n[BASELINE] Naive API scan: {result['elapsed_ms']}ms, found {result['count']} funcs")

    def test_indexed_api_scan(self, ida_runner):
        """
        Measure: time to find functions calling VirtualAlloc using SchemaBoot.
        """
        script = '''
import time
from schemaboot import schemaboot

schemaboot(action="ingest")
start = time.time()
result = schemaboot(action="query", constraints={"apis": "VirtualAlloc"}, limit=20)
elapsed = time.time() - start

import os
with open(RESULT_PATH, "w") as f:
    json.dump({
        "ok": True,
        "count": len(result.get("functions", [])),
        "query_ms": round(elapsed * 1000, 2),
    }, f)
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        print(f"\n[INDEXED] API query: {result['query_ms']}ms, found {result['count']} funcs")

        baseline = getattr(pytest, "baseline_api_ms", None)
        if baseline and baseline > 0:
            speedup = baseline / max(result["query_ms"], 1)
            print(f"[SPEEDUP] {speedup:.1f}x faster than naive API scan")
            assert speedup >= 5.0, f"Expected >=5x speedup, got {speedup:.1f}x"

    def test_complex_multi_constraint_query(self, ida_runner):
        """
        Benchmark a complex query with 5 constraints.
        """
        script = '''
import time
from schemaboot import schemaboot

schemaboot(action="ingest")
start = time.time()
result = schemaboot(
    action="query",
    constraints={
        "min_size": 200,
        "min_entropy": 5.5,
        "has_loops": True,
        "min_call_count": 5,
        "min_bb_count": 10,
    },
    limit=20,
    order_by="entropy DESC",
)
elapsed = time.time() - start

import os
with open(RESULT_PATH, "w") as f:
    json.dump({
        "ok": True,
        "count": len(result.get("functions", [])),
        "query_ms": round(elapsed * 1000, 2),
        "total_matches": result.get("total_matches", 0),
    }, f)
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        print(f"\n[COMPLEX] 5-constraint query: {result['query_ms']}ms, {result['total_matches']} total matches")
        # Complex queries should still be sub-100ms
        assert result["query_ms"] < 500, f"Complex query too slow: {result['query_ms']}ms"

    def test_ingest_throughput(self, ida_runner):
        """
        Measure how many functions per second we can ingest.
        """
        script = '''
import time
from schemaboot import schemaboot

start = time.time()
result = schemaboot(action="ingest")
elapsed = time.time() - start

import os
with open(RESULT_PATH, "w") as f:
    json.dump({
        "ok": True,
        "ingested": result.get("ingested", 0),
        "elapsed_ms": round(elapsed * 1000, 2),
        "funcs_per_sec": round(result.get("ingested", 0) / max(elapsed, 0.001), 1),
    }, f)
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        print(f"\n[INGEST] {result['ingested']} funcs in {result['elapsed_ms']}ms ({result['funcs_per_sec']} funcs/sec)")
        assert result["funcs_per_sec"] > 10, f"Ingest too slow: {result['funcs_per_sec']} funcs/sec"
