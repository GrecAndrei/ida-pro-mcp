"""
Integration tests for schemaboot using real IDA Pro.

These tests launch idat headlessly, ingest the test binary, and verify
that structured queries return correct deterministic results.
"""

import pytest


pytestmark = pytest.mark.skipif(
    not pytest.importorskip("conftest", reason="IDA integration tests disabled"),
    reason="IDA integration tests require licensed IDA Pro",
)


class TestSchemaBootIntegration:
    """End-to-end tests for schemaboot with real IDA analysis."""

    def test_ingest_creates_index(self, ida_runner):
        """Verify ingest builds the SQLite DB and returns stats."""
        script = '''
from schemaboot import schemaboot
result = schemaboot(action="ingest")
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True, f"Ingest failed: {result}"
        assert result.get("ingested", 0) > 0, "No functions ingested"
        assert result.get("elapsed_seconds", 0) > 0, "No elapsed time recorded"

    def test_query_by_api(self, ida_runner):
        """Query functions that call a known API."""
        script = '''
from schemaboot import schemaboot
schemaboot(action="ingest")
result = schemaboot(action="query", constraints={"apis": "VirtualAlloc"}, limit=10)
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        # VirtualAlloc may or may not be present; just verify structure
        assert "functions" in result
        assert "total_matches" in result
        for func in result.get("functions", []):
            assert "ea" in func
            assert "name" in func
            assert "entropy" in func

    def test_query_by_entropy_and_xor(self, ida_runner):
        """Find high-entropy functions with XOR operations."""
        script = '''
from schemaboot import schemaboot
schemaboot(action="ingest")
result = schemaboot(
    action="query",
    constraints={"min_entropy": 6.0, "min_xor_count": 2},
    limit=20,
    order_by="entropy DESC"
)
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        funcs = result.get("functions", [])
        for func in funcs:
            assert func.get("entropy", 0) >= 6.0
            assert func.get("xor_count", 0) >= 2

    def test_query_by_segment(self, ida_runner):
        """Filter functions by segment name."""
        script = '''
from schemaboot import schemaboot
schemaboot(action="ingest")
result = schemaboot(action="query", constraints={"segment": ".text"}, limit=5)
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        for func in result.get("functions", []):
            assert func.get("segment") == ".text"

    def test_get_single_function(self, ida_runner):
        """Retrieve full attributes for a specific function."""
        script = '''
from schemaboot import schemaboot
schemaboot(action="ingest")
# Get first function and query it back
first = schemaboot(action="query", limit=1)
addr = first["functions"][0]["ea"]
result = schemaboot(action="get", addr=addr, include_apis=True, include_strings=True)
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        func = result.get("function", {})
        assert "ea" in func
        assert "name" in func
        assert "bb_count" in func
        assert "cyclomatic_complexity" in func

    def test_stats_returns_aggregates(self, ida_runner):
        """Stats action returns aggregate metrics."""
        script = '''
from schemaboot import schemaboot
schemaboot(action="ingest")
result = schemaboot(action="stats")
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        assert result.get("total_indexed", 0) > 0
        assert "avg_entropy" in result
        assert "avg_bb_count" in result
        assert "segments" in result

    def test_delete_removes_index(self, ida_runner):
        """Delete action removes the SQLite DB."""
        script = '''
from schemaboot import schemaboot
schemaboot(action="ingest")
del_result = schemaboot(action="delete")
with open(RESULT_PATH, "w") as f:
    json.dump(del_result, f)
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        assert "deleted" in result

    def test_query_complex_constraints(self, ida_runner):
        """Query with multiple constraints (has_loops + min_size + min_call_count)."""
        script = '''
from schemaboot import schemaboot
schemaboot(action="ingest")
result = schemaboot(
    action="query",
    constraints={"has_loops": True, "min_size": 100, "min_call_count": 3},
    limit=10
)
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        for func in result.get("functions", []):
            assert func.get("has_loops") is True
            assert func.get("size", 0) >= 100
            assert func.get("call_count", 0) >= 3

    def test_refresh_single_function(self, ida_runner):
        """Refresh updates a single function's attributes."""
        script = '''
from schemaboot import schemaboot
schemaboot(action="ingest")
# Get first function
first = schemaboot(action="query", limit=1)
addr = first["functions"][0]["ea"]
result = schemaboot(action="refresh", addr=addr)
import os
with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
    f.flush()
    os.fsync(f.fileno())
'''
        result = ida_runner.run_script(script, timeout=120)
        assert result.get("ok") is True
        assert result.get("refreshed") == 1
