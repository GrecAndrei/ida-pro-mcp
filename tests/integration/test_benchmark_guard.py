import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "benchmarks"))

from benchmark_guard import parse_means


def test_parse_means_extracts_named_metrics():
    text = """
semantic cached                    mean=   0.274 ms median=   0.250 ms p99=   0.515 ms
focus candidate ranking            mean=   0.015 ms median=   0.013 ms p99=   0.029 ms
"""
    out = parse_means(text)
    assert out["semantic cached"] == 0.274
    assert out["focus candidate ranking"] == 0.015
