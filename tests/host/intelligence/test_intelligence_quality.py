from __future__ import annotations

import os
import sys

# Ensure benchmarks folder is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "benchmarks"))

from benchmark_quality_metrics import (
    evaluate_bayesian_confidence_propagation,
    evaluate_federated_utility_stability,
    evaluate_triage_prioritization_quality,
)


def test_triage_prioritization_quality():
    evaluate_triage_prioritization_quality()


def test_bayesian_confidence_propagation():
    evaluate_bayesian_confidence_propagation()


def test_federated_utility_stability():
    evaluate_federated_utility_stability()
