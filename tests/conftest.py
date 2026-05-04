# tests/conftest.py
import os

# Disable deterministic stuck-detection during tests so repeated tool calls
# in test suites don't trigger blocking interventions.
os.environ.setdefault("IDA_MCP_DISABLE_STUCK_DETECTION", "1")

# Disable rate limiting during tests to avoid test failures from rapid sequential calls.
os.environ.setdefault("IDA_MCP_DISABLE_RATE_LIMIT", "1")
