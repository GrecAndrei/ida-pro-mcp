"""Step 10: code(action="analyze") deprecated in favour of
agent(action="analyze_function").

The code tool's "analyze" action used to be a 120-line comprehensive
function analyser. We now deprecate it (it returns a thin shim with
a "deprecated" key + a "hint" pointing callers to
agent(action="analyze_function", ...)).

This test verifies:
  - code tool's Literal no longer advertises "analyze" as a primary
    action (it stays for back-compat but is documented as deprecated)
  - agent tool still has "analyze_function" action
  - prompts no longer recommend code(action="analyze")
  - agent.analyze_function no longer calls code_tool(action="analyze")
"""
import os
import re

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as f:
        return f.read()

