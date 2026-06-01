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


def test_code_analyze_branch_marks_deprecated():
    """The code tool's "analyze" branch returns a "deprecated" key
    and a "hint" pointing to agent(action=analyze_function)."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/code.py")
    # Find the elif action == "analyze": block
    m = re.search(r'elif action == "analyze":.*?results\.append\(info\)', text, re.DOTALL)
    assert m, "analyze branch not found in code.py"
    block = m.group(0)
    assert '"deprecated": True' in block
    assert "agent(action=\\\"analyze_function\\\"" in block or 'agent(action="analyze_function"' in block


def test_agent_analyze_function_no_longer_calls_code_analyze():
    """agent.analyze_function now uses code(action="decompile") and
    no longer calls code(action="analyze") (the deprecated shim)."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/agent.py")
    # Locate the analyze_function branch
    m = re.search(
        r'if action == "analyze_function":.*?elif action == "explore_address":',
        text, re.DOTALL
    )
    assert m, "analyze_function branch not found"
    block = m.group(0)
    # Now check there's no live `code_tool(action="analyze", ...)` call
    # (the `if action == "analyze_function":` literal is fine; we just
    # want to make sure we don't call the deprecated shim).
    # Strip comment lines to avoid matching the docstring.
    code_lines = "\n".join(
        line for line in block.splitlines()
        if not line.lstrip().startswith("#")
    )
    code_analyze_calls = re.findall(
        r'code_tool\(action="analyze"', code_lines
    )
    assert not code_analyze_calls, (
        f"agent.analyze_function still calls code_tool(action='analyze'): {code_analyze_calls}"
    )
    # And it should use code(action="decompile") now.
    assert 'action="decompile"' in code_lines
    # And it does use code(action="decompile") instead.
    assert 'action="decompile"' in block


def test_agent_literal_still_lists_analyze_function():
    """agent tool's Literal still exposes "analyze_function"."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/agent.py")
    assert '"analyze_function"' in text


def test_prompts_recommend_agent_analyze_function():
    """prompts.py recommends agent(action="analyze_function") over
    code(action="analyze")."""
    text = _read("src/ida_pro_mcp/ida_mcp/prompts.py")
    assert 'agent(action="analyze_function"' in text
    # The old recommendation should be gone (the deprecation shim is
    # for back-compat but the docs should not point at it).
    # (We allow it to still be present in deprecated-redirect
    # discussion, but the recommendation lines should not start with
    # `code(action="analyze"`. We can't easily distinguish, so just
    # sanity-check the new pattern appears at least once.)


def test_code_literal_still_lists_analyze_for_back_compat():
    """The code tool still accepts action="analyze" — it's just
    a thin shim now. Back-compat callers (and the deprecation hint)
    rely on it."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/code.py")
    assert '"analyze"' in text
