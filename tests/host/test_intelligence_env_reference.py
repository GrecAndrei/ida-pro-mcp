"""Every intelligence environment variable must be documented.

The wiki documented 7 of the 38 environment variables the intelligence layer
reads. A user configuring the layer had to guess names for the rest, and a
variable added in code would land undocumented without any test noticing. This
scans the source for the variables actually read and requires each to appear in
the reference, so the gap cannot reopen.

It also pins the alias rule, which is easy to break: every budget setting accepts
both a mode-neutral ``IDA_MCP_INTELLIGENCE_*`` name and a ``IDA_MCP_JEV_*`` name,
and the Jev name wins.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src" / "ida_pro_mcp"

WIKI_INTELLIGENCE = REPO_ROOT / "docs" / "wiki" / "core" / "intelligence.md"
WIKI_CLIENT_CONFIG = REPO_ROOT / "docs" / "wiki" / "client-configuration.md"

# Variables read outside the providers package (budgets, switch, config path).
_SEARCH_ROOTS = (
    SRC_ROOT / "host" / "intelligence",
    SRC_ROOT / "host" / "server" / "runtime.py",
    SRC_ROOT / "installer",
)

_VAR_RE = re.compile(r"IDA_MCP_(?:INTELLIGENCE|JEV)_[A-Z0-9_]+")

# Documented elsewhere with a different, non-regex prefix.
_NOT_A_PROVIDER_VAR = frozenset()


def _source_texts() -> list[str]:
    texts: list[str] = []
    for root in _SEARCH_ROOTS:
        if root.is_file():
            texts.append(root.read_text(encoding="utf-8"))
            continue
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            texts.append(path.read_text(encoding="utf-8"))
    return texts


def _read_vars() -> set[str]:
    found: set[str] = set()
    for text in _source_texts():
        found.update(_VAR_RE.findall(text))
    return found - _NOT_A_PROVIDER_VAR


READ_VARS = _read_vars()


def test_the_scan_actually_finds_variables():
    # A silently-empty scan would make every other assertion pass vacuously.
    assert len(READ_VARS) >= 30, f"env var scan found only {len(READ_VARS)}: {sorted(READ_VARS)}"


@pytest.mark.parametrize("name", sorted(READ_VARS))
def test_variable_is_documented(name: str):
    reference = WIKI_INTELLIGENCE.read_text(encoding="utf-8")
    assert name in reference, (
        f"{name} is read by the intelligence layer but is not documented in "
        f"{WIKI_INTELLIGENCE.relative_to(REPO_ROOT)}"
    )


def test_posture_variables_are_documented_where_users_configure_clients():
    # client-configuration.md is where someone editing a client config looks, so
    # the switch and the spend gate must appear there and not only in the
    # deep intelligence page.
    config = WIKI_CLIENT_CONFIG.read_text(encoding="utf-8")
    assert "IDA_MCP_INTELLIGENCE_ENABLED" in config
    assert "IDA_MCP_JEV_ALLOW_UNKNOWN_PRICING" in config
    assert "unknown_pricing" in config


def test_alias_rule_is_documented():
    # The mode-neutral alias is the rule most likely to be broken by a careless
    # refactor, and a user setting only the JEV name must know it still works.
    reference = WIKI_INTELLIGENCE.read_text(encoding="utf-8")
    lowered = reference.lower()
    assert "alias" in lowered, "the intelligence page must explain the alias rule"
    assert "precedence" in lowered or "takes precedence" in lowered, (
        "the intelligence page must say which name wins when both are set"
    )


def test_every_aliased_pair_is_present_in_both_families():
    # Derive the pairs from the source itself so a new alias cannot ship
    # undocumented on the mode-neutral side.
    source = "\n".join(_source_texts())
    pairs = set(
        re.findall(
            r'"(IDA_MCP_JEV_[A-Z0-9_]+)",\s*"(IDA_MCP_INTELLIGENCE_[A-Z0-9_]+)"',
            source,
        )
    )
    assert pairs, "expected at least one JEV/INTELLIGENCE alias pair in the source"
    reference = WIKI_INTELLIGENCE.read_text(encoding="utf-8")
    for jev_name, generic_name in sorted(pairs):
        assert jev_name in reference, f"alias source {jev_name} undocumented"
        assert generic_name in reference, f"alias source {generic_name} undocumented"


def test_budget_defaults_match_the_source():
    # Defaults are the most quietly wrong thing in a reference table, so pin the
    # ones the wiki states numerically against the code that applies them.
    from ida_pro_mcp.host.intelligence.providers.usage_accounting import BudgetConfig

    config = BudgetConfig.from_env({})
    reference = WIKI_INTELLIGENCE.read_text(encoding="utf-8")
    assert config.request_output_tokens == 2048
    assert config.token_budget_session == 100_000
    assert config.token_budget_daily == 500_000
    assert config.cost_budget_session == 5.0
    assert config.cost_budget_daily == 20.0
    assert config.request_count_session == 200
    assert config.request_count_daily == 2_000
    assert config.budget_mode == "block"
    assert config.unknown_pricing_blocks is True
    for stated in ("2048", "100000", "500000", "2000", "200"):
        assert stated in reference, f"default {stated} is not stated in the reference"
