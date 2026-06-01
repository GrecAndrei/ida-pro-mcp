"""Static test: bridgerag must use the canonical HybridQueryBuilder for its
SQL WHERE clause, not a third hand-rolled implementation.

Background: bridgerag previously had its own `_build_where_clause_local`
function that duplicated the legacy constraint dialect. Three copies of
this builder (schemaboot, hybrid_search, bridgerag) drift over time. The
fix was to delete the local copy and route through
`HybridQueryBuilder.build_legacy`.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


BRIDGERAG_PATH = os.path.join(
    SRC, "ida_pro_mcp", "ida_mcp", "tools", "bridgerag.py"
)


def test_bridgerag_has_no_local_where_clause_builder():
    text = open(BRIDGERAG_PATH, encoding="utf-8").read()
    assert "_build_where_clause_local" not in text, (
        "bridgerag must not contain a local SQL WHERE clause builder; "
        "use HybridQueryBuilder.build_legacy instead"
    )


def test_bridgerag_uses_hybrid_query_builder():
    text = open(BRIDGERAG_PATH, encoding="utf-8").read()
    assert "HybridQueryBuilder" in text, (
        "bridgerag must import HybridQueryBuilder to build SQL constraints"
    )
    assert "build_legacy" in text, (
        "bridgerag must call HybridQueryBuilder.build_legacy to build SQL constraints"
    )
