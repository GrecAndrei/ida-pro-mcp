"""Static test: the legacy `host.intelligence` shim module must not exist.

The shim was a re-export wrapper that pointed at `intelligence_core` and
`intelligence_context`. Callers must import the canonical modules directly.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


def test_shim_module_file_is_gone():
    shim = os.path.join(SRC, "ida_pro_mcp", "host", "intelligence.py")
    assert not os.path.exists(shim), (
        f"legacy shim {shim} must be removed; "
        "importers should use ida_pro_mcp.host.intelligence_core / intelligence_context"
    )


def test_shim_module_cannot_be_imported():
    try:
        import ida_pro_mcp.host.intelligence  # noqa: F401
    except ImportError:
        return
    raise AssertionError(
        "ida_pro_mcp.host.intelligence must not be importable; "
        "use intelligence_core or intelligence_context"
    )


def test_canonical_modules_are_importable():
    import ida_pro_mcp.host.intelligence_core
    import ida_pro_mcp.host.intelligence_context
    from ida_pro_mcp.host.intelligence_core import (
        BgeCodeEmbedder,
        BehaviorClassifier,
        FunctionEmbeddingIndex,
        INTEL_PROFILE,
        PreferenceMemoryBank,
        SemanticObject,
        SemanticObjectIndex,
        _extract_signature,
        emit_preference_suggestion,
    )
    from ida_pro_mcp.host.intelligence_context import ContextAssembler, get_assembler
    # Smoke-construct: classes are reachable
    assert ContextAssembler is not None
    assert get_assembler is not None
    assert BgeCodeEmbedder is not None
    assert BehaviorClassifier is not None
    assert FunctionEmbeddingIndex is not None
    assert SemanticObject is not None
    assert SemanticObjectIndex is not None
    assert PreferenceMemoryBank is not None
    assert _extract_signature is not None
    assert emit_preference_suggestion is not None
    assert isinstance(INTEL_PROFILE, bool)
