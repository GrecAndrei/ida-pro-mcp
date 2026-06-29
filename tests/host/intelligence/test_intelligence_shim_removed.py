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
        "importers should use ida_pro_mcp.host.intelligence.core / intelligence.context"
    )


def test_shim_module_cannot_be_imported():
    # Now that 'intelligence' is a package directory, it is importable.
    import ida_pro_mcp.host.intelligence
    assert ida_pro_mcp.host.intelligence is not None


def test_canonical_modules_are_importable():
    import ida_pro_mcp.host.intelligence.context
    import ida_pro_mcp.host.intelligence.core
    from ida_pro_mcp.host.intelligence.core import (
        INTEL_PROFILE,
        BehaviorClassifier,
        BgeCodeEmbedder,
        FunctionEmbeddingIndex,
        _extract_signature,
    )
    from ida_pro_mcp.services import ContextAssembler, get_assembler
    # Smoke-construct: classes are reachable
    assert ContextAssembler is not None
    assert get_assembler is not None
    assert BgeCodeEmbedder is not None
    assert BehaviorClassifier is not None
    assert FunctionEmbeddingIndex is not None
    assert _extract_signature is not None
    assert isinstance(INTEL_PROFILE, bool)
