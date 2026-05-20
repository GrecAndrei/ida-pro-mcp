"""
Compatibility wrapper for the refactored intelligence stack.

Public callers continue importing from `host.intelligence`, while the actual
implementations now live in `intelligence_core.py` and `intelligence_context.py`.
"""

import urllib.error
import urllib.request

from .intelligence_core import (
    BgeCodeEmbedder,
    FunctionEmbeddingIndex,
    PreferenceMemoryBank,
    BehaviorClassifier,
    INTEL_PROFILE,
    emit_memrl_suggestion,
    _extract_signature,
)
from .intelligence_context import ContextAssembler, get_assembler
