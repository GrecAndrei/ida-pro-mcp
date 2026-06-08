# Compatibility shim (TODO: deprecate — import from .intelligence.embeddings directly)
import sys
try:
    from .intelligence import embeddings as _target
except (ImportError, ValueError):
    try:
        from ida_pro_mcp.host.intelligence import embeddings as _target
    except (ImportError, ValueError):
        import os
        _dir = os.path.dirname(os.path.abspath(__file__))
        if _dir not in sys.path:
            sys.path.append(_dir)
        from intelligence import embeddings as _target

sys.modules[__name__] = _target
globals().update(_target.__dict__)
