# Compatibility shim (TODO: deprecate — import from .intelligence.context_semantic directly)
import sys
try:
    from .intelligence import context_semantic as _target
except (ImportError, ValueError):
    try:
        from ida_pro_mcp.host.intelligence import context_semantic as _target
    except (ImportError, ValueError):
        import os
        _dir = os.path.dirname(os.path.abspath(__file__))
        if _dir not in sys.path:
            sys.path.append(_dir)
        from intelligence import context_semantic as _target

sys.modules[__name__] = _target
globals().update(_target.__dict__)
