"""Host-side MCP/JSON-RPC stdio server package.

Exposes the console-script entry point ``main`` (declared in pyproject as
``ida_pro_mcp.host.server:main``) via a lazy module ``__getattr__``.

The laziness is deliberate: ``host.server`` is imported transitively very
early (``host.schemas_data`` imports ``host.server.tool_registry`` while
``host.schemas`` is still initializing). Eagerly importing ``server.py``
from this package ``__init__`` would re-enter ``server.py`` -> ``schemas``
mid-initialization and hit a circular import. Resolving ``main`` on first
access keeps the package import light and only pulls in the heavy server
module when the entry point actually asks for ``main``.
"""

__all__ = ["main"]


def __getattr__(name):
    if name == "main":
        from .server import main as _main

        return _main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(list(globals()) + __all__)