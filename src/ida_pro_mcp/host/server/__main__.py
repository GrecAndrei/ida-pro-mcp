"""``python -m ida_pro_mcp.host.server`` entry point.

Runs the stdio MCP server. The package ``__init__`` is intentionally light
(`main` is resolved lazily via ``__getattr__``), so by the time this
``__main__`` imports ``server.py`` the package is already fully initialized
and the ``server`` -> ``schemas`` -> ``schemas_data`` -> ``host.server.*``
import chain cannot cycle.
"""
from .server import main

raise SystemExit(main())
