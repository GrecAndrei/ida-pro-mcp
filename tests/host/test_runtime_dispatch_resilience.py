import os
import sys
from unittest.mock import Mock

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.services import (
    MCPError,  # noqa: E402
    Session,  # noqa: E402
)


def _make_session() -> Session:
    return Session(
        session_id="A1B2C3D4",
        idb_path="/tmp/a.i64",
        binary_path="/tmp/a.bin",
    )

