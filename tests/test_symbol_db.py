import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.symbol_db import SymbolDB


def test_symbol_db_upsert_and_lookup():
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "symbols.db")
        db = SymbolDB(db_path)
        rid = db.upsert_symbol(
            {
                "symbol_name": "wifi_tx_frame",
                "source_session": "ABC12345",
                "source_binary": "/tmp/fw.bin",
                "source_addr": "0x1000",
                "chip_family": "AIC8800D80",
                "fingerprint": "fp-1",
                "callgraph_hash": "cg-1",
                "strings": ["wifi", "tx"],
                "confidence": 0.95,
            }
        )
        assert rid > 0

        rid2 = db.upsert_symbol(
            {
                "symbol_name": "wifi_tx_frame",
                "source_session": "ABC12345",
                "source_binary": "/tmp/fw2.bin",
                "source_addr": "0x2000",
                "chip_family": "AIC8800D80",
                "fingerprint": "fp-1",
                "callgraph_hash": "cg-1",
                "strings": ["wifi", "tx"],
                "confidence": 0.99,
            }
        )
        assert rid2 == rid

        hits = db.query_symbols("wifi")
        assert hits
        assert hits[0]["symbol_name"] == "wifi_tx_frame"

        fp_hits = db.lookup_by_fingerprint("fp-1")
        assert fp_hits
        assert fp_hits[0]["symbol_name"] == "wifi_tx_frame"

        stats = db.stats_by_chip()
        assert any(s.get("chip_family") == "AIC8800D80" for s in stats)
