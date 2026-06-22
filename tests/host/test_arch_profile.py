import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.arch_profile import normalize_arch_options, infer_binary_arch_profile


def test_normalize_arch_options_aliases():
    out, meta = normalize_arch_options(
        {
            "processor": "x86_64",
            "endian": "LE",
            "loader_options": {"k": "v"},
        }
    )
    assert out["processor"] == "metapc"
    assert out["bitness"] == 64
    assert out["endian"] == "little"
    assert out["value"] == {"k": "v"}
    assert meta.get("normalizations")


def test_infer_binary_arch_profile_raw_cortex_m():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        # SP in RAM, reset vector thumb bit set -> Cortex-M heuristic.
        tf.write((0x20001000).to_bytes(4, "little"))
        tf.write((0x08000101).to_bytes(4, "little"))
        tf.write(b"\x00" * 64)
        path = tf.name
    try:
        inf = infer_binary_arch_profile(path)
        assert inf["file_kind"] == "raw"
        assert inf["processor"] == "arm"
        assert inf["bitness"] == 32
        assert inf["endian"] == "little"
        assert float(inf["confidence"]) >= 0.9
    finally:
        os.unlink(path)


def test_infer_binary_arch_profile_raw_ambiguous_does_not_force_processor():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        # Weak x86-ish signal: enough for candidates, below auto-apply threshold.
        tf.write((b"\xe8" + (b"\x00" * 63)) * 8)
        path = tf.name
    try:
        inf = infer_binary_arch_profile(path)
        assert inf["file_kind"] == "raw"
        # Ambiguous raw blobs should not be hard-forced into one processor.
        assert inf.get("processor") in (None, "",)
        assert isinstance(inf.get("candidates"), list)
        assert len(inf.get("candidates") or []) >= 1
        assert inf.get("reason")
    finally:
        os.unlink(path)


def test_infer_binary_arch_profile_wffw_chip_profile():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        blob = bytearray(b"\x00" * 256)
        blob[0:4] = (0x20001000).to_bytes(4, "little")
        blob[4:8] = (0x00120001).to_bytes(4, "little")
        blob[0x20:0x24] = b"WFFW"
        tf.write(blob)
        path = tf.name
    try:
        inf = infer_binary_arch_profile(path)
        assert inf["file_kind"] == "raw"
        assert str(inf.get("chip_family", "")).lower() in {"aic8800d80", "aic8800d80".lower()}
        assert inf.get("load_base") is not None
        assert isinstance(inf.get("memory_map"), list)
        assert isinstance(inf.get("peripheral_addresses"), list)
    finally:
        os.unlink(path)


def test_infer_binary_arch_profile_cortex_assigns_chip_family():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write((0x20002000).to_bytes(4, "little"))
        tf.write((0x08000101).to_bytes(4, "little"))
        tf.write(b"\x00" * 64)
        path = tf.name
    try:
        inf = infer_binary_arch_profile(path)
        assert inf["processor"] == "arm"
        assert inf.get("chip_family") in {"STM32", "Generic Cortex-M"}
        assert inf.get("load_base") is not None
    finally:
        os.unlink(path)


def test_infer_binary_arch_profile_packed_idb_magic():
    """IDA2 magic → packed_idb detection with no processor override."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".i64") as tf:
        # IDA2 magic (0x49444132) identifies a packed IDA database.
        tf.write(b"IDA2")
        tf.write(b"\x00" * 256)
        path = tf.name
    try:
        inf = infer_binary_arch_profile(path)
        assert inf["file_kind"] == "packed_idb"
        assert float(inf["confidence"]) == 1.0
        # Must NOT set processor/bitness — let IDA load the DB as-is.
        assert inf.get("processor") is None
        assert inf.get("bitness") is None
    finally:
        os.unlink(path)
