"""WO-R2a — Architecture A Phase 1: host-side radare2/Rizin subprocess engine.

Covers ``host/r2_engine.py`` (R2Engine) and ``host/server/server_r2.py``
(ServerR2Mixin) plus the ``server_dispatch.py`` ``r2`` branch and the
``IDA_MCP_R2_*`` config knobs and ``R2_*`` error codes.

Design contract under test (from the research paper §8/§9):
  * Optional, default-off: every op is a per-call stateless one-shot
    (``rz -q -c`` / ``r2 -q -c``) over the raw binary path.
  * Subprocess-only hardening: scrubbed env (never leak
    ``IDA_MCP_SESSION_TOKEN``), restricted cwd, wall-clock cap, stderr
    capture, ``R2_NOPLUGINS``, no shell interpolation of the path, and
    target-path canonicalization via the memory allow-root logic.
  * Works during safe_mode and when IDA is down (no runtime-alive /
    safe-mode-clear requirement).
  * Every op returns the standard host envelope via ``make_error`` /
    ``is_error_result``.

The tests are hermetic: a tiny fake-r2 shim subprocess stands in for
``rz``/``r2``/``rz-bin``, so the base CI matrix needs no r2. A second set of
contract tests runs against a real ``rz``/``r2`` when one is installed
(optional ``apt install rz`` CI job). No live IDA anywhere.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host import r2_engine as r2_engine_mod
from ida_pro_mcp.host.errors import MCPError, is_error_result, make_error
from ida_pro_mcp.host.r2_engine import R2Engine
from ida_pro_mcp.host.server.server import IDAMCPServer

# ---------------------------------------------------------------------------
# Hermetic fake-r2 shim
# ---------------------------------------------------------------------------

# A tiny script the engine drives as if it were rz/r2/rz-bin. It emulates:
#   rz -v                                   -> version line
#   rz-bin -Ij <path>                       -> {"info": {...}} JSON
#   rz-bin -ej <path>                       -> {"entries": [...]} JSON
#   rz -q [-m 0xBASE] -c '<cmds>' <path>    -> disassembly lines tagged by arch
# The arch-tagged mnemonics make the engine's disagreement computation
# deterministic: rv32/rv64 decode 4-byte words, thumb/metapc decode 2-byte
# words, and every mnemonic differs, so every aligned offset disagrees.
_FAKE_RZ_SHIM = r"""#!/usr/bin/env python3
import os
import re
import sys

args = sys.argv[1:]


def _after(flag):
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            return args[i + 1]
    return None


if "-v" in args:
    print("radare2 6.1.6 +0 abi:107 @ linux-x86_64")
    sys.exit(0)

if "-Ij" in args:
    print(
        '{"info":{"arch":"riscv","binsz":64,"bintype":"bin","bits":32,'
        '"class":"raw","endian":"little","machine":"riscv","os":"",'
        '"havecode":true,"checksums":{}}}'
    )
    sys.exit(0)

if "-ej" in args:
    print(
        '{"entries":[{"vaddr":0,"paddr":0,"baddr":0,"laddr":0,'
        '"type":"program"}]}'
    )
    sys.exit(0)

cmd = _after("-c")
if cmd is None:
    print("error: no -c command", file=sys.stderr)
    sys.exit(1)

arch = "unknown"
m = re.search(r"asm\.arch=([a-z0-9]+)", cmd)
if m:
    arch = m.group(1)

seek = 0
m = re.search(r"s 0x([0-9a-fA-F]+)", cmd)
if m:
    seek = int(m.group(1), 16)

size = 16
m = re.search(r"pD (\d+)", cmd)
if m:
    size = int(m.group(1))

step = 4 if arch == "riscv" else 2
count = max(1, size // step)
for i in range(count):
    addr = seek + i * step
    hexbytes = "13" + "00" * (step - 1)
    print(f"0x{addr:08x} {hexbytes} {arch}_i{i}")
sys.exit(0)
"""


def _write_shim(tmp_path, content=_FAKE_RZ_SHIM, name="fake_rz.py") -> str:
    """Write an executable shim and return its absolute path."""
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
class _FakeIdaProcess:
    """A fake idat subprocess that is always alive but cannot be killed."""

    pid = 2147483647

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 1


@pytest.fixture
def fake_shim(tmp_path):
    return _write_shim(tmp_path)


@pytest.fixture
def fake_engine(fake_shim, monkeypatch):
    """R2Engine driven entirely by the hermetic fake-r2 shim."""
    monkeypatch.setattr(r2_engine_mod, "R2_BIN", fake_shim)
    monkeypatch.setattr(r2_engine_mod, "R2_BININFO_BIN", fake_shim)
    monkeypatch.setattr(r2_engine_mod, "R2_TIMEOUT_SECONDS", 5.0)
    engine = R2Engine()
    engine.timeout = 5.0
    return engine


def _ensure_real_r2_engine():
    """Return an R2Engine pointed at a real rz/r2, or None when absent."""
    rz = shutil.which("rz") or shutil.which("r2")
    if not rz:
        return None
    bininfo = shutil.which("rz-bin") or shutil.which("rabin2")
    if not bininfo:
        return None
    return R2Engine(bin_path=rz, bininfo_bin=bininfo, timeout=20.0)


@pytest.fixture
def real_engine():
    """Real rz/r2 engine, or pytest.skip when none is installed."""
    engine = _ensure_real_r2_engine()
    if engine is None:
        pytest.skip("no real rz/r2 installed (install rz for the real-engine CI job)")
    return engine


@pytest.fixture
def engines(fake_engine, real_engine):
    """Both engines — the hermetic fake plus real rz when available."""
    return [fake_engine, real_engine]


@pytest.fixture
def server(tmp_path, monkeypatch, fake_shim):
    """IDAMCPServer with the r2 tool pointing at the fake shim."""
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    # Some safe-mode fixtures here open via the experimental background path.
    monkeypatch.setenv("IDA_MCP_BACKGROUND_OPEN", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    monkeypatch.setattr(r2_engine_mod, "R2_BIN", fake_shim)
    monkeypatch.setattr(r2_engine_mod, "R2_BININFO_BIN", fake_shim)
    monkeypatch.setattr(r2_engine_mod, "R2_TIMEOUT_SECONDS", 5.0)
    srv = IDAMCPServer()
    monkeypatch.setattr(srv, "_ensure_runtime_and_idb", lambda session: None)
    srv.safe_mode_poll_seconds = 0.05
    yield srv
    srv.shutdown()


def _open_background_pending(server, binary_path):
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "ida_open_background",
                "arguments": {"binary_path": binary_path},
            },
        }
    )
    result = response["result"]["structuredContent"]
    assert result.get("ok") is True
    return server.session_mgr.get_session(result["session_id"]), result


def _write_raw_bin(tmp_path, name="target.bin", data=None):
    """Write an opaque raw blob and return its absolute path."""
    path = tmp_path / name
    path.write_bytes(data or (b"\x13\x00\x00\x00\x00\x00\x00\x00" * 8))
    return str(path)


# ---------------------------------------------------------------------------
# Engine: status
# ---------------------------------------------------------------------------
def test_engine_status_available(fake_engine):
    res = fake_engine.status()
    assert res.get("ok") is True
    assert res.get("available") is True
    assert res.get("variant") == "radare2"
    assert res.get("version") == "6.1.6"
    assert res.get("bin")


def test_engine_status_unavailable_when_bin_missing(fake_engine):
    fake_engine.bin_path = "/nonexistent/rz"
    res = fake_engine.status()
    # An absent engine is the expected default-off state, not an error.
    assert res.get("ok") is True
    assert res.get("available") is False
    assert "R2" in res.get("reason", "") or "rz" in res.get("reason", "")


def test_engine_status_real_envelope(real_engine):
    res = real_engine.status()
    assert res.get("ok") is True
    assert res.get("available") is True
    assert res.get("variant") in ("rizin", "radare2", "unknown")
    assert res.get("version")


# ---------------------------------------------------------------------------
# Engine: bininfo
# ---------------------------------------------------------------------------
def test_engine_bininfo_parses_rz_bin_json(fake_engine, tmp_path):
    binary = _write_raw_bin(tmp_path)
    res = fake_engine.bininfo(binary)
    assert is_error_result(res) is False
    assert res.get("ok") is True
    assert res["filetype"] == "bin"
    assert res["arch"] == "riscv"
    assert res["endian"] == "little"
    assert res["bits"] == 32
    # shim -ej provides one entry
    assert isinstance(res["entries"], list)
    assert res["entries"][0]["type"] == "program"
    assert res["raw"]["bintype"] == "bin"


def test_engine_bininfo_missing_binary(fake_engine, tmp_path):
    res = fake_engine.bininfo(str(tmp_path / "nope.bin"))
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.R2_BINARY_NOT_FOUND
    assert res.get("category") == "user"
    assert res.get("hint")


def test_engine_bininfo_engine_missing(fake_engine, tmp_path, monkeypatch):
    monkeypatch.setattr(r2_engine_mod, "R2_BININFO_BIN", "/nonexistent/rz-bin")
    fake_engine.bininfo_bin = "/nonexistent/rz-bin"
    binary = _write_raw_bin(tmp_path)
    res = fake_engine.bininfo(binary)
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.R2_ENGINE_START_FAILED
    assert res.get("recoverable") is True


# ---------------------------------------------------------------------------
# Engine: load_hints
# ---------------------------------------------------------------------------
def test_engine_load_hints_merges_bininfo_and_context(fake_engine, tmp_path):
    binary = _write_raw_bin(tmp_path)
    res = fake_engine.load_hints(binary)
    assert is_error_result(res) is False
    assert res.get("ok") is True
    # bininfo (from the shim) supplies the processor when nothing else does.
    assert res["load_hints"]["processor"] == "riscv"
    assert res["load_hints"]["bitness"] == 32
    assert res["filetype"] == "bin"
    assert res["arch_context_applied"] is False

    explicit = fake_engine.load_hints(
        binary,
        arch_context={"processor": "riscv", "bitness": 64, "baseaddr": "0x20000"},
    )
    # Explicit caller options always override r2's guesses.
    assert explicit["load_hints"]["processor"] == "riscv"
    assert explicit["load_hints"]["bitness"] == 64
    assert explicit["load_hints"]["baseaddr"] == "0x20000"
    assert explicit["arch_context_applied"] is True


def test_engine_load_hints_missing_binary(fake_engine, tmp_path):
    res = fake_engine.load_hints(str(tmp_path / "gone.bin"))
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.R2_BINARY_NOT_FOUND


# ---------------------------------------------------------------------------
# Engine: disassemble_hypothesis
# ---------------------------------------------------------------------------
def test_engine_disassemble_hypothesis_window_and_disagreements(
    fake_engine, tmp_path
):
    binary = _write_raw_bin(tmp_path)
    res = fake_engine.disassemble_hypothesis(binary, offset=0, size=12, base=0)
    assert is_error_result(res) is False
    assert res.get("ok") is True
    assert res["window"] == {"offset": 0, "size": 12, "base": 0}
    names = {h["arch"] for h in res["hypotheses"]}
    assert names == {"rv32", "rv64", "thumb", "metapc"}
    by_arch = {h["arch"]: h for h in res["hypotheses"]}
    # rv32 decodes 4-byte words; the fake tags mnemonics with the arch.
    assert by_arch["rv32"]["instructions"][0]["text"].startswith("riscv_i")
    assert by_arch["rv32"]["instructions"][0]["size"] == 4
    assert by_arch["thumb"]["instructions"][0]["size"] == 2
    assert by_arch["thumb"]["instructions"][0]["text"].startswith("arm_i")
    assert by_arch["metapc"]["instructions"][0]["text"].startswith("x86_i")
    # Disagreement at offset 0: all four decoders interpret the same bytes.
    assert len(res["disagreements"]) >= 1
    d0 = res["disagreements"][0]
    assert d0["offset"] == 0
    assert len(d0["interpretations"]) >= 2


def test_engine_disassemble_hypothesis_narrowed_by_arch_context(
    fake_engine, tmp_path
):
    binary = _write_raw_bin(tmp_path)
    res = fake_engine.disassemble_hypothesis(
        binary,
        offset=0,
        size=16,
        arch_context={"processor": "riscv", "bitness": 64},
    )
    names = {h["arch"] for h in res["hypotheses"]}
    assert names == {"rv64"}


def test_engine_disassemble_hypothesis_base_offset(fake_engine, tmp_path):
    binary = _write_raw_bin(tmp_path)
    res = fake_engine.disassemble_hypothesis(binary, offset=4, size=8, base=0x1000)
    assert is_error_result(res) is False
    # The fake shim starts each decode at the seek address; the engine maps
    # virtual address -> file offset using base.
    rv64 = next(h for h in res["hypotheses"] if h["arch"] == "rv64")
    assert rv64["instructions"][0]["offset"] == 4


def test_engine_disassemble_hypothesis_offset_out_of_range(fake_engine, tmp_path):
    binary = _write_raw_bin(tmp_path)
    res = fake_engine.disassemble_hypothesis(binary, offset=10_000, size=16)
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.ADDRESS_INVALID


def test_engine_disassemble_hypothesis_filters_invalid_hypotheses(fake_engine, tmp_path):
    binary = _write_raw_bin(tmp_path)
    # Unknown names are ignored; the valid subset is honored.
    res = fake_engine.disassemble_hypothesis(
        binary, offset=0, size=16, hypotheses=["rv32", "bogus"]
    )
    assert is_error_result(res) is False
    names = {h["arch"] for h in res["hypotheses"]}
    assert names == {"rv32"}
    # A fully-unknown list falls back to the default decoder set.
    res = fake_engine.disassemble_hypothesis(
        binary, offset=0, size=16, hypotheses=["not_an_arch"]
    )
    assert is_error_result(res) is False
    names = {h["arch"] for h in res["hypotheses"]}
    assert names == {"rv32", "rv64", "thumb", "metapc"}


# ---------------------------------------------------------------------------
# Engine: vxrefs (raw pointer-word scan — the /v gap)
# ---------------------------------------------------------------------------
def test_engine_vxrefs_le_be_word_scan(fake_engine, tmp_path):
    """Opaque raw blob: pointer-width words equal to a target are found at
    their byte offsets regardless of alignment or byte order."""
    blob = bytearray(b"\x00" * 64)
    target = 0x356F8
    # little-endian u32 at offset 8
    blob[8:12] = target.to_bytes(4, "little")
    # big-endian u32 at offset 20
    blob[20:24] = target.to_bytes(4, "big")
    # little-endian u64 at offset 32
    blob[32:40] = target.to_bytes(8, "little")
    path = _write_raw_bin(tmp_path, name="tables.bin", data=bytes(blob))

    res = fake_engine.vxrefs(path, target="0x356f8")
    assert is_error_result(res) is False
    assert res.get("ok") is True
    assert res["target"] == 0x356F8
    assert res["total"] == 3
    offsets = {(m["offset"], m["endian"], m["width"]) for m in res["matches"]}
    assert (8, "little", 4) in offsets
    assert (20, "big", 4) in offsets
    # The u64 at 32 embeds the target's 4-byte LE image, so the auto-width
    # (prefers more hits) keeps the 4-byte interpretation of that offset too.
    assert (32, "little", 4) in offsets

    # Explicit pointer_width + endian narrows the scan: the LE u32 at 8 plus
    # the 4-byte LE prefix of the u64 at 32.
    narrowed = fake_engine.vxrefs(
        path, target="0x356f8", pointer_width=4, endian="little"
    )
    assert narrowed["total"] == 2
    assert {m["offset"] for m in narrowed["matches"]} == {8, 32}


def test_engine_vxrefs_auto_width_prefers_more_hits(fake_engine, tmp_path):
    blob = bytearray(b"\x00" * 64)
    target = 0x777
    # Two u32 hits (plus a 4-byte LE prefix inside the u64) vs one u64 hit
    # -> auto width should pick 4.
    blob[0:4] = target.to_bytes(4, "little")
    blob[12:16] = target.to_bytes(4, "little")
    blob[40:48] = target.to_bytes(8, "little")
    path = _write_raw_bin(tmp_path, name="auto.bin", data=bytes(blob))
    res = fake_engine.vxrefs(path, target=0x777)
    assert res["total"] == 3
    assert res["pointer_width"] == 4
    assert all(m["width"] == 4 for m in res["matches"])
    assert {m["offset"] for m in res["matches"]} == {0, 12, 40}


def test_engine_vxrefs_limit(fake_engine, tmp_path):
    blob = bytearray(b"\x00" * 64)
    for i in range(5):
        blob[i * 8 : i * 8 + 4] = 0x1234.to_bytes(4, "little")
    path = _write_raw_bin(tmp_path, name="many.bin", data=bytes(blob))
    res = fake_engine.vxrefs(path, target=0x1234, pointer_width=4, limit=2)
    assert res["total"] == 5
    assert res["count"] == 2
    assert len(res["matches"]) == 2


def test_engine_vxrefs_invalid_target(fake_engine, tmp_path):
    binary = _write_raw_bin(tmp_path)
    res = fake_engine.vxrefs(binary, target="not-an-int")
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.INVALID_ARGS


def test_engine_vxrefs_missing_binary(fake_engine, tmp_path):
    res = fake_engine.vxrefs(str(tmp_path / "gone.bin"), target=0x100)
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.R2_BINARY_NOT_FOUND


# ---------------------------------------------------------------------------
# Engine: hardening / subprocess plumbing
# ---------------------------------------------------------------------------
def test_r2_env_never_leaks_session_token(monkeypatch):
    monkeypatch.setenv("IDA_MCP_SESSION_TOKEN", "super-secret-token")
    monkeypatch.setenv("IDA_MCP_R2_BIN", "leaky")
    env = r2_engine_mod._r2_env()
    assert "IDA_MCP_SESSION_TOKEN" not in env
    assert "super-secret-token" not in str(env)
    assert env.get("R2_NOPLUGINS") == "1"
    # PATH is preserved so the child can resolve its own binary/plugins.
    assert env.get("PATH")


def test_one_shot_timeout_envelope(tmp_path):
    sleeper = _write_shim(
        tmp_path,
        content="#!/bin/sh\nsleep 5\n",
        name="fake_sleep.sh",
    )
    engine = R2Engine(bin_path=sleeper, timeout=0.2)
    res = engine._one_shot([sleeper, "-v"])
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.R2_TIMEOUT
    assert res.get("recoverable") is False
    assert res.get("category") == "runtime"


def test_one_shot_process_died_envelope(tmp_path):
    killer = _write_shim(
        tmp_path,
        content="#!/bin/sh\nkill -9 $$\n",
        name="fake_kill.sh",
    )
    engine = R2Engine(bin_path=killer, timeout=5.0)
    res = engine._one_shot([killer, "-v"])
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.R2_PROCESS_DIED
    assert res.get("category") == "runtime"


def test_one_shot_start_failed_envelope():
    engine = R2Engine(bin_path="/nonexistent/r2", timeout=5.0)
    res = engine._one_shot(["/nonexistent/r2", "-v"])
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.R2_ENGINE_START_FAILED
    assert res.get("recoverable") is True


def test_canonicalize_target_escapes_allowed_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"\x00" * 8)
    canonical, err = R2Engine.canonicalize_target(str(outside), str(root))
    assert canonical is None
    assert is_error_result(err) is True
    assert err.get("code") == MCPError.INVALID_ARGS

    inside = root / "ok.bin"
    inside.write_bytes(b"\x00" * 8)
    canonical, err = R2Engine.canonicalize_target(str(inside), str(root))
    assert err is None
    assert canonical == str(inside)


def test_canonicalize_target_rejects_symlink(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target_outside = tmp_path / "secret.bin"
    target_outside.write_bytes(b"\x00" * 8)
    link = root / "link.bin"
    try:
        os.symlink(str(target_outside), str(link))
    except OSError:
        pytest.skip("symlinks not supported on this filesystem")
    canonical, err = R2Engine.canonicalize_target(str(link), str(root))
    assert canonical is None
    assert is_error_result(err) is True
    assert err.get("code") == MCPError.INVALID_ARGS


def test_canonicalize_target_requires_path():
    canonical, err = R2Engine.canonicalize_target("")
    assert canonical is None
    assert is_error_result(err) is True
    assert err.get("code") == MCPError.INVALID_ARGS


# ---------------------------------------------------------------------------
# Server handler (_handle_r2)
# ---------------------------------------------------------------------------
def test_handler_r2_status_no_session_required(server):
    res = server._handle_r2({"action": "status"})
    assert is_error_result(res) is False
    assert res.get("available") is True
    assert res.get("variant") == "radare2"


def test_handler_r2_standalone_binary_path(server, tmp_path):
    binary = _write_raw_bin(tmp_path)
    res = server._handle_r2(
        {"action": "bininfo", "binary_path": binary}
    )
    assert is_error_result(res) is False
    assert res["arch"] == "riscv"
    assert res["ok"] is True


def test_handler_r2_requires_session_or_binary_path(server):
    res = server._handle_r2({"action": "bininfo"})
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.INVALID_ARGS
    assert "binary_path" in (res.get("hint") or "")


def test_handler_r2_unknown_action(server):
    res = server._handle_r2({"action": "write_idb", "binary_path": "/tmp/x"})
    assert is_error_result(res) is True
    assert res.get("code") == MCPError.ACTION_NOT_FOUND
    # IDB-writing r2 paths are refused by design in Phase 1.
    assert "read-only" in (res.get("hint") or "")


def test_handler_r2_session_resolution_uses_session_binary(server, tmp_path):
    binary = _write_raw_bin(tmp_path, name="firmware.bin")
    token = server._begin_client_connection()
    try:
        session, _ = _open_background_pending(server, binary)
        sid = session.session_id
        res = server._handle_r2({"action": "bininfo", "idb": sid})
        assert is_error_result(res) is False
        assert res["file"] == os.path.realpath(binary)
        assert res["arch"] == "riscv"

        # disassemble_hypothesis through the handler (schema: addr + count).
        res = server._handle_r2(
            {"action": "disassemble_hypothesis", "idb": sid, "addr": "0x0", "count": 4}
        )
        assert is_error_result(res) is False
        assert res["window"]["offset"] == 0
    finally:
        server._end_client_connection(token)


def test_handler_r2_vxrefs_value_param(server, tmp_path):
    blob = bytearray(b"\x00" * 32)
    blob[4:8] = 0xABC.to_bytes(4, "little")
    binary = _write_raw_bin(tmp_path, name="v.bin", data=bytes(blob))
    res = server._handle_r2(
        {"action": "vxrefs", "binary_path": binary, "value": "0xabc"}
    )
    assert is_error_result(res) is False
    assert res["total"] == 1
    assert res["matches"][0]["offset"] == 4


def test_dispatch_r2_branch_forwards_to_handler(server, tmp_path):
    """The r2 tool must be handled host-side, never forwarded to IDA."""
    binary = _write_raw_bin(tmp_path)
    result = server._execute_tool("r2", {"action": "bininfo", "binary_path": binary})
    assert is_error_result(result) is False
    assert result["arch"] == "riscv"


def test_r2_works_during_safe_mode(server, tmp_path):
    """r2 read ops must be available while a session's IDA analysis is pending."""
    binary = _write_raw_bin(tmp_path)
    token = server._begin_client_connection()
    try:
        session, _ = _open_background_pending(server, binary)
        sid = session.session_id
        assert server._safe_mode_active(sid)

        # The safe-mode gate must not block any r2 read op.
        for action in ("status", "bininfo", "load_hints", "disassemble_hypothesis", "vxrefs"):
            assert server._safe_mode_gate(sid, "r2", action) is None, (
                f"r2/{action} must be available in safe mode"
            )

        # And the dispatch actually executes it (subprocess, no IDA runtime).
        res = server._execute_tool(
            "r2", {"action": "status", "idb": sid}
        )
        assert is_error_result(res) is False
        assert res.get("available") is True
    finally:
        server._end_client_connection(token)


def test_dispatch_long_running_actions_includes_r2():
    from ida_pro_mcp.host.server.server_dispatch import LONG_RUNNING_ACTIONS

    assert ("r2", "vxrefs") in LONG_RUNNING_ACTIONS
    assert ("r2", "disassemble_hypothesis") in LONG_RUNNING_ACTIONS


# ---------------------------------------------------------------------------
# Real-engine contract tests (optional CI job: apt install rz)
# ---------------------------------------------------------------------------
def test_contract_status_real(real_engine):
    res = real_engine.status()
    assert res.get("ok") is True
    assert res.get("available") is True
    assert res.get("variant") in ("rizin", "radare2", "unknown")
    assert res.get("version")


def test_contract_bininfo_real(real_engine, tmp_path):
    binary = _write_raw_bin(tmp_path, name="raw.bin")
    res = real_engine.bininfo(binary)
    # Standard envelope: ok:true on success, error envelope on failure.
    assert is_error_result(res) is False
    assert res.get("ok") is True
    assert isinstance(res.get("filetype"), str)
    assert isinstance(res.get("entries"), list)


def test_contract_disassemble_hypothesis_real(real_engine, tmp_path):
    binary = _write_raw_bin(
        tmp_path,
        name="hyp.bin",
        data=bytes.fromhex("2de9f0470020012102220323" + "00" * 32),
    )
    res = real_engine.disassemble_hypothesis(binary, offset=0, size=16, base=0)
    assert is_error_result(res) is False
    assert res.get("ok") is True
    assert res["window"]["size"] == 16
    # Every hypothesis must return a structured instructions list.
    for hyp in res["hypotheses"]:
        assert "instructions" in hyp
        assert "decode_error" in hyp
    assert isinstance(res["disagreements"], list)


def test_contract_vxrefs_real(real_engine, tmp_path):
    blob = bytearray(b"\x00" * 32)
    blob[8:12] = 0x12345.to_bytes(4, "little")
    binary = _write_raw_bin(tmp_path, name="vt.bin", data=bytes(blob))
    res = real_engine.vxrefs(binary, target=0x12345, pointer_width=4, endian="little")
    assert is_error_result(res) is False
    assert res["total"] == 1
    assert res["matches"][0]["offset"] == 8


def test_contract_load_hints_real(real_engine, tmp_path):
    binary = _write_raw_bin(tmp_path)
    res = real_engine.load_hints(binary)
    # load_hints always returns the standard envelope; heuristics are advisory.
    assert is_error_result(res) is False
    assert res.get("ok") is True
    assert "load_hints" in res


# ---------------------------------------------------------------------------
# Boundary and parser tests that do not require a real r2 installation.
# ---------------------------------------------------------------------------
def test_r2_helper_parsers_cover_malformed_output_and_disagreements():
    assert r2_engine_mod._extract_json_object('notice\n{"ok": true}') == {"ok": True}
    assert r2_engine_mod._extract_json_object("no object") is None
    assert r2_engine_mod._extract_json_object("{not-json}") is None
    assert r2_engine_mod._extract_json_object("[1, 2]") is None

    assert r2_engine_mod._decode_stdout({"stdout": b"bytes"}) == "bytes"
    assert r2_engine_mod._decode_stdout({"stdout": "text"}) == "text"
    assert r2_engine_mod._decode_stdout({}) == ""
    assert r2_engine_mod._decode_stderr({"stderr": b"warning"}) == "warning"
    assert r2_engine_mod._decode_stderr({"stderr": "text"}) == "text"

    assert r2_engine_mod._scan_words(b"abcd", 1, 3, "little") == []
    assert r2_engine_mod._scan_words(b"\x01\x00\x00\x00", 2**32, 4, "little") == []
    results = r2_engine_mod._compute_disagreements(
        [
            {"error": "failed", "instructions": [{"offset": 0, "text": "bad"}]},
            {
                "arch": "a",
                "bits": 32,
                "instructions": [{"offset": 0, "size": 2, "bytes": "aa", "text": "mov r0"}],
            },
            {
                "arch": "b",
                "bits": 64,
                "instructions": [{"offset": 0, "size": 4, "bytes": "aabb", "text": "add r0"}],
            },
        ]
    )
    assert results[0]["offset"] == 0
    assert len(results[0]["interpretations"]) == 2


def test_r2_env_and_restricted_cwd_are_minimal(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/custom/bin")
    monkeypatch.setenv("HOME", "/custom/home")
    monkeypatch.setenv("IDA_MCP_SESSION_TOKEN", "secret")
    env = r2_engine_mod._r2_env()
    assert env == {
        "PATH": "/custom/bin",
        "HOME": "/custom/home",
        "LANG": "C",
        "LC_ALL": "C",
        "R2_NOPLUGINS": "1",
    }
    assert "IDA_MCP_SESSION_TOKEN" not in env

    target = tmp_path / "raw.bin"
    target.write_bytes(b"x")
    assert R2Engine._restricted_cwd(str(target)) == str(tmp_path)
    assert R2Engine._restricted_cwd(str(tmp_path / "missing" / "file")) == r2_engine_mod.tempfile.gettempdir()


def test_one_shot_start_and_exit_boundaries(monkeypatch):
    engine = R2Engine(bin_path="fake", timeout=0.1)

    monkeypatch.setattr(
        r2_engine_mod.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("denied")),
    )
    denied = engine._one_shot(["fake"])
    assert denied["code"] == MCPError.R2_ENGINE_START_FAILED
    assert "denied" in denied["message"]

    monkeypatch.setattr(
        r2_engine_mod.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=7, stdout=b"", stderr=b"bad command"
        ),
    )
    exited = engine._one_shot(["fake"])
    assert exited["code"] == MCPError.R2_ENGINE_START_FAILED
    assert exited["details"]["returncode"] == 7
    assert exited["details"]["stderr"] == "bad command"

    monkeypatch.setattr(
        r2_engine_mod.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=7, stdout=b"usable output", stderr=b"warning"
        ),
    )
    usable = engine._one_shot(["fake"])
    assert usable["ok"] is True
    assert usable["returncode"] == 7


def test_status_and_bininfo_handle_nonstandard_engine_output(tmp_path, monkeypatch):
    engine = R2Engine()
    monkeypatch.setattr(
        engine,
        "_one_shot",
        lambda _argv: {"ok": True, "stdout": b"Rizin nightly build", "stderr": b""},
    )
    status = engine.status()
    assert status["variant"] == "rizin"
    assert status["version"] is None

    binary = _write_raw_bin(tmp_path)
    calls = []

    def fake_bininfo(flags, path):
        calls.append((flags, path))
        if flags == ["-Ij"]:
            return {"info": {"class": "raw", "type": "blob"}}
        return {"entries": [{"vaddr": 1}, "ignore-me"]}

    monkeypatch.setattr(engine, "_run_bininfo_json", fake_bininfo)
    info = engine.bininfo(binary)
    assert info["filetype"] == "raw"
    assert info["entries"] == [{"vaddr": 1}]
    assert len(calls) == 2


def test_load_hints_keeps_context_when_advisory_sources_fail(tmp_path, monkeypatch):
    engine = R2Engine()
    binary = _write_raw_bin(tmp_path)
    monkeypatch.setattr(
        engine,
        "bininfo",
        lambda _path: make_error(MCPError.R2_ENGINE_START_FAILED, "bininfo unavailable"),
    )

    def fail_inference(_path):
        raise RuntimeError("heuristic failure")

    monkeypatch.setattr(
        "ida_pro_mcp.host.analysis.arch_profile.infer_binary_arch_profile",
        fail_inference,
    )
    hints = engine.load_hints(
        binary,
        {"processor": "metapc", "bitness": 64, "endian": "little", "baseaddr": 0},
    )
    assert hints["ok"] is True
    assert hints["processor"] == "metapc"
    assert hints["bitness"] == 64
    assert hints["arch_context_applied"] is True
    assert "heuristic failure" in hints["reason"]
    assert hints["bininfo"] is None


def test_decode_window_filters_invalid_lines_and_negative_offsets(tmp_path, monkeypatch):
    engine = R2Engine()
    binary = _write_raw_bin(tmp_path)
    monkeypatch.setattr(
        engine,
        "_one_shot",
        lambda _argv: {
            "ok": True,
            "stdout": (
                "\x1b[31m0x00000010 13 00 mov r0\x1b[0m\n"
                "0x0000000f 13 00 before-base\n"
                "0x00000010 13 00 invalid instruction\n"
                "not an instruction\n"
            ),
            "stderr": b"",
        },
    )
    result = engine._decode_window(binary, 0, 8, 0x10, "thumb", {"bits": 16})
    assert result["decode_error"] is None
    assert result["instructions"] == [
        {"offset": 0, "size": 2, "bytes": "1300", "text": "mov r0"}
    ]


def test_disassemble_and_vxrefs_io_boundaries(tmp_path, monkeypatch):
    engine = R2Engine()
    binary = _write_raw_bin(tmp_path)
    monkeypatch.setattr(
        r2_engine_mod.os.path,
        "getsize",
        lambda _path: (_ for _ in ()).throw(OSError("stat failed")),
    )
    stat_result = engine.disassemble_hypothesis(binary)
    assert stat_result["code"] == MCPError.IO_ERROR

    monkeypatch.undo()
    monkeypatch.setattr(
        "builtins.open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read failed")),
    )
    read_result = engine.vxrefs(binary, target=1)
    assert read_result["code"] == MCPError.IO_ERROR

    blob = bytearray(b"\x00" * 16)
    blob[4:8] = (1).to_bytes(4, "little")
    target = _write_raw_bin(tmp_path, name="pointers.bin", data=bytes(blob))
    monkeypatch.undo()
    result = engine.vxrefs(target, target=1, pointer_width=3, endian="middle", limit=-1)
    assert result["ok"] is True
    assert result["count"] == 0
