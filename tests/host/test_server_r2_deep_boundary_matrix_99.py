"""Deep offline coverage for the r2 host mixin's remaining safety branches."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_r2
from ida_pro_mcp.host.server.server_r2 import ServerR2Mixin


class _Server(ServerR2Mixin):
    current_session = None


def test_r2_root_resolution_and_current_session_fallback(monkeypatch, tmp_path):
    srv = _Server()
    monkeypatch.setenv("IDA_MCP_MEMORY_ROOT", "~/r2-root")
    assert srv._r2_allowed_root_for("/tmp/sample.bin").endswith("/r2-root")

    original_realpath = server_r2.os.path.realpath

    def fail_realpath(_path):
        raise OSError("path unavailable")

    monkeypatch.setattr(server_r2.os.path, "realpath", fail_realpath)
    monkeypatch.setenv("IDA_MCP_MEMORY_ROOT", "/broken")
    assert srv._r2_allowed_root_for(str(tmp_path / "sample.bin")) is None
    monkeypatch.setattr(server_r2.os.path, "realpath", original_realpath)
    monkeypatch.delenv("IDA_MCP_MEMORY_ROOT")
    assert srv._r2_allowed_root_for("") is None

    srv.current_session = SimpleNamespace(session_id="SID_current")
    monkeypatch.setattr(srv, "_resolve_session_from_idb_ref", lambda ref: None, raising=False)
    result = srv._resolve_r2_target({})[2]
    assert result["code"] == MCPError.FILE_NOT_FOUND


def test_r2_disassembly_defaults_and_nonlist_hypotheses(monkeypatch, tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00")
    calls = []

    class Engine:
        def __init__(self):
            self.allowed_root = None

        def disassemble_hypothesis(self, path, **kwargs):
            calls.append((path, kwargs))
            return {"ok": True, **kwargs}

    monkeypatch.setattr(server_r2, "R2Engine", Engine)
    srv = _Server()
    srv._resolve_r2_target = lambda _args: (str(target), {"processor": "x"}, None)
    srv._r2_allowed_root_for = lambda _path: str(tmp_path)
    result = srv._handle_r2({"action": "disassemble_hypothesis", "binary_path": str(target), "hypotheses": 7})
    assert result["size"] == 64
    assert result["hypotheses"] is None
    assert calls[0][1]["base"] == 0
    result = srv._handle_r2({"action": "disassemble_hypothesis", "binary_path": str(target), "hypotheses": ["x86"]})
    assert result["hypotheses"] == ["x86"]


def test_r2_engine_canonicalize_target_edges(tmp_path, monkeypatch):
    import os

    from ida_pro_mcp.host.r2_engine import R2Engine

    eng = R2Engine(bin_path="/bin/true", allowed_root=str(tmp_path))

    # 208-209: realpath exception on path
    monkeypatch.setattr(os.path, "realpath", lambda p: (_ for _ in ()).throw(OSError("boom")))
    _, err = eng.canonicalize_target("/any/path", str(tmp_path))
    assert err["code"] == MCPError.INVALID_ARGS
    assert "invalid binary path" in err["message"]
    monkeypatch.undo()

    # 227-228: realpath exception on allowed_root
    target = tmp_path / "bin.exe"
    target.write_bytes(b"MZ")
    real_realpath = os.path.realpath

    def flaky_realpath(p, *args, **kwargs):
        if "bad_root" in str(p):
            raise OSError("root fail")
        return real_realpath(p, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", flaky_realpath)
    c, err = eng.canonicalize_target(str(target), str(tmp_path / "bad_root"))
    assert err is None
    assert c == str(target.resolve())
    monkeypatch.undo()

    # 232-233: commonpath ValueError
    monkeypatch.setattr(os.path, "commonpath", lambda paths: (_ for _ in ()).throw(ValueError("diff drives")))
    c, err = eng.canonicalize_target(str(target), str(tmp_path))
    assert err is not None
    assert "escapes the allowed root" in err["message"]
    monkeypatch.undo()

    # 243: empty part in rel.split(os.sep)
    monkeypatch.setattr(os.path, "relpath", lambda c, r: os.sep + "bin.exe")
    c, err = eng.canonicalize_target(str(target), str(tmp_path))
    assert err is None
    monkeypatch.undo()

    # 246: symlink in path
    monkeypatch.setattr(os.path, "islink", lambda p: True)
    c, err = eng.canonicalize_target(str(target), str(tmp_path))
    assert err is not None
    assert "symbolic links are not allowed" in err["message"]
    monkeypatch.undo()


def test_r2_engine_status_genuine_error(monkeypatch):
    from ida_pro_mcp.host.r2_engine import R2Engine

    eng = R2Engine(bin_path="/bin/true")
    monkeypatch.setattr(eng, "_one_shot", lambda argv: {"ok": False, "code": MCPError.R2_TIMEOUT, "message": "timed out"})
    res = eng.status()
    assert res["code"] == MCPError.R2_TIMEOUT


def test_r2_engine_bininfo_invalid_json(tmp_path, monkeypatch):
    from ida_pro_mcp.host.r2_engine import R2Engine

    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00" * 32)
    eng = R2Engine(bin_path="/bin/true", bininfo_bin="/bin/true")
    monkeypatch.setattr(eng, "_one_shot", lambda argv: {"ok": True, "stdout": "NOT JSON AT ALL"})
    res = eng.bininfo(str(target))
    assert res["code"] == MCPError.R2_ENGINE_START_FAILED
    assert "not valid JSON" in res["message"]


def test_r2_engine_disasm_hypothesis_edges(tmp_path, monkeypatch):
    from ida_pro_mcp.host.r2_engine import R2Engine

    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x90" * 32)
    eng = R2Engine(bin_path="/bin/true", allowed_root=str(tmp_path))

    # 590: canonicalize err
    res = eng.disassemble_hypothesis(str(tmp_path / "missing.bin"))
    assert res["code"] == MCPError.R2_BINARY_NOT_FOUND

    # 536: _decode_window error
    monkeypatch.setattr(eng, "_one_shot", lambda argv: {"ok": False, "code": MCPError.R2_PROCESS_DIED, "message": "crash"})
    dec = eng._decode_window(str(target), 0, 16, 0, "rv32", {"asm_arch": "riscv", "bits": 32})
    assert dec["decode_error"] is not None

    # 550-551: disasm line address ValueError
    orig_int = int
    def flaky_int(val, *a, **kw):
        if val == "1234":
            raise ValueError("bad addr")
        return orig_int(val, *a, **kw)
    monkeypatch.setattr("builtins.int", flaky_int)
    monkeypatch.setattr(eng, "_one_shot", lambda argv: {"ok": True, "stdout": "0x1234 90 nop\n"})
    dec = eng._decode_window(str(target), 0, 16, 0, "metapc", {"asm_arch": "x86", "bits": 32})
    assert dec["instructions"] == []
    monkeypatch.setattr("builtins.int", orig_int)

    # 614, 616, 618: arch_context branches
    monkeypatch.setattr(eng, "_decode_window", lambda *a: {"arch": a[4], "instructions": []})
    r1 = eng.disassemble_hypothesis(str(target), offset=0, size=8, arch_context={"processor": "riscv", "bitness": 32})
    assert [h["arch"] for h in r1["hypotheses"]] == ["rv32"]
    r2 = eng.disassemble_hypothesis(str(target), offset=0, size=8, arch_context={"processor": "arm"})
    assert [h["arch"] for h in r2["hypotheses"]] == ["thumb"]
    r3 = eng.disassemble_hypothesis(str(target), offset=0, size=8, arch_context={"processor": "x86"})
    assert [h["arch"] for h in r3["hypotheses"]] == ["metapc"]

    # 622: empty chosen
    monkeypatch.setattr("ida_pro_mcp.host.r2_engine._HYPOTHESES", {})
    r4 = eng.disassemble_hypothesis(str(target), offset=0, size=8, hypotheses=["not_a_valid_arch"])
    assert r4["code"] == MCPError.INVALID_ARGS


def test_r2_engine_vxrefs_negative_target(tmp_path):
    from ida_pro_mcp.host.r2_engine import R2Engine

    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00" * 16)
    eng = R2Engine(bin_path="/bin/true", allowed_root=str(tmp_path))
    res = eng.vxrefs(str(target), target="-1")
    assert res["code"] == MCPError.INVALID_ARGS
    assert "must be non-negative" in res["message"]
