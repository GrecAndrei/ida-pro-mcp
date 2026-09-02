"""Additional boundary coverage for deterministic, offline project surfaces.

These tests exercise error paths and cross-mode combinations that are easy to
miss when the happy-path integration tests dominate the suite.  They deliberately
stay independent of a licensed IDA installation and of network services.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import runpy
import tarfile
import types
import zipfile
from pathlib import Path

import pytest

from ida_pro_mcp.host import config
from ida_pro_mcp.host.intelligence.helpers import parse_str_list
from ida_pro_mcp.host.intelligence.sources import SourceParser, UrlhausSource
from ida_pro_mcp.installer import bron_corpus, clients
from ida_pro_mcp.installer.common import InstallerOptions, InstallReport


@pytest.mark.parametrize(
    ("arch_name", "return_reg", "stack", "tail"),
    [
        ("x86", "eax", {"esp"}, {"jmp"}),
        ("x64", "rax", {"rsp"}, {"jmp"}),
        ("arm", "r0", {"sp", "r13"}, {"b"}),
        ("arm64", "x0", {"sp"}, {"b"}),
        ("mips", "v0", {"sp", "$sp", "$29"}, {"j", "b"}),
        ("mips64", "v0", {"sp", "$sp", "$29"}, {"j", "b"}),
        ("ppc", "r3", {"r1"}, {"b", "ba"}),
        ("ppc64", "r3", {"r1"}, {"b", "ba"}),
        ("riscv", "a0", {"sp", "x2"}, {"j", "jal", "c.j", "c.jal"}),
        ("riscv64", "a0", {"sp", "x2"}, {"j", "jal", "c.j"}),
        ("sparc", "o0", {"sp", "o6"}, {"ba", "jmp"}),
        ("sparc64", "o0", {"sp", "o6"}, {"ba", "jmp"}),
        ("sh", "r0", {"r15"}, {"jmp", "b", "j"}),
        ("68k", "d0", {"sp", "a7"}, {"jmp", "b", "j"}),
        ("s390", "r2", {"sp"}, {"jmp", "b", "j"}),
        ("xtensa", "a2", {"sp", "a1"}, {"jmp", "b", "j"}),
        ("tricore", "d2", {"sp", "a10"}, {"jmp", "b", "j"}),
        ("avr", "r24", {"sp"}, {"jmp", "b", "j"}),
        ("msp430", "r12", {"sp", "r1"}, {"jmp", "b", "j"}),
        ("csky", "a0", {"sp"}, {"jmp", "b", "j"}),
        ("arc", "r0", {"sp"}, {"jmp", "b", "j"}),
        ("nios2", "r2", {"sp"}, {"jmp", "b", "j"}),
        ("microblaze", "r3", {"r1", "sp"}, {"jmp", "b", "j"}),
        ("v850", "r10", {"sp"}, {"jmp", "b", "j"}),
        ("rl78", "ax", {"sp"}, {"jmp", "b", "j"}),
        ("h8", "er0", {"sp", "er7"}, {"jmp", "b", "j"}),
        ("mcs51", "dpl", {"sp"}, {"jmp", "b", "j"}),
        ("z80", "a", {"sp"}, {"jmp", "b", "j"}),
        ("pic24", "w0", {"w15", "sp"}, {"jmp", "b", "j"}),
        ("pic18", "wreg", {"stkptr"}, {"jmp", "b", "j"}),
    ],
)
def test_architecture_abi_tables_are_total(arch_name, return_reg, stack, tail):
    from tests._isolated_repo_loader import load_support_module

    arch = load_support_module("arch_utils")

    assert arch.get_return_register(arch_name) == return_reg
    assert arch.get_stack_pointer_names(arch_name) == stack
    assert tail == arch.get_tail_call_mnemonics(arch_name)
    assert isinstance(arch.get_callee_saved_registers(arch_name), set)


@pytest.mark.parametrize(
    ("arch_name", "mnems", "expected"),
    [
        ("x86", ["nop"], "unknown"),
        ("arm", ["sub"], "stack_alloc"),
        ("arm", ["nop"], "unknown"),
        ("mips", ["nop"], "unknown"),
        ("ppc", ["nop"], "unknown"),
        ("riscv", ["addi"], "riscv_frame_setup"),
        ("riscv", ["c.addi4spn"], "riscv_frame_setup"),
        ("riscv", ["sd"], "riscv_reg_save"),
        ("riscv", ["nop"], "unknown"),
        ("sparc", ["save"], "unknown"),
    ],
)
def test_architecture_prologue_edges(arch_name, mnems, expected):
    from tests._isolated_repo_loader import load_support_module

    arch = load_support_module("arch_utils")

    assert arch.get_prologue_pattern(mnems, arch_name) == expected
    assert arch.get_prologue_pattern([], arch_name) == "unknown"


@pytest.mark.parametrize(
    ("arch_name", "mnems", "expected"),
    [
        ("x86", ["leave", "ret"], "standard_frame_teardown"),
        ("x86", ["nop"], "unknown"),
        ("arm", ["pop", "pc"], "arm_pop_pc"),
        ("arm", ["b"], "tail_call"),
        ("arm", ["nop"], "unknown"),
        ("mips", ["j"], "tail_call"),
        ("mips", ["nop"], "unknown"),
        ("ppc", ["b"], "tail_call"),
        ("ppc", ["nop"], "unknown"),
        ("riscv", ["c.jal"], "tail_call"),
        ("riscv", ["nop"], "unknown"),
        ("sparc", ["retl"], "unknown"),
    ],
)
def test_architecture_epilogue_edges(arch_name, mnems, expected):
    from tests._isolated_repo_loader import load_support_module

    arch = load_support_module("arch_utils")

    assert arch.get_epilogue_pattern(mnems, arch_name) == expected
    assert arch.get_epilogue_pattern([], arch_name) == "unknown"


def test_parse_str_list_handles_non_string_and_custom_separators():
    assert parse_str_list(123) == ["123"]
    assert parse_str_list(()) == []
    assert parse_str_list("  ") == []
    assert parse_str_list("a| b || c", sep="|") == ["a", "b", "c"]


def test_config_environment_and_range_boundaries(monkeypatch):
    monkeypatch.setenv("N", "bad")
    assert config._env_int("N", 4) == 4
    monkeypatch.setenv("N", "-10")
    assert config._env_int("N", 4, min_value=0) == 0
    monkeypatch.setenv("N", "99")
    assert config._env_int("N", 4, max_value=8) == 8
    monkeypatch.setenv("F", "nan")
    assert config._env_float("F", 1.5) == 1.5
    monkeypatch.setenv("F", "-2")
    assert config._env_float("F", 1.5, min_value=0) == 0
    monkeypatch.setenv("F", "99")
    assert config._env_float("F", 1.5, max_value=8) == 8

    assert config._parse_line_range(None) == (None, None)
    assert config._parse_line_range(["3", "8"]) == (3, 8)
    assert config._parse_line_range("-8") == (None, 8)
    assert config._parse_line_range("3-") == (3, None)
    assert config._parse_line_range("oops") == (None, None)
    assert config._parse_line_range(True) == (None, None)
    assert config._normalize_session_id(" sid_a1b2c3d4 ") == "A1B2C3D4"
    assert config._normalize_session_id(123) is None
    assert config._normalize_session_id("bad") is None


def test_config_platform_runtime_defaults(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    monkeypatch.setattr(config.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert config._default_runtime_dir().endswith("ida-pro-mcp")
    monkeypatch.delenv("LOCALAPPDATA")
    assert "AppData" in config._default_runtime_dir()

    monkeypatch.setattr(config.sys, "platform", "darwin")
    assert "Library" in config._default_runtime_dir()
    monkeypatch.setattr(config.sys, "platform", "linux")
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert config._default_runtime_dir() == str(tmp_path / "state" / "ida-pro-mcp")
    monkeypatch.delenv("XDG_STATE_HOME")
    assert ".local" in config._default_runtime_dir()
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", "$HOME/custom")
    assert config._resolve_runtime_dir().endswith("custom")


def test_config_runtime_selection_and_migration(monkeypatch, tmp_path):
    preferred = tmp_path / "preferred"
    fallback = tmp_path / "fallback"
    monkeypatch.setattr(config, "_default_runtime_dir", lambda: str(fallback))
    monkeypatch.setattr(config.tempfile, "gettempdir", lambda: str(tmp_path / "tmp"))
    real_is_writable_dir = config._is_writable_dir
    monkeypatch.setattr(config, "_is_writable_dir", lambda _path: False)
    selected = config._select_runtime_dir(str(preferred))
    assert selected.endswith("ida_mcp_cache")

    script_dir = tmp_path / "script"
    legacy = script_dir / "ida_mcp_cache"
    legacy.mkdir(parents=True)
    (legacy / "one.txt").write_text("one", encoding="utf-8")
    nested = legacy / "nested"
    nested.mkdir()
    (nested / "two.txt").write_text("two", encoding="utf-8")
    monkeypatch.setattr(config, "__file__", str(script_dir / "config.py"))
    target = tmp_path / "migrated"
    config._migrate_legacy_runtime_dir(str(target))
    assert (target / "one.txt").read_text(encoding="utf-8") == "one"
    assert (target / "nested" / "two.txt").read_text(encoding="utf-8") == "two"
    monkeypatch.setattr(config, "_is_writable_dir", real_is_writable_dir)
    assert config._is_writable_dir(str(tmp_path / "writable")) is True


def test_config_log_rotation_and_parse_datetime(monkeypatch, tmp_path):
    log = tmp_path / "bridge.log"
    log.write_bytes(b"0123456789")
    monkeypatch.setattr(config, "BRIDGE_LOG", str(log))
    monkeypatch.setattr(config, "_BRIDGE_LOG_MAX_BYTES", 5)
    monkeypatch.setattr(config, "_BRIDGE_LOG_KEEP_BYTES", 0)
    config._rotate_bridge_log_if_needed()
    assert log.read_bytes() == b""
    assert config._parse_iso_datetime("2025-01-01T00:00:00Z").year == 2025
    assert config._parse_iso_datetime("not-a-date") is None
    assert config._parse_iso_datetime(None) is None

    monkeypatch.setattr(config, "_log_file_handle", None)
    config.log_rpc("hello")
    assert "hello" in log.read_text(encoding="utf-8")
    if config._log_file_handle is not None:
        config._log_file_handle.close()
        monkeypatch.setattr(config, "_log_file_handle", None)
    monkeypatch.setattr(config, "BRIDGE_LOG", str(tmp_path / "missing" / "bridge.log"))
    config.log_rpc("ignored")


def test_client_config_failure_modes_and_removal(tmp_path, monkeypatch):
    report = InstallReport()
    cfg = {"command": "python", "args": ["-m", "ida_pro_mcp"], "env": {}}
    bad_json = tmp_path / "bad.json"
    bad_json.write_text('{"mcpServers": []}', encoding="utf-8")
    assert not clients.update_json_config(bad_json, "ida-pro-mcp", cfg, report, False)
    assert report.errors

    nested_bad = tmp_path / "nested.json"
    nested_bad.write_text('{"mcp": "not-an-object"}', encoding="utf-8")
    report = InstallReport()
    assert not clients.update_json_config(nested_bad, "ida-pro-mcp", cfg, report, False, nested_key="mcp.servers")

    opencode_bad = tmp_path / "opencode.json"
    opencode_bad.write_text('{"mcp": []}', encoding="utf-8")
    report = InstallReport()
    assert not clients.update_opencode_config(opencode_bad, "ida-pro-mcp", cfg, report, False)

    yaml_bad = tmp_path / "config.yaml"
    yaml_bad.write_text("mcp_servers: []\n", encoding="utf-8")
    report = InstallReport()
    assert not clients.update_yaml_config(yaml_bad, "ida-pro-mcp", cfg, report, False)

    toml_bad = tmp_path / "config.toml"
    toml_bad.write_text("mcp_servers = []\n", encoding="utf-8")
    report = InstallReport()
    assert not clients.update_toml_config(toml_bad, "ida-pro-mcp", cfg, report, False)

    # Exercise every configure branch and the per-client failure collection.
    paths = {
        "OpenCode": tmp_path / "opencode-fresh.json",
        "TOML": tmp_path / "server.toml",
        "YAML": tmp_path / "server.yaml",
        "JSON": tmp_path / "server.json",
        "Fail": tmp_path / "fail.json",
    }
    monkeypatch.setattr(clients, "get_config_paths", lambda _root: paths)
    monkeypatch.setattr(clients, "_client_meta", lambda _root: {
        "YAML": {"yaml": {"top_level_key": "servers"}},
        "JSON": {"json": {"nested_key": "root.servers", "type": "stdio"}},
    })
    original_json = clients.update_json_config
    def fail_one(path, *args, **kwargs):
        if path == paths["Fail"]:
            return False
        return original_json(path, *args, **kwargs)
    monkeypatch.setattr(clients, "update_json_config", fail_one)
    configured = clients.configure_clients(tmp_path, cfg, InstallReport(), False)
    assert set(configured) == {"OpenCode", "TOML", "YAML", "JSON"}

    # Removal handles existing JSON and missing paths without touching absent
    # client configs.
    json_path = paths["JSON"]
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text('{"root": {"servers": {"ida-pro-mcp": {}}}}', encoding="utf-8")
    report = InstallReport()
    monkeypatch.setattr(clients, "get_config_paths", lambda _root: {"JSON": json_path, "Missing": tmp_path / "none.json"})
    monkeypatch.setattr(clients, "_client_meta", lambda _root: {"JSON": {"json": {"nested_key": "root.servers"}}})
    assert clients.remove_server_entry_from_clients(tmp_path, report, False) == ["JSON"]
    assert "ida-pro-mcp" not in json.loads(json_path.read_text())["root"]["servers"]


class _Response:
    def __init__(self, payload: bytes, content_length: str | None = None):
        self.payload = io.BytesIO(payload)
        self.headers = {"Content-Length": content_length} if content_length is not None else {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        return self.payload.read(size)


def test_bron_download_copy_and_verification_paths(monkeypatch, tmp_path):
    payload = b"bron bytes"
    monkeypatch.setattr(bron_corpus.urllib.request, "urlopen", lambda *_a, **_k: _Response(payload))
    dst = tmp_path / "raw.bin"
    result = bron_corpus._download_to_file("https://example.test/raw", str(dst))
    assert result["bytes"] == len(payload)
    assert dst.read_bytes() == payload

    target = io.BytesIO()
    assert bron_corpus._copy_extracted(io.BytesIO(b"abc"), target, already_written=0, declared_size=3) == 3
    with pytest.raises(RuntimeError, match="archive extraction"):
        bron_corpus._copy_extracted(io.BytesIO(b"abc"), io.BytesIO(), already_written=bron_corpus._MAX_EXTRACTED_BYTES, declared_size=0)

    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    with pytest.raises(RuntimeError, match="empty"):
        bron_corpus._verify_or_report("x", str(empty), force_verify=False, sources_dir=str(tmp_path))
    expected = hashlib.sha256(payload).hexdigest()
    monkeypatch.setenv("IDA_MCP_BRON_CORPUS_SHA256_X", expected)
    verified = bron_corpus._verify_or_report("x", str(dst), force_verify=False, sources_dir=str(tmp_path))
    assert verified["verified"] is True
    monkeypatch.setenv("IDA_MCP_BRON_CORPUS_SHA256_X", "wrong")
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        bron_corpus._verify_or_report("x", str(dst), force_verify=False, sources_dir=str(tmp_path))


def test_bron_archive_materialization_and_manifest_paths(tmp_path):
    sources = tmp_path / "sources"
    sources.mkdir()
    cwe_zip = sources / bron_corpus.BRON_SOURCES["cwe"]["filename"]
    with zipfile.ZipFile(cwe_zip, "w") as zf:
        zf.writestr("nested/catalog.xml", "<catalog/>")
    xml = bron_corpus._unpack_cwe_zip(str(cwe_zip), str(sources / "cwe"))
    assert Path(xml).read_text(encoding="utf-8") == "<catalog/>"

    tar_path = sources / "signature-base.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        info = tarfile.TarInfo("signature-base-master/yara/rule.yar")
        data = b"rule x { condition: true }"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    yara_dir = bron_corpus._unpack_signature_base_tar(str(tar_path), str(sources / "signature-base"))
    assert (Path(yara_dir) / "rule.yar").read_bytes() == data

    result = {"x": {"path": "raw", "sha256": "abc", "bytes": 3}}
    manifest = bron_corpus._record_sha_manifest(str(sources), result)
    assert json.loads(Path(manifest).read_text())["sources"]["x"]["sha256"] == "abc"
    assert bron_corpus._parse_only(" a, ,b ") == ["a", "b"]
    assert bron_corpus._parse_only("") == []


def test_bron_top_level_status_and_cli(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(bron_corpus, "BRON_SOURCES", {"x": {"filename": "x.bin"}})
    monkeypatch.setattr(bron_corpus, "download_source", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("nope")))
    failed = bron_corpus.download_bron_corpus(str(tmp_path), only=["x"])
    assert failed["built"] is False
    assert failed["reason"] == "all source downloads failed"

    monkeypatch.setattr(bron_corpus, "download_source", lambda *_a, **_k: {"path": "x", "sha256": "a", "bytes": 1})
    monkeypatch.setattr(bron_corpus, "_record_sha_manifest", lambda *_a, **_k: "manifest")
    monkeypatch.setattr(bron_corpus, "_materialize_cwe_xml", lambda *_a: (_ for _ in ()).throw(RuntimeError("bad cwe")))
    monkeypatch.setattr(bron_corpus, "_materialize_signature_base", lambda *_a: (_ for _ in ()).throw(RuntimeError("bad yara")))
    monkeypatch.setattr(bron_corpus, "_materialize_findcrypt", lambda *_a: None)
    monkeypatch.setattr(bron_corpus, "build_corpus_from_sources", lambda **_k: types.SimpleNamespace(is_empty=lambda: True))
    monkeypatch.setattr(bron_corpus, "_materialize_cwe_xml", lambda *_a: "")
    status = bron_corpus.download_bron_corpus(str(tmp_path), only=["x"])
    assert status["built"] is False

    monkeypatch.setattr(bron_corpus, "download_bron_corpus", lambda **_k: {"built": True, "ok": 1})
    assert bron_corpus.main(["--sources-dir", str(tmp_path), "--only", "x"]) == 0
    assert '"built": true' in capsys.readouterr().out


def test_urlhaus_nested_dict_and_archive_error_paths(tmp_path):
    data = {"one": {"url": "http://one"}, "two": [None, {"url": "http://two", "tags": ["a", "b"]}]}
    (tmp_path / "nested.json").write_text(json.dumps(data), encoding="utf-8")
    entries = UrlhausSource().parse(str(tmp_path))
    assert [item["url"] for item in entries] == ["http://one", "http://two"]
    assert UrlhausSource()._find_json(str(tmp_path / "missing")) is None
    assert UrlhausSource()._is_zip(str(tmp_path / "missing")) is False

    plain = tmp_path / "feed.bin"
    plain.write_bytes(b"not zip")
    UrlhausSource()._post_download(str(plain), str(tmp_path))


class _StubSource(SourceParser):
    name = "stub"
    description = "stub"
    cache_key = "stub"

    def __init__(self):
        self.urls = ["https://example.test/stub.bin", "https://example.test/other"]

    def parse(self, data_dir):
        return []


def test_source_download_progress_cache_and_failure_cleanup(monkeypatch, tmp_path):
    import ida_pro_mcp.host.intelligence.threat_corpus as threat_corpus

    calls = []
    monkeypatch.setattr(threat_corpus, "_download_url", lambda url: calls.append(url) or b"data")
    progress = []
    source = _StubSource()
    result = source.download(str(tmp_path), progress_cb=progress.append)
    assert result["downloaded"] == ["stub.bin", "other"]
    assert len(progress) == 2
    second = source.download(str(tmp_path))
    assert second["downloaded"] == []

    monkeypatch.setattr(threat_corpus, "_download_url", lambda _url: (_ for _ in ()).throw(OSError("offline")))
    failed = _StubSource().download(str(tmp_path / "failed"))
    assert len(failed["errors"]) == 2


def test_host_lazy_export_rejects_unknown_names():
    from ida_pro_mcp import host

    with pytest.raises(AttributeError, match="does-not-exist"):
        host.__getattr__("does-not-exist")


def test_ida_plugin_entrypoint_lifecycle_and_port_failover(monkeypatch, tmp_path):
    fake_idaapi = types.ModuleType("idaapi")
    fake_idaapi.PLUGIN_KEEP = 17
    fake_idaapi.PLUGIN_HIDE = 1
    fake_idaapi.PLUGIN_FIX = 2
    fake_idaapi.plugin_t = type("plugin_t", (), {})
    fake_flat_ida_mcp = types.ModuleType("ida_mcp")

    class Server:
        def __init__(self):
            self.calls = []
            self.stopped = 0

        def serve(self, host, port, request_handler):
            self.calls.append((host, port, request_handler))
            if port == 13337:
                raise OSError(98, "address in use")

        def stop(self):
            self.stopped += 1

    server = Server()
    fake_flat_ida_mcp.MCP_SERVER = server
    fake_flat_ida_mcp.IdaMcpHttpRequestHandler = object
    monkeypatch.setitem(__import__("sys").modules, "idaapi", fake_idaapi)
    monkeypatch.setitem(__import__("sys").modules, "ida_mcp", fake_flat_ida_mcp)
    plugin_ns = runpy.run_path(
        str(Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "ida_mcp.py"),
        run_name="ida_plugin_coverage",
    )
    # Keep this lifecycle test independent of the package-unload side effect;
    # the unload helper itself is checked separately below.
    plugin_ns["MCP"].run.__globals__["unload_package"] = lambda _name: None
    plugin = plugin_ns["PLUGIN_ENTRY"]()
    assert plugin.init() == fake_idaapi.PLUGIN_KEEP
    plugin.run(0)
    assert plugin.mcp is server
    assert [call[1] for call in server.calls] == [13337, 13338]
    plugin.term()
    assert server.stopped == 1
    plugin.term()  # no-op after the runtime has been stopped by the plugin

    bad_server = types.SimpleNamespace(
        serve=lambda *_a, **_k: (_ for _ in ()).throw(OSError(13, "permission denied")),
        stop=lambda: None,
    )
    fake_flat_ida_mcp.MCP_SERVER = bad_server
    plugin = plugin_ns["MCP"]()
    plugin.init()
    with pytest.raises(OSError, match="permission"):
        plugin.run(0)


def test_ida_plugin_unload_package_removes_only_matching_modules(monkeypatch):
    import sys

    fake_idaapi = types.ModuleType("idaapi")
    fake_idaapi.PLUGIN_KEEP = 1
    fake_idaapi.PLUGIN_HIDE = 1
    fake_idaapi.PLUGIN_FIX = 2
    fake_idaapi.plugin_t = type("plugin_t", (), {})
    monkeypatch.setitem(sys.modules, "idaapi", fake_idaapi)
    plugin_ns = runpy.run_path(
        str(Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "ida_mcp.py"),
        run_name="ida_plugin_unload_coverage",
    )
    monkeypatch.setitem(sys.modules, "ida_mcp", types.ModuleType("ida_mcp"))
    monkeypatch.setitem(sys.modules, "ida_mcp.child", types.ModuleType("ida_mcp.child"))
    monkeypatch.setitem(sys.modules, "ida_mcp_extra", types.ModuleType("ida_mcp_extra"))
    plugin_ns["unload_package"]("ida_mcp")
    assert "ida_mcp" not in sys.modules
    assert "ida_mcp.child" not in sys.modules
    assert "ida_mcp_extra" in sys.modules


def test_module_entrypoints_delegate_to_server_main(monkeypatch):
    import sys

    fake_server = types.ModuleType("ida_pro_mcp.host.server.server")
    seen = []
    fake_server.main = lambda: seen.append("called") or 0
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.host.server.server", fake_server)

    server_main_path = Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "host" / "server" / "__main__.py"
    with pytest.raises(SystemExit) as exc:
        exec(compile(server_main_path.read_bytes(), str(server_main_path), "exec"), {
            "__name__": "__main__",
            "__package__": "ida_pro_mcp.host.server",
            "__file__": str(server_main_path),
        })
    assert exc.value.code == 0
    assert seen == ["called"]

    seen.clear()
    runpy.run_path(
        str(Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "__main__.py"),
        run_name="__main__",
    )
    assert seen == ["called"]


def test_installer_skill_links_and_copy_fallbacks(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as installer

    checkout = tmp_path / "checkout"
    source = checkout / ".agents" / "skills" / "ida-pro-mcp"
    (source / "references").mkdir(parents=True)
    (source / "SKILL.md").write_text("skill", encoding="utf-8")
    (source / "references" / "operations.md").write_text("ops", encoding="utf-8")
    (checkout / ".git").mkdir()
    link_root = tmp_path / "codex" / "skills"
    link_root.mkdir(parents=True)
    link = link_root / "ida-pro-mcp"
    link.symlink_to(source, target_is_directory=True)
    assert installer._is_checkout_skill_link(link) is True
    assert installer._is_checkout_skill_link(tmp_path / "missing") is False

    with pytest.raises(FileNotFoundError):
        installer._replace_with_symlink_or_copy(tmp_path / "missing", tmp_path / "out")

    destination = tmp_path / "out" / "skill.txt"
    monkeypatch.setattr(installer.os, "symlink", lambda *_a, **_k: (_ for _ in ()).throw(OSError("no links")))
    source_file = tmp_path / "source.txt"
    source_file.write_text("source", encoding="utf-8")
    assert installer._replace_with_symlink_or_copy(source_file, destination) == "copied"
    assert destination.read_text(encoding="utf-8") == "source"

    # Existing directory backups are removed after a successful replacement.
    source_dir = tmp_path / "source-dir"
    source_dir.mkdir()
    (source_dir / "new").write_text("new", encoding="utf-8")
    existing = tmp_path / "out-dir"
    existing.mkdir()
    (existing / "old").write_text("old", encoding="utf-8")
    assert installer._replace_with_symlink_or_copy(source_dir, existing) in {"linked", "copied"}
    assert (existing / "new").read_text(encoding="utf-8") == "new"


def test_installer_skill_installation_error_and_checkout_refresh(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as installer

    report = InstallReport()
    skills = types.ModuleType("ida_pro_mcp.installer.skills")
    skills.default_skill_dirs = lambda: [tmp_path / "skills"]
    skills.install_skills = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("skill failure"))
    monkeypatch.setitem(__import__("sys").modules, "ida_pro_mcp.installer.skills", skills)
    assert installer._install_claude_opencode_skills(report, False, installer.UI()) is False
    assert report.warnings

    source = tmp_path / "source" / ".agents" / "skills" / "ida-pro-mcp"
    (source / "references").mkdir(parents=True)
    (source / "SKILL.md").write_text("new skill", encoding="utf-8")
    (source / "references" / "operations.md").write_text("new ops", encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    destination = tmp_path / "codex" / "skills" / "ida-pro-mcp"
    destination.mkdir(parents=True)
    (destination / "custom-reference.md").write_text("keep", encoding="utf-8")

    real_skills = types.ModuleType("ida_pro_mcp.installer.skills")
    real_skills.install_skills = lambda dirs, dry_run=False: {
        "ida-pro-mcp": [dirs[0] / "ida-pro-mcp" / "SKILL.md"]
    }
    monkeypatch.setitem(__import__("sys").modules, "ida_pro_mcp.installer.skills", real_skills)
    report = InstallReport()
    installer.install_codex_skills(tmp_path / "source", "agent", report, False)
    assert str(destination / "SKILL.md") in [str(path) for path in report.modified_files]


def test_installer_reranker_validation_and_python_warning(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main as installer

    monkeypatch.setattr(installer, "find_rerank_model", lambda *_a, **_k: "")
    opts = InstallerOptions(download_rerank_model=True, rerank_profile="not-a-profile")
    with pytest.raises(RuntimeError, match="Unknown rerank profile"):
        installer._resolve_reranker_for_install(opts, tmp_path, InstallReport(), installer.UI(), semantic_enabled=True)

    opts = InstallerOptions(download_rerank_model=True, rerank_profile="bge-reranker-v2-m3")
    with pytest.raises(RuntimeError, match="non-commercial|license"):
        installer._resolve_reranker_for_install(opts, tmp_path, InstallReport(), installer.UI(), semantic_enabled=True)

    report = InstallReport()
    modern = types.SimpleNamespace(version=(9, 4))
    monkeypatch.setattr(installer._runtime, "python_environment_kind", lambda: "conda")
    monkeypatch.setitem(__import__("sys").modules, "ida_pro_mcp.installer.runtime", installer._runtime)
    installer._warn_ida_python_compat(modern, report, installer.UI())
    assert report.metadata["python_kind"] == "conda"
    installer._warn_ida_python_compat(types.SimpleNamespace(version=(9, 3)), InstallReport(), installer.UI())
    installer._warn_ida_python_compat(types.SimpleNamespace(version=("bad",)), InstallReport(), installer.UI())


def test_installer_uninstall_removes_skills_plugins_and_reports(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import clients as client_module, main as installer

    install_root = tmp_path / "install"
    (install_root / "bin").mkdir(parents=True)
    (install_root / "bin" / "ida-pro-mcp").write_text("shim", encoding="utf-8")
    ida_root = tmp_path / "ida"
    plugin_dir = ida_root / "plugins"
    plugin_dir.mkdir(parents=True)
    for name in ("server_script.py", "ida_pro_mcp_plugin.py"):
        (plugin_dir / name).write_text("plugin", encoding="utf-8")
    skill_dir = tmp_path / "skills"
    (skill_dir / "ida-pro-mcp").mkdir(parents=True)
    monkeypatch.setattr(client_module, "get_config_paths", lambda _root: {})
    discovery = types.ModuleType("ida_pro_mcp.installer.discovery")
    discovery.detect_ida_installs = lambda: [types.SimpleNamespace(ida_dir=ida_root)]
    monkeypatch.setitem(__import__("sys").modules, "ida_pro_mcp.installer.discovery", discovery)
    skills = types.ModuleType("ida_pro_mcp.installer.skills")
    skills.SKILL_NAME = "ida-pro-mcp"
    skills.default_skill_dirs = lambda: [skill_dir]
    monkeypatch.setitem(__import__("sys").modules, "ida_pro_mcp.installer.skills", skills)
    opts = InstallerOptions(install_root=install_root, source_root=tmp_path)
    report = InstallReport()
    assert installer._run_uninstall(opts, installer.UI(), report) == 0
    assert not (skill_dir / "ida-pro-mcp").exists()
    assert not (ida_root / "plugins" / "server_script.py").exists()
    assert (install_root / "uninstall-report.json").exists()


def test_installer_run_install_lock_failure_and_windows_shell(monkeypatch, tmp_path):
    from ida_pro_mcp.installer import main as installer

    monkeypatch.setattr(installer, "installer_lock", lambda _root: (_ for _ in ()).throw(RuntimeError("locked")))
    opts = InstallerOptions(install_root=tmp_path / "install", interactive=False)
    assert installer.run_install(opts, installer.UI()) == 1
    monkeypatch.setattr(installer.sys, "platform", "win32")
    report = InstallReport()
    assert installer.install_bashrc_cli(tmp_path / "install", False, report) is False
    assert report.warnings
