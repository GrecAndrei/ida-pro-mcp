import os
import sys
import types
import unittest

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
IDA_MCP = os.path.join(SRC, "ida_pro_mcp", "ida_mcp")
if IDA_MCP not in sys.path:
    sys.path.insert(0, IDA_MCP)
TOOLS = os.path.join(IDA_MCP, "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import ida_pro_mcp.host.intelligence.core as intel_mod
from ida_pro_mcp.host.intelligence.core import BehaviorClassifier
from ida_pro_mcp.host.intelligence.context import ContextAssembler


class _FakeEmbedder:
    def embed(self, text):
        low = (text or "").lower()
        if any(k in low for k in ("sub_bytes", "aes", "round_keys", "mix_columns")):
            return [1.0, 0.0]
        if any(k in low for k in ("socket", "http", "send", "recv", "connect")):
            return [0.0, 1.0]
        return [0.0, 0.0]


class TestBehaviorClassifierManagement(unittest.TestCase):
    def setUp(self):
        self._old_shared = BehaviorClassifier._shared
        BehaviorClassifier._shared = None

    def tearDown(self):
        BehaviorClassifier._shared = self._old_shared

    def test_classify_handles_short_text_and_blocking(self):
        clf = BehaviorClassifier(_FakeEmbedder())
        clf.clear_cache()
        results = clf.classify("aes", block=True)
        self.assertTrue(results)
        self.assertEqual(results[0]["behavior"], "crypto_symmetric")

    def test_classify_impl_delegates_without_crashing(self):
        clf = BehaviorClassifier(_FakeEmbedder())
        results = clf._classify_impl([1.0, 0.0], block=True)
        self.assertTrue(results)
        self.assertEqual(results[0]["behavior"], "crypto_symmetric")

    def test_instance_rebinds_embedder(self):
        e1 = _FakeEmbedder()
        e2 = _FakeEmbedder()
        inst1 = BehaviorClassifier.instance(e1)
        inst2 = BehaviorClassifier.instance(e2)
        self.assertIs(inst1, inst2)
        self.assertIs(inst2._embedder, e2)

    def test_stale_anchor_generation_does_not_backfill_cache(self):
        clf = BehaviorClassifier(_FakeEmbedder())
        clf.clear_cache()
        stale_generation = clf._anchor_generation - 1
        anchor = clf._get_anchor("crypto_symmetric", generation=stale_generation)
        self.assertIsNone(anchor)
        self.assertNotIn("crypto_symmetric", clf._anchor_embs)

    def test_token_evidence_can_rescue_low_vector_score(self):
        class WeakEmbedder:
            def embed(self, text):
                return [0.0, 0.0]

        clf = BehaviorClassifier(WeakEmbedder())
        rows = clf.classify(
            "void AESDecryptRoundKeySchedule() { sub_bytes(state); mix_columns(state); round_key(state); }",
            threshold=0.05,
            block=True,
            top_k=4,
        )

        self.assertTrue(rows)
        self.assertEqual(rows[0]["behavior"], "crypto_symmetric")
        self.assertIn("matched_tokens", rows[0])


class TestClassifySchemaHelpers(unittest.TestCase):
    def setUp(self):
        self._orig_modules = {}
        for name in ("ida_mcp", "idaapi", "idautils", "idc", "ida_name", "ida_bytes", "ida_hexrays", "ida_typeinf", "ida_nalt", "ida_segment", "ida_funcs", "ida_kernwin", "ida_frame", "ida_lines", "rpc", "sync", "utils", "error_handling", "classify", "_common", "ida_pro_mcp.ida_mcp.tools._common"):
            self._orig_modules[name] = sys.modules.get(name)
        sys.modules["ida_mcp"] = types.ModuleType("ida_mcp")
        for name in ("idaapi", "idautils", "idc", "ida_name", "ida_bytes", "ida_hexrays", "ida_typeinf", "ida_nalt", "ida_segment", "ida_funcs", "ida_kernwin", "ida_frame", "ida_lines"):
            mod = types.ModuleType(name)
            if name == "idaapi":
                mod.BADADDR = -1
                mod.get_kernel_version = lambda: "9.0"
            sys.modules[name] = mod
        rpc_mod = types.ModuleType("rpc")
        rpc_mod.tool = lambda f: f
        rpc_mod.unsafe = lambda f: f
        sys.modules["rpc"] = rpc_mod
        sync_mod = types.ModuleType("sync")
        sync_mod.idaread = lambda f: f
        sync_mod.idawrite = lambda f: f
        sync_mod.IDAError = Exception
        sys.modules["sync"] = sync_mod
        utils_mod = types.ModuleType("utils")
        for name in ("parse_address", "normalize_list_input", "normalize_dict_list", "get_function", "get_prototype", "get_image_size", "looks_like_address", "get_stack_frame_variables_internal", "get_type_by_name", "hex_ea", "hex_size", "smart_match", "compile_smart_pattern", "resolve_symbol"):
            setattr(utils_mod, name, lambda *args, **kwargs: None)
        sys.modules["utils"] = utils_mod
        eh_mod = types.ModuleType("error_handling")
        class _FakeMCPError:
            INVALID_ARGS = "INVALID_ARGS"
        eh_mod.MCPError = _FakeMCPError
        eh_mod.make_error = lambda *args, **kwargs: {"ok": False}
        eh_mod.handle_error = lambda e: {"ok": False, "error": str(e)}
        eh_mod.ERROR_HINTS = {}
        for name in ("validate_addr", "validate_range", "check_debugger", "validate_path_safe", "require_arg", "require_one_of", "validate_action", "validate_count"):
            setattr(eh_mod, name, lambda *args, **kwargs: None)
        sys.modules["error_handling"] = eh_mod
        import importlib
        sys.modules.pop("classify", None)
        sys.modules.pop("_common", None)
        sys.modules.pop("ida_pro_mcp.ida_mcp.tools._common", None)
        self.classify_mod = importlib.import_module("classify")

        class FakeFn:
            start_ea = 0x1000
            end_ea = 0x1010
            flags = 0x2

        class FakeIdaFuncs:
            FUNC_LIB = 0x1
            FUNC_THUNK = 0x2

            @staticmethod
            def get_func(ea):
                return FakeFn() if ea == 0x1000 else None

        class FakeIdautils:
            @staticmethod
            def Heads(start, end):
                return []

            @staticmethod
            def CodeRefsFrom(head, zero):
                return []

            @staticmethod
            def DataRefsFrom(head):
                return []

            @staticmethod
            def XrefsTo(ea, zero):
                return []

        class FakeIdc:
            @staticmethod
            def get_func_name(ea):
                return "j_thunk" if ea == 0x1000 else ""

            @staticmethod
            def get_str_type(ea):
                return None

            @staticmethod
            def get_strlit_contents(*args, **kwargs):
                return None

        class FakeSegment:
            @staticmethod
            def getseg(ea):
                return None

            @staticmethod
            def get_segm_name(seg):
                return ""

        class FakeFlowChart:
            def __init__(self, fn):
                self._blocks = []

            def __iter__(self):
                return iter(self._blocks)

        class FakeIdaApi:
            FlowChart = FakeFlowChart

        self.classify_mod.ida_funcs = FakeIdaFuncs
        self.classify_mod.idautils = FakeIdautils
        self.classify_mod.idc = FakeIdc
        self.classify_mod.ida_segment = FakeSegment
        self.classify_mod.idaapi = FakeIdaApi

    def tearDown(self):
        for name, value in self._orig_modules.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value

    def test_induce_function_schema_includes_compiler_hints(self):
        schema = self.classify_mod._induce_function_schema(0x1000)
        self.assertIn("compiler_generated", schema["compiler_hints"])
        self.assertIn("thunk", schema["structural_features"])
        self.assertIn("very_small", schema["structural_features"])


class TestRawBinaryPlanning(unittest.TestCase):
    def setUp(self):
        self._orig_modules = {}
        for name in ("ida_mcp", "idaapi", "idautils", "idc", "ida_name", "ida_bytes", "ida_hexrays", "ida_typeinf", "ida_nalt", "ida_segment", "ida_funcs", "ida_kernwin", "ida_frame", "ida_lines", "rpc", "sync", "utils", "error_handling", "llm_helpers", "_common", "ida_pro_mcp.ida_mcp.tools._common"):
            self._orig_modules[name] = sys.modules.get(name)
        sys.modules["ida_mcp"] = types.ModuleType("ida_mcp")
        for name in ("idaapi", "idautils", "idc", "ida_name", "ida_bytes", "ida_hexrays", "ida_typeinf", "ida_nalt", "ida_segment", "ida_funcs", "ida_kernwin", "ida_frame", "ida_lines"):
            mod = types.ModuleType(name)
            if name == "idaapi":
                mod.BADADDR = -1
                mod.get_kernel_version = lambda: "9.0"
            sys.modules[name] = mod
        rpc_mod = types.ModuleType("rpc")
        rpc_mod.tool = lambda f: f
        rpc_mod.unsafe = lambda f: f
        sys.modules["rpc"] = rpc_mod
        sync_mod = types.ModuleType("sync")
        sync_mod.idaread = lambda f: f
        sync_mod.idawrite = lambda f: f
        sync_mod.IDAError = Exception
        sys.modules["sync"] = sync_mod
        utils_mod = types.ModuleType("utils")
        for name in ("parse_address", "normalize_list_input", "normalize_dict_list", "get_function", "get_prototype", "get_image_size", "looks_like_address", "get_stack_frame_variables_internal", "get_type_by_name", "hex_ea", "hex_size", "smart_match", "compile_smart_pattern", "resolve_symbol"):
            setattr(utils_mod, name, lambda *args, **kwargs: None)
        sys.modules["utils"] = utils_mod
        eh_mod = types.ModuleType("error_handling")
        class _FakeMCPError:
            INVALID_ARGS = "INVALID_ARGS"
        eh_mod.MCPError = _FakeMCPError
        eh_mod.make_error = lambda *args, **kwargs: {"ok": False}
        eh_mod.handle_error = lambda e: {"ok": False, "error": str(e)}
        eh_mod.ERROR_HINTS = {}
        for name in ("validate_addr", "validate_range", "check_debugger", "validate_path_safe", "require_arg", "require_one_of", "validate_action", "validate_count"):
            setattr(eh_mod, name, lambda *args, **kwargs: None)
        sys.modules["error_handling"] = eh_mod
        import importlib
        sys.modules.pop("llm_helpers", None)
        sys.modules.pop("_common", None)
        sys.modules.pop("ida_pro_mcp.ida_mcp.tools._common", None)
        self.llm_helpers_mod = importlib.import_module("llm_helpers")

    def tearDown(self):
        for name, value in self._orig_modules.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value

    def test_raw_firmware_queries_prioritize_binary_recon(self):
        self.assertEqual(self.llm_helpers_mod._infer_question_type("raw binary firmware blob"), "raw_firmware_retyping")
        plan = self.llm_helpers_mod._build_tool_plan("raw binary firmware blob", addr=None)
        self.assertGreaterEqual(len(plan), 4)
        self.assertEqual(plan[0]["tool"], "binary_info")
        self.assertEqual(plan[1]["action"], "sections")
        self.assertTrue(any(step["tool"] == "firmware_view" and step["action"] == "triage_snapshot" for step in plan))
        self.assertFalse(any(step["tool"] == "data_ops" for step in plan))

    def test_raw_firmware_plan_keeps_code_validation_for_anchored_addr(self):
        plan = self.llm_helpers_mod._build_tool_plan("raw firmware image", addr="0x401000")
        self.assertTrue(any(step["tool"] == "data_ops" and step["addr"] == "0x401000" for step in plan))
        self.assertEqual(plan[-3]["tool"], "code")
        self.assertEqual(plan[-2]["tool"], "code")

    def test_guided_analysis_firmware_flow_includes_triage_snapshot(self):
        self.llm_helpers_mod.info = None
        result = self.llm_helpers_mod.llm_helpers(action="guided_analysis")
        self.assertTrue(result.get("ok"))
        steps = result.get("guided_steps", "")
        self.assertIn("firmware_view(action='triage_snapshot')", steps)

    def test_adaptive_query_planner_raw_firmware_order_includes_triage_snapshot(self):
        result = self.llm_helpers_mod.llm_helpers(
            action="adaptive_query_planner",
            query="raw firmware blob"
        )
        self.assertTrue(result.get("ok"))
        order = result.get("recommended_order", [])
        self.assertIn("firmware_view.triage_snapshot", order)


class TestFirmwareViewBounds(unittest.TestCase):
    def setUp(self):
        self._orig_modules = {}
        for name in ("ida_mcp", "idaapi", "idautils", "idc", "ida_name", "ida_bytes", "ida_hexrays", "ida_typeinf", "ida_nalt", "ida_segment", "ida_funcs", "ida_kernwin", "ida_frame", "ida_lines", "rpc", "sync", "utils", "error_handling", "blackboard", "firmware_view", "_common", "ida_pro_mcp.ida_mcp.tools._common"):
            self._orig_modules[name] = sys.modules.get(name)
        sys.modules["ida_mcp"] = types.ModuleType("ida_mcp")
        for name in ("idaapi", "idautils", "idc", "ida_name", "ida_bytes", "ida_hexrays", "ida_typeinf", "ida_nalt", "ida_segment", "ida_funcs", "ida_kernwin", "ida_frame", "ida_lines"):
            mod = types.ModuleType(name)
            if name == "idaapi":
                mod.BADADDR = -1
                mod.get_kernel_version = lambda: "9.0"
            sys.modules[name] = mod
        rpc_mod = types.ModuleType("rpc")
        rpc_mod.tool = lambda f: f
        rpc_mod.unsafe = lambda f: f
        sys.modules["rpc"] = rpc_mod
        sync_mod = types.ModuleType("sync")
        sync_mod.idaread = lambda f: f
        sync_mod.idawrite = lambda f: f
        sync_mod.IDAError = Exception
        sys.modules["sync"] = sync_mod
        utils_mod = types.ModuleType("utils")
        for name in ("parse_address", "normalize_list_input", "normalize_dict_list", "get_function", "get_prototype", "get_image_size", "looks_like_address", "get_stack_frame_variables_internal", "get_type_by_name", "hex_ea", "hex_size", "smart_match", "compile_smart_pattern", "resolve_symbol"):
            setattr(utils_mod, name, lambda *args, **kwargs: None)
        sys.modules["utils"] = utils_mod
        eh_mod = types.ModuleType("error_handling")
        class _FakeMCPError:
            INVALID_ARGS = "INVALID_ARGS"
            IDA_ERROR = "IDA_ERROR"
        eh_mod.MCPError = _FakeMCPError
        eh_mod.make_error = lambda *args, **kwargs: {"ok": False, "error": args[1] if len(args) > 1 else ""}
        eh_mod.handle_error = lambda e: {"ok": False, "error": str(e)}
        eh_mod.ERROR_HINTS = {}
        for name in ("validate_addr", "validate_range", "check_debugger", "validate_path_safe", "require_arg", "require_one_of", "validate_action", "validate_count"):
            setattr(eh_mod, name, lambda *args, **kwargs: None)
        sys.modules["error_handling"] = eh_mod
        bb_mod = types.ModuleType("blackboard")
        bb_mod.BlackboardStore = None
        sys.modules["blackboard"] = bb_mod
        import importlib
        sys.modules.pop("firmware_view", None)
        sys.modules.pop("_common", None)
        sys.modules.pop("ida_pro_mcp.ida_mcp.tools._common", None)
        self.firmware_view_mod = importlib.import_module("firmware_view")

    def tearDown(self):
        for name, value in self._orig_modules.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value

    def test_seg_bounds_accepts_zero_based_images(self):
        self.firmware_view_mod._inf_min_ea = lambda: 0
        self.firmware_view_mod._inf_max_ea = lambda: 0x2000

        start, end, err = self.firmware_view_mod._seg_bounds(None, None)

        self.assertIsNone(err)
        self.assertEqual(start, 0)
        self.assertEqual(end, 0x2000)

    def test_create_ascii_string_uses_discovered_length(self):
        calls = []

        def _fake_create_strlit(ea, length, stype=None):
            calls.append((ea, length, stype))
            return True

        self.firmware_view_mod.idc.create_strlit = _fake_create_strlit

        ok = self.firmware_view_mod._create_ascii_string(0x3000, 8)

        self.assertTrue(ok)
        self.assertEqual(calls[0][1], 8)

    def test_detect_load_address_returns_structured_fallback_when_bounds_unavailable(self):
        self.firmware_view_mod._inf_min_ea = lambda: self.firmware_view_mod.idaapi.BADADDR
        self.firmware_view_mod._inf_max_ea = lambda: self.firmware_view_mod.idaapi.BADADDR

        result = self.firmware_view_mod.firmware_view(action="detect_load_address")

        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("binary_size"), "0x0")
        self.assertEqual(result.get("candidates"), [])
        self.assertIn("note", result)

    def test_detect_vector_table_returns_structured_fallback_when_bounds_unavailable(self):
        self.firmware_view_mod._inf_min_ea = lambda: self.firmware_view_mod.idaapi.BADADDR
        self.firmware_view_mod._inf_max_ea = lambda: self.firmware_view_mod.idaapi.BADADDR

        result = self.firmware_view_mod.firmware_view(action="detect_vector_table")

        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("vectors"), [])
        self.assertEqual(result.get("entry_points"), [])
        self.assertEqual(result.get("entry_count"), 0)

    def test_detect_mmio_returns_structured_fallback_when_bounds_unavailable(self):
        self.firmware_view_mod._inf_min_ea = lambda: self.firmware_view_mod.idaapi.BADADDR
        self.firmware_view_mod._inf_max_ea = lambda: self.firmware_view_mod.idaapi.BADADDR

        result = self.firmware_view_mod.firmware_view(action="detect_mmio")

        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("likely_chip_family"), "unknown")
        self.assertEqual(result.get("peripheral_count"), 0)
        self.assertEqual(result.get("peripherals"), [])

    def test_triage_snapshot_aggregates_detection_outputs(self):
        self.firmware_view_mod._inf_min_ea = lambda: self.firmware_view_mod.idaapi.BADADDR
        self.firmware_view_mod._inf_max_ea = lambda: self.firmware_view_mod.idaapi.BADADDR

        result = self.firmware_view_mod.firmware_view(action="triage_snapshot")

        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("action"), "triage_snapshot")
        self.assertIn("summary", result)
        self.assertIn("subresults", result)
        self.assertIn("load_address", result["subresults"])
        self.assertIn("vector_table", result["subresults"])
        self.assertIn("mmio", result["subresults"])
        self.assertIn("next_actions", result)
        self.assertGreaterEqual(len(result["next_actions"]), 1)


class TestContextAssemblerClassifierIntegration(unittest.TestCase):
    def setUp(self):
        self._orig_embedder = intel_mod.BgeCodeEmbedder
        self._orig_classifier_instance = BehaviorClassifier.__dict__["instance"]

        class _FakeBehaviorClassifier:
            def classify(self, text, threshold=0.35, top_k=4, block=True):
                return [{"behavior": "crypto_symmetric", "confidence": 0.99}]

        class _FakeEmbedder:
            def embed(self, text):
                return [0.0, 0.0]

            def embed_batch(self, texts):
                return [[0.0, 0.0] for _ in texts]

        intel_mod.BgeCodeEmbedder = _FakeEmbedder
        BehaviorClassifier.instance = classmethod(lambda cls, embedder: _FakeBehaviorClassifier())

    def tearDown(self):
        intel_mod.BgeCodeEmbedder = self._orig_embedder
        BehaviorClassifier.instance = self._orig_classifier_instance

    def test_decompile_enrichment_surfaces_behavior_classifications(self):
        asm = ContextAssembler()
        pack = {}
        pseudocode = """
        void aes_like(void) {
            sub_bytes();
            mix_columns();
            round_keys[0] = 0;
        }
        """
        asm._enrich_decompile(pack, {"name": "aes_like"}, pseudocode, "0x401000", "", None, "sess-behavior")
        self.assertIn("behavior_classifications", pack)
        self.assertEqual(pack["behavior_classifications"][0]["behavior"], "crypto_symmetric")
        self.assertIn("behavior_tags", pack)


class TestIdbOverviewRouting(unittest.TestCase):
    def setUp(self):
        self._orig_modules = {}
        for name in (
            "ida_mcp", "idaapi", "idautils", "idc", "ida_name", "ida_bytes",
            "ida_hexrays", "ida_typeinf", "ida_nalt", "ida_segment", "ida_funcs",
            "ida_kernwin", "ida_frame", "ida_lines", "ida_entry", "ida_ida",
            "rpc", "sync", "utils", "error_handling", "idb", "_common", "ida_pro_mcp.ida_mcp.tools._common"
        ):
            self._orig_modules[name] = sys.modules.get(name)
        sys.modules["ida_mcp"] = types.ModuleType("ida_mcp")
        for name in (
            "idaapi", "idautils", "idc", "ida_name", "ida_bytes", "ida_hexrays",
            "ida_typeinf", "ida_nalt", "ida_segment", "ida_funcs", "ida_kernwin",
            "ida_frame", "ida_lines", "ida_entry", "ida_ida"
        ):
            mod = types.ModuleType(name)
            if name == "idaapi":
                mod.BADADDR = -1
                mod.get_kernel_version = lambda: "9.0"
            sys.modules[name] = mod
        rpc_mod = types.ModuleType("rpc")
        rpc_mod.tool = lambda f: f
        rpc_mod.unsafe = lambda f: f
        sys.modules["rpc"] = rpc_mod
        sync_mod = types.ModuleType("sync")
        sync_mod.idaread = lambda f: f
        sync_mod.idawrite = lambda f: f
        sync_mod.IDAError = Exception
        sys.modules["sync"] = sync_mod
        utils_mod = types.ModuleType("utils")
        for name in ("parse_address", "normalize_list_input", "normalize_dict_list", "get_function", "get_prototype", "get_image_size", "looks_like_address", "get_stack_frame_variables_internal", "get_type_by_name", "hex_ea", "hex_size", "smart_match", "compile_smart_pattern", "resolve_symbol"):
            setattr(utils_mod, name, lambda *args, **kwargs: None)
        sys.modules["utils"] = utils_mod
        eh_mod = types.ModuleType("error_handling")
        class _FakeMCPError:
            INVALID_ARGS = "INVALID_ARGS"
        eh_mod.MCPError = _FakeMCPError
        eh_mod.make_error = lambda *args, **kwargs: {"ok": False, "message": args[1] if len(args) > 1 else ""}
        eh_mod.handle_error = lambda e, *_args, **_kwargs: {"ok": False, "error": str(e)}
        eh_mod.ERROR_HINTS = {}
        for name in ("validate_addr", "validate_range", "check_debugger", "validate_path_safe", "require_arg", "require_one_of", "validate_action", "validate_count"):
            setattr(eh_mod, name, lambda *args, **kwargs: None)
        sys.modules["error_handling"] = eh_mod
        import importlib
        sys.modules.pop("idb", None)
        sys.modules.pop("_common", None)
        sys.modules.pop("ida_pro_mcp.ida_mcp.tools._common", None)
        self.idb_mod = importlib.import_module("idb")

    def tearDown(self):
        for name, value in self._orig_modules.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value

    def test_overview_firmware_next_actions_include_triage_snapshot(self):
        # idb(action='overview') calls into the real infer_binary_arch_profile
        # via idb_architecture_profile. Stub it out so we don't recurse into
        # the architecture inference path which needs filesystem access.
        self.idb_mod.idb_architecture_profile = lambda meta=None, summary=None: {
            "current": {"processor": "arm", "bitness": 32, "endian": "little",
                        "file_type": "raw"},
            "inferred_from_binary": {"candidates": []},
            "raw_binary_mode": True,
            "recommendations": [],
        }
        self.idb_mod.idb_meta = lambda **kw: {
            "file_type": "raw", "processor": "arm", "image_base": 0,
            "min_ea": 0, "max_ea": 0, "is_be": False, "file_type_id": 17,
            "file_type_info": {"effective": "raw", "loader": "raw"},
        }
        self.idb_mod.idb_summary = lambda **kw: {"imports": 0, "functions": 0}
        self.idb_mod.idb_segments_detailed = lambda **kw: []
        self.idb_mod.idb_entrypoints_detailed = lambda **kw: {"entrypoints": []}

        result = self.idb_mod.idb(action="overview")

        self.assertTrue(result.get("ok"), msg=f"idb(overview) failed: {result}")
        self.assertTrue(result.get("firmware_detected"))
        actions = result.get("next_actions", [])
        self.assertIn("firmware_view(action='triage_snapshot')", actions)

    def test_overview_non_firmware_next_actions_exclude_triage_snapshot(self):
        self.idb_mod.idb_architecture_profile = lambda meta=None, summary=None: {
            "current": {"processor": "metapc", "bitness": 64, "endian": "little",
                        "file_type": "pe"},
            "inferred_from_binary": {"candidates": []},
            "raw_binary_mode": False,
            "recommendations": [],
        }
        self.idb_mod.idb_meta = lambda **kw: {
            "file_type": "pe", "processor": "metapc", "image_base": 0,
            "min_ea": 0, "max_ea": 0, "is_be": False, "file_type_id": 8,
            "file_type_info": {"effective": "pe", "loader": "pe"},
        }
        self.idb_mod.idb_summary = lambda **kw: {"imports": 24, "functions": 100}
        self.idb_mod.idb_segments_detailed = lambda **kw: []
        self.idb_mod.idb_entrypoints_detailed = lambda **kw: {"entrypoints": []}

        result = self.idb_mod.idb(action="overview")

        self.assertTrue(result.get("ok"), msg=f"idb(overview) failed: {result}")
        self.assertFalse(result.get("firmware_detected", False))
        actions = result.get("next_actions", [])
        self.assertNotIn("firmware_view(action='triage_snapshot')", actions)


if __name__ == "__main__":
    unittest.main()
