#!/usr/bin/env python3
"""
AST-level regression tests for the 50-feature llm_helpers expansion pass.
"""

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LLM_HELPERS_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "llm_helpers.py"
HOST_PATH = ROOT / "ida_mcp_stdio.py"


NEW_ACTIONS = {
    "intent_tool_compiler",
    "adaptive_query_planner",
    "token_aware_context_optimizer",
    "cross_call_variable_resolver",
    "evidence_weighted_response_assembler",
    "uncertainty_propagation_engine",
    "multi_granularity_retrieval_layer",
    "semantic_chunking_for_decompiled_code",
    "question_type_router",
    "interactive_clarification_protocol",
    "behavioral_signature_search",
    "cross_artifact_correlation_search",
    "temporal_search_replay",
    "search_hypothesis_sandbox",
    "path_constrained_search",
    "argument_semantics_search",
    "decompile_disasm_consistency_search",
    "near_miss_search_ranking",
    "persistent_search_collections",
    "auto_expansion_search_chains",
    "function_role_classifier",
    "protocol_format_reconstruction_assistant",
    "global_state_influence_mapper",
    "api_contract_extractor",
    "interprocedural_data_lineage_graph",
    "semantic_diff_explainer",
    "dangerous_pattern_explainer",
    "binary_capability_matrix_builder",
    "execution_hypothesis_generator",
    "patch_impact_forecaster",
    "safe_idapython_orchestration_runtime",
    "script_template_marketplace_layer",
    "auto_script_synthesis_from_intent",
    "script_output_schema_enforcer",
    "long_running_job_manager",
    "cross_session_script_memory",
    "privilege_scope_guardrails_for_scripts",
    "script_to_tool_promotion_pipeline",
    "experiment_harness_for_script_variants",
    "idapython_provenance_recorder",
    "investigation_playbook_engine",
    "next_best_action_recommender",
    "analysis_dead_end_detector",
    "workset_intelligence_capsules",
    "contradiction_tracker",
    "review_queue_for_ai_edits",
    "case_narrative_composer",
    "cost_latency_optimizer",
    "trust_verification_layer",
    "learning_feedback_loop",
}


def _find_fn(module, name):
    return next((n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == name), None)


class TestLLMHelpersExpansionAst(unittest.TestCase):
    def setUp(self):
        self.source = LLM_HELPERS_PATH.read_text(encoding="utf-8")
        self.module = ast.parse(self.source)

    def test_llm_helpers_action_literal_includes_all_expansion_actions(self):
        fn = _find_fn(self.module, "llm_helpers")
        self.assertIsNotNone(fn)
        action_arg = next((a for a in fn.args.args if a.arg == "action"), None)
        self.assertIsNotNone(action_arg)
        ann = action_arg.annotation
        self.assertIsInstance(ann, ast.Subscript)
        literal = ann.slice.elts[0]
        values = {
            e.value
            for e in literal.slice.elts
            if isinstance(e, ast.Constant) and isinstance(e.value, str)
        }
        for action in NEW_ACTIONS:
            self.assertIn(action, values)

    def test_feature_phase_map_has_exactly_50_new_actions(self):
        node = next(
            (
                n
                for n in self.module.body
                if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "_FEATURE_PHASES" for t in n.targets)
            ),
            None,
        )
        self.assertIsNotNone(node)
        self.assertIsInstance(node.value, ast.Dict)
        keys = [k.value for k in node.value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        self.assertEqual(len(keys), 50)
        self.assertEqual(set(keys), NEW_ACTIONS)

    def test_dispatcher_source_mentions_all_expansion_actions(self):
        for action in NEW_ACTIONS:
            self.assertIn(f'"{action}"', self.source)


class TestHostRegistrationExpansionAst(unittest.TestCase):
    def test_tool_actions_llm_helpers_contains_expansion_actions(self):
        source = HOST_PATH.read_text(encoding="utf-8")
        module = ast.parse(source)
        tool_actions = None
        for node in module.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "TOOL_ACTIONS":
                        tool_actions = node.value
                        break
                if tool_actions is not None:
                    break
        self.assertIsNotNone(tool_actions)
        self.assertIsInstance(tool_actions, ast.Dict)

        llm_actions = None
        for k, v in zip(tool_actions.keys, tool_actions.values):
            if isinstance(k, ast.Constant) and k.value == "llm_helpers":
                llm_actions = v
                break
        self.assertIsNotNone(llm_actions)
        self.assertIsInstance(llm_actions, ast.List)
        action_values = {elt.value for elt in llm_actions.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)}
        for action in NEW_ACTIONS:
            self.assertIn(action, action_values)


if __name__ == "__main__":
    unittest.main()
