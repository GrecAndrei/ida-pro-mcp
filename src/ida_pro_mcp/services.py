"""Single import contract for all subsystems.

Tools and test files should import from here, not from
host.* or host.intelligence.* directly.  Internal host/ structure
can change freely — only this file needs updating.
"""

from __future__ import annotations

# --- Host server infrastructure -------------------------------------------
from ida_pro_mcp.host.analysis.arch_profile import (
    infer_binary_arch_profile,
    normalize_arch_options,
)
from ida_pro_mcp.host.analysis.context_density import ContextDensityOptimizer
from ida_pro_mcp.host.analysis.patterns import compile_smart_pattern, smart_match
from ida_pro_mcp.host.auto_nudge import get_reroute
from ida_pro_mcp.host.batch_manager import BatchManager, BatchTask
from ida_pro_mcp.host.config import CACHE_DIR
from ida_pro_mcp.host.errors import MCPError, make_error

# --- Intelligence layer ---------------------------------------------------
from ida_pro_mcp.host.intelligence.context import (
    ContextAssembler,
    get_assembler,
)
from ida_pro_mcp.host.intelligence.core import (
    INTEL_PROFILE,
    BehaviorClassifier,
    BgeCodeEmbedder,
    FunctionEmbeddingIndex,
    _extract_signature,
)

# AgentMacroCrystallizer removed (cleanup cut)
# FederationBridge removed (cleanup cut)
from ida_pro_mcp.host.intelligence.helpers import (
    best_match,
    coerce_int,
    estimate_tokens,
    parse_str_list,
    quantile,
)
from ida_pro_mcp.host.intelligence.rerank import Reranker
from ida_pro_mcp.host.intelligence.usage import UsageIntelligence
from ida_pro_mcp.host.policy import (
    PolicyDecision,
    PolicyMode,
    RiskTier,
    build_audit_record,
    classify_tool_action,
    evaluate_policy,
)
from ida_pro_mcp.host.schemas import (
    ADVERTISED_TOOLS,
    HIDDEN_TOOLS_IN_LIST,
    TOOL_ACTIONS,
    TOOL_ARG_SCHEMAS,
    TOOL_DESCRIPTIONS,
    TOOLS,
)
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_session import ServerSessionMixin
from ida_pro_mcp.host.server.session import Session, SessionManager
from ida_pro_mcp.host.stores.blackboard_store import (
    BlackboardStore,
    _resolve_db_path,
)
from ida_pro_mcp.host.stores.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.stores.symbol_db import SymbolDB

__all__ = [
    "BgeCodeEmbedder",
    "BehaviorClassifier",
    "FunctionEmbeddingIndex",
    "Reranker",
    "_extract_signature",
    "INTEL_PROFILE",
    "ContextAssembler",
    "get_assembler",
    "coerce_int",
    "estimate_tokens",
    "parse_str_list",
    "UsageIntelligence",
    "infer_binary_arch_profile",
    "normalize_arch_options",
    "BlackboardStore",
    "_resolve_db_path",
    "MCPError",
    "make_error",
    "PolicyDecision",
    "PolicyMode",
    "RiskTier",
    "build_audit_record",
    "classify_tool_action",
    "evaluate_policy",
    "KnowledgeGraph",
    "CACHE_DIR",
    "ContextDensityOptimizer",
    "SymbolDB",
    "compile_smart_pattern",
    "smart_match",
    "best_match",
    "quantile",
    "BatchManager",
    "BatchTask",
    "get_reroute",
    "IDAMCPServer",
    "ServerSessionMixin",
    "Session",
    "SessionManager",
    "ADVERTISED_TOOLS",
    "HIDDEN_TOOLS_IN_LIST",
    "TOOLS",
    "TOOL_ACTIONS",
    "TOOL_ARG_SCHEMAS",
    "TOOL_DESCRIPTIONS",
]
