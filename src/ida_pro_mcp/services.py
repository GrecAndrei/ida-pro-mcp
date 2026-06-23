"""Single import contract for all subsystems.

Tools and test files should import from here, not from
host.* or host.intelligence.* directly.  Internal host/ structure
can change freely — only this file needs updating.
"""

from __future__ import annotations

# --- Intelligence layer ---------------------------------------------------

from ida_pro_mcp.host.intelligence.analogy import CrossBinaryAnalogyEngine
from ida_pro_mcp.host.intelligence.bridge_retrieval import (
    MultiHopBridgeIndex,
    _resolve_schemaboot_db_path,
)
from ida_pro_mcp.host.intelligence.context import (
    ContextAssembler,
    get_assembler,
)
from ida_pro_mcp.host.intelligence.core import (
    INTEL_PROFILE,
    BehaviorClassifier,
    BgeCodeEmbedder,
    FunctionEmbeddingIndex,
    SemanticObject,
    SemanticObjectIndex,
    _extract_signature,
)
from ida_pro_mcp.host.intelligence.crystallizer import AgentMacroCrystallizer
from ida_pro_mcp.host.intelligence.entropy import FunctionEntropyCalculator
from ida_pro_mcp.host.intelligence.federation import FederationBridge
from ida_pro_mcp.host.intelligence.helpers import (
    best_match,
    coerce_int,
    estimate_tokens,
    parse_str_list,
    quantile,
)
from ida_pro_mcp.host.intelligence.reasoner import VulnerabilityReasoner
from ida_pro_mcp.host.intelligence.structural_index import (
    get_db_path,
    ensure_tables,
    upsert_functions_batch,
    execute_host_query,
    write_insight_index,
    add_global_facts,
    _detect_global_facts,
)
from ida_pro_mcp.host.intelligence.usage import UsageIntelligence

# --- Host server infrastructure -------------------------------------------

from ida_pro_mcp.host.analysis.analysis_engine import AnalysisEngine
from ida_pro_mcp.host.analysis.arch_profile import (
    infer_binary_arch_profile,
    normalize_arch_options,
)
from ida_pro_mcp.host.analysis.context_density import ContextDensityOptimizer
from ida_pro_mcp.host.analysis.frontier import FrontierEngine
from ida_pro_mcp.host.analysis.gap_engine import GapEngine
from ida_pro_mcp.host.analysis.narrative_engine import NarrativeEngine
from ida_pro_mcp.host.auto_nudge import get_reroute
from ida_pro_mcp.host.batch_manager import BatchManager, BatchTask
from ida_pro_mcp.host.stores.analysis_proposal_store import ProposalStore
from ida_pro_mcp.host.stores.blackboard_store import (
    BlackboardStore,
    _resolve_db_path,
)
from ida_pro_mcp.host.stores.chip_db import (
    find_chip_profile,
    get_chip_family_catalog,
)
from ida_pro_mcp.host.stores.knowledge_graph import KnowledgeGraph
from ida_pro_mcp.host.stores.symbol_db import SymbolDB
from ida_pro_mcp.host.casefile_helpers import (
    build_chain_of_custody,
    build_risk_summary,
    to_markdown_casefile,
)
from ida_pro_mcp.host.config import CACHE_DIR
from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.host.policy import (
    PolicyDecision,
    PolicyMode,
    RiskTier,
    build_audit_record,
    classify_tool_action,
    evaluate_policy,
)
from ida_pro_mcp.host.mbagcn_engine import (
    CFGExtractor,
    GraphEmbeddingStore,
    MbaGCNEncoder,
    default_db_path,
    default_db_path as mbagcn_default_db_path,
    is_available,
    is_available as mbagcn_is_available,
)
from ida_pro_mcp.host.analysis.patterns import compile_smart_pattern, smart_match
from ida_pro_mcp.host.server.resources import list_resources, ResourceResolver
from ida_pro_mcp.host.schemas import (
    ADVERTISED_TOOLS,
    HIDDEN_TOOLS_IN_LIST,
    TOOLS,
    TOOL_ACTIONS,
    TOOL_ARG_SCHEMAS,
    TOOL_DESCRIPTIONS,
    WRAPPER_ACTIONS,
)
from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.server_session import ServerSessionMixin
from ida_pro_mcp.host.server.session import Session, SessionManager

__all__ = [
    "AnalysisEngine",
    "BgeCodeEmbedder",
    "BehaviorClassifier",
    "FunctionEmbeddingIndex",
    "SemanticObject",
    "SemanticObjectIndex",
    "_extract_signature",
    "INTEL_PROFILE",
    "ContextAssembler",
    "get_assembler",
    "MultiHopBridgeIndex",
    "_resolve_schemaboot_db_path",
    "CrossBinaryAnalogyEngine",
    "AgentMacroCrystallizer",
    "FunctionEntropyCalculator",
    "FederationBridge",
    "coerce_int",
    "estimate_tokens",
    "parse_str_list",
    "VulnerabilityReasoner",
    "StructuralIndex",
    "get_structural_db_path",
    "get_db_path",
    "ensure_tables",
    "upsert_functions_batch",
    "execute_host_query",
    "write_insight_index",
    "add_global_facts",
    "_detect_global_facts",
    "UsageIntelligence",
    "infer_binary_arch_profile",
    "normalize_arch_options",
    "BlackboardStore",
    "_resolve_db_path",
    "build_chain_of_custody",
    "build_risk_summary",
    "to_markdown_casefile",
    "MCPError",
    "make_error",
    "PolicyDecision",
    "PolicyMode",
    "RiskTier",
    "build_audit_record",
    "classify_tool_action",
    "evaluate_policy",
    "find_chip_profile",
    "get_chip_family_catalog",
    "KnowledgeGraph",
    "CACHE_DIR",
    "ContextDensityOptimizer",
    "FrontierEngine",
    "GapEngine",
    "NarrativeEngine",
    "CFGExtractor",
    "GraphEmbeddingStore",
    "MbaGCNEncoder",
    "mbagcn_default_db_path",
    "mbagcn_is_available",
    "default_db_path",
    "is_available",
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
    "list_resources",
    "ResourceResolver",
    "ADVERTISED_TOOLS",
    "HIDDEN_TOOLS_IN_LIST",
    "TOOLS",
    "TOOL_ACTIONS",
    "TOOL_ARG_SCHEMAS",
    "TOOL_DESCRIPTIONS",
    "WRAPPER_ACTIONS",
]
