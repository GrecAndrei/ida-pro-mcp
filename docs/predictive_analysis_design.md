# Predictive Analysis Architecture for IDA Pro MCP

**Design Document**  
*May 2026*

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Core Data Layer Integrations](#2-core-data-layer-integrations)
3. [Predictive Capability 1: Next-Tool Prediction](#3-next-tool-prediction)
4. [Predictive Capability 2: Function Completion System](#4-function-completion-system)
5. [Predictive Capability 3: Stuck Detection & Breakthrough Paths](#5-stuck-detection--breakthrough-paths)
6. [Predictive Capability 4: Vulnerability Class Prediction](#6-vulnerability-class-prediction)
7. [Predictive Capability 5: Similar Case Retrieval](#7-similar-case-retrieval)
8. [Predictive Capability 6: Pre-Computed Interestingness Scores](#8-pre-computed-interestingness-scores)
9. [Predictive Capability 7: Analyst Preference Learning](#9-analyst-preference-learning)
10. [Unified Predictor Engine: New Tool Design](#10-unified-predictor-engine)
11. [Resource Exposure: Predictive Resources](#11-resource-exposure)
12. [Implementation Roadmap](#12-implementation-roadmap)

---

## 1. Executive Summary

This document describes how to combine four existing components—**SchemaBoot** (SQLite function index), **TurboQuant** (3-bit compressed embeddings), **BridgeRAG** (multi-hop bridge search), and **MemRL** (Q-learning on episodic memory)—to create a predictive analysis layer for IDA Pro MCP.

The core insight: **these four components form a complete retrieval-augmented learning loop**:

```
SchemaBoot ──> TurboQuant ──> BridgeRAG ──> MemRL
   │              │              │              │
   │   (index)    │   (embedd)   │  (bridge)    │  (feedback)
   └──────────────┴──────────────┴──────────────┘
                       │
              Predictive Engine (new)
                       │
         ┌─────────────┼─────────────┐
         │             │             │
    Next-Tool    Function      Vulnerability
    Prediction   Completion    Prediction
         │             │             │
    Stuck-Detect   SimilarCase   Interestingness
```

The design proposes:

1. **A unified `predictor` tool** that wraps all seven predictive capabilities
2. **Resource endpoints** (`ida://predictive/...`) exposing computed scores
3. **A learning feedback pipeline** that uses MemRL to improve predictions over time
4. **Zero IDAPython dependency for predictions**—all queries run against pre-built indexes

---

## 2. Core Data Layer Integrations

### 2.1 SchemaBoot Extension: Predictive Metadata Columns

Extend the `function_attrs` table with five new columns to store pre-computed predictive scores:

```sql
ALTER TABLE function_attrs ADD COLUMN interestingness REAL DEFAULT 0.0;
ALTER TABLE function_attrs ADD COLUMN predicted_vuln_class TEXT DEFAULT NULL;
ALTER TABLE function_attrs ADD COLUMN predicted_vuln_confidence REAL DEFAULT 0.0;
ALTER TABLE function_attrs ADD COLUMN embedding_cluster_id INTEGER DEFAULT -1;
ALTER TABLE function_attrs ADD COLUMN analysis_progress REAL DEFAULT 0.0;
```

New auxiliary tables:

```sql
-- Pre-computed next-tool suggestions by function signature
CREATE TABLE predictor_next_tool (
    func_ea INTEGER NOT NULL,
    signature_hash TEXT NOT NULL,       -- hash of function feature vector
    suggested_tool TEXT NOT NULL,
    suggested_action TEXT NOT NULL,
    confidence REAL DEFAULT 0.0,
    frequency INTEGER DEFAULT 0,
    PRIMARY KEY (signature_hash, suggested_tool, suggested_action),
    FOREIGN KEY (func_ea) REFERENCES function_attrs(ea)
);

-- Pre-computed interestingness score breakdown
CREATE TABLE predictor_interestingness (
    func_ea INTEGER NOT NULL PRIMARY KEY,
    total_score REAL NOT NULL,
    api_interestingness REAL DEFAULT 0.0,
    string_interestingness REAL DEFAULT 0.0,
    structural_interestingness REAL DEFAULT 0.0,
    xref_interestingness REAL DEFAULT 0.0,
    entropy_interestingness REAL DEFAULT 0.0,
    embedding_novelty REAL DEFAULT 0.0,
    last_updated REAL NOT NULL,
    FOREIGN KEY (func_ea) REFERENCES function_attrs(ea)
);

-- Function-to-vulnerability-class predictions
CREATE TABLE predictor_vuln_prediction (
    func_ea INTEGER NOT NULL PRIMARY KEY,
    predicted_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    top_features TEXT,                  -- JSON: [{feature, weight}, ...]
    similar_vuln_funcs TEXT,            -- JSON: [{name, cve, similarity}, ...]
    FOREIGN KEY (func_ea) REFERENCES function_attrs(ea)
);

-- Similar-case library (cross-binary fingerprint database)
CREATE TABLE predictor_similarity_library (
    fingerprint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_hash TEXT NOT NULL,          -- SHA256 of binary
    binary_name TEXT,
    func_ea INTEGER NOT NULL,
    func_name TEXT NOT NULL,
    fingerprint BLOB NOT NULL,          -- 256-bit locality-sensitive hash
    known_malware_family TEXT,
    known_cve TEXT,
    tags TEXT,                          -- JSON array
    created_at REAL NOT NULL
);
CREATE INDEX idx_similarity_fp ON predictor_similarity_library(fingerprint);
CREATE INDEX idx_similarity_binary ON predictor_similarity_library(binary_hash);
```

### 2.2 TurboQuant Extension: Multi-Resolution Embeddings

Extend `FunctionEmbeddingEngine` to produce three embedding levels:

```python
class MultiResolutionEmbedding:
    """
    Three-tier embedding for different prediction tasks:
    
    - Coarse (256 dim): for clustering, interestingness, anomaly detection
    - Medium (1024 dim): for similarity search, vuln class prediction
    - Fine (4096 dim): for precise function matching (existing)
    """
    
    RESOLUTIONS = {"coarse": 256, "medium": 1024, "fine": 4096}
    
    def __init__(self):
        self._engines = {
            name: FunctionEmbeddingEngine(dim=d)
            for name, d in self.RESOLUTIONS.items()
        }
        self._banks = {
            name: TurboQuantMemoryBank(dim=d, chunk_size=min(128, d))
            for name, d in self.RESOLUTIONS.items()
        }
    
    def ingest_all(self, schemaboot_db: str):
        """Vectorize all functions at all resolutions and store in TurboQuant banks."""
        ...
    
    def cluster_coarse(self, n_clusters: int = 32) -> Dict[int, int]:
        """Cluster coarse embeddings using k-means, return {ea: cluster_id}."""
        ...
```

### 2.3 BridgeRAG Extension: Predictive Bridges

Add a new bridge type for predictive search: **"pattern_bridges"** — functions connected by shared structural patterns (instruction mix similarity, entropy ranges, complexity bands):

```python
def pattern_bridge_search(func_ea: int, top_k: int = 10) -> List[Dict]:
    """
    Find functions with similar structural patterns to func_ea,
    using SchemaBoot's numeric columns as the bridge.
    
    Uses z-score normalized similarity across:
    - entropy, bb_count, cyclomatic_complexity,
    - instruction mix ratios (xor/size, call/size, push/size, etc.)
    - api_count, string_count, data_ref_count
    """
```

### 2.4 MemRL Extension: Predictive Reward Signals

Add a new reward type for predictive tasks:

```python
PREDICTIVE_REWARDS = {
    "next_tool_accepted": 0.8,      # LLM used our suggested next tool
    "next_tool_declined": -0.3,     # LLM chose something else
    "vuln_prediction_correct": 1.0, # Vulnerability class matched later analysis
    "vuln_prediction_wrong": -0.7,  # Vulnerability class was wrong
    "interestingness_confirmed": 0.6, # LLM examined a high-interestingness function
    "stuck_breakthrough": 1.0,      # LLM escaped stuck state using our suggestion
    "stuck_false_positive": -0.5,   # We flagged stuck but LLM was fine
    "similar_case_useful": 0.8,     # LLM found a similar case reference useful
    "similar_case_waste": -0.4,     # LLM ignored our similar case suggestion
}
```

---

## 3. Predictive Capability 1: Next-Tool Prediction

### 3.1 Goal

Given the current function the LLM is examining and the sequence of tools it just called, predict the next most useful tool/action pair. This is analogous to next-token prediction, but for analysis tool sequences.

### 3.2 Algorithm: Tool-Sequence Markov Model + MemRL

```python
class NextToolPredictor:
    """
    Predicts the next tool call based on:
    
    1. Function feature vector matched against SchemaBoot signatures
       → Look up pre-computed tool sequences for similar functions
    
    2. Current tool call history (last 3 tool calls)
       → N-gram Markov model of tool sequences
    
    3. MemRL Q-values for (function_signature, tool) pairs
       → Bootstrap from historical analyst behavior
    """
    
    def predict(
        self,
        func_ea: int,
        recent_tools: List[str],    # e.g., ["search", "code", "data"]
        signature: Dict,            # SchemaBoot attrs for current function
        top_k: int = 3,
    ) -> List[Dict]:
        """
        1. Hash the function signature → lookup predictor_next_tool table
           for confidences by (signature_hash)
        
        2. Compute Markov score: P(next_tool | last_3_tools) from global
           tool-transition matrix (also stored in SQLite)
        
        3. Query MemRL for Q-values of (signature_hash, tool) pairs
        
        4. Weighted combination:
           score = 0.4 * frequency_bias + 0.3 * markov_score + 0.3 * memrl_q
           
        5. Return top_k {(tool, action, confidence, reasoning)}
        """
```

### 3.3 Learning Pipeline

```python
def log_tool_call(
    func_ea: int,
    tool: str,
    action: str,
    success: bool,
    signature_hash: str,
):
    """
    1. Increment predictor_next_tool table for the signature hash
    2. Update tool-transition Markov matrix
    3. MemRL update:
       - intent_key = signature_hash
       - experience_key = tool:action  
       - reward = +0.8 if accepted, -0.3 if declined
    """
```

### 3.4 Data Flow

```
LLM examines func @ 0x401000
       │
       ▼
NextToolPredictor.predict(0x401000, ["search", "code"])
       │
       ├──> SchemaBoot → signature_hash = SHA256(numeric_attrs)
       ├──> predictor_next_tool WHERE signature_hash = ?
       ├──> MemRL: get_q("sig_abc123", "code:decompile") → 0.82
       ├──> Markov: P("code" | "search", "code") → 0.45
       └──> Combine → [{"tool":"code","action":"decompile","confidence":0.87}, ...]
```

---

## 4. Predictive Capability 2: Function Completion System

### 4.1 Goal

Given partial analysis of a function (e.g., only its name and API calls), predict the remaining properties (entropy, complexity, strings, instruction mix, behavioral tags, vulnerability class). This enables "pre-fetching" function attributes before the LLM explicitly requests them.

### 4.2 Algorithm: Multi-Target Embedding Regression

```python
class FunctionCompletionPredictor:
    """
    Predicts missing function attributes from observed ones using:
    
    1. Nearest-neighbor imputation: find similar functions in TurboQuant
       with complete data, copy their missing attributes
    
    2. Embedding interpolation: project partial vector onto coarse PCA
       space → reconstruct missing dimensions
    
    3. SchemaBoot rule-based fallback: if 0-observed, return median
       values from functions with similar API patterns
    """
    
    def predict_missing(
        self,
        partial_attrs: Dict,  # what we know
    ) -> Dict:
        """
        Observed keys → build partial embedding (zero out missing dims)
        → TurboQuant similarity search to find K=5 nearest complete functions
        → For each missing attribute, compute weighted average from neighbors
        
        Returns dict with predicted values + confidence intervals:
        {
            "entropy": {"predicted": 5.8, "confidence": 0.87, "range": [5.2, 6.3]},
            "cyclomatic_complexity": {"predicted": 14, "confidence": 0.72, ...},
            "has_loops": {"predicted": True, "confidence": 0.91},
            "strings": [predicted list with confidence scores],
            "behavior_tags": ["crypto", "network"],
            "vuln_class": {"predicted": "buffer_overflow", "confidence": 0.65},
        }
        """
    
    def complete_schema_from_name(self, name: str) -> Dict:
        """
        Special case: only the function name is known (e.g., just loaded a binary).
        
        1. Tokenize name (e.g., "sub_401000", "memcpy_safe")
        2. If auto-generated ("sub_*"): return default predictions
        3. If named: match against known name patterns → predicted attrs
           "decrypt_*" → crypto behavior, high xor_count, etc.
           "alloc_*" → memory behavior, low complexity
           "ConnectToServer" → network behavior, socket APIs
        """
```

### 4.3 Partial Analysis States

| State | Observed | Predictable |
|-------|----------|-------------|
| Name only | `sub_401000` | Size ~100-500 (median), entropy ~5.5 (median) |
| Name + APIs | `CryptDecrypt` called | crypto behavior tag, high xor_count, high complexity |
| Name + APIs + size | size=512, calls VirtualAlloc | heap manipulation, dangerous_api tag |
| Full SchemaBoot | all numeric attrs | strings, behavior tags, vuln class |
| Full + decompile | all attrs + pseudocode | recommended next tools, similar cases |

---

## 5. Predictive Capability 3: Stuck Detection & Breakthrough Paths

### 5.1 Goal

Detect when the LLM is "spinning its wheels" (repeating similar tool calls with no progress) and suggest breakthrough paths: alternative analysis strategies, related functions to examine, or different approaches.

### 5.2 Stuck Detection Algorithm

```python
class StuckDetector:
    """
    Detects stuck states using:
    
    1. Tool repetition: same tool+action called >3x within N calls
    2. Address stagnation: LLM examining the same address range
    3. Negative progress indicators:
       - Repeated decompile with no rename
       - Repeated search with no follow-through
       - Back-and-forth between two functions
    4. MemRL entropy: low variety in (intent_key, experience_key) pairs
    """
    
    def detect(
        self,
        activity_log: List[Dict],  # from session manager
        current_addr: Optional[int],
        window: int = 15,
    ) -> StuckReport:
        score = 0.0
        reasons = []
        
        # 1. Tool repetition score
        recent_tools = [e["tool"] + ":" + e["action"] for e in activity_log[-window:]]
        tool_set = set(recent_tools)
        redundancy = 1.0 - (len(tool_set) / max(len(recent_tools), 1))
        if redundancy > 0.6:
            score += 0.4
            reasons.append(f"Tool repetition: {redundancy:.0%} redundant")
        
        # 2. Address stagnation
        if current_addr and len(activity_log) >= 3:
            recent_addrs = [e.get("addr") or e.get("func_ea") for e in activity_log[-5:] if e.get("addr") or e.get("func_ea")]
            if recent_addrs and all(a == recent_addrs[0] for a in recent_addrs):
                score += 0.3
                reasons.append("Address stagnation: same address for 5+ calls")
        
        # 3. No-progress indicators
        n_edits = sum(1 for e in activity_log[-window:] if e.get("is_edit"))
        if n_edits == 0 and len(activity_log) >= 10:
            score += 0.3
            reasons.append("No edits in last 10 actions (read-only mode)")
        
        is_stuck = score >= 0.5
        
        return StuckReport(
            is_stuck=is_stuck,
            stuck_score=score,
            reasons=reasons,
            severity="high" if score > 0.7 else ("medium" if score > 0.5 else "low"),
        )
```

### 5.3 Breakthrough Path Generator

```python
class BreakthroughGenerator:
    """
    Generates breakthrough suggestions when stuck is detected.
    
    Strategies ranked by MemRL Q-values + diversity bonus:
    """
    
    STRATEGIES = [
        # Switch to different analysis mode
        {"type": "perspective_switch", "tool": "graph", "action": "callgraph", "reason": "Visualize the call tree"},
        {"type": "perspective_switch", "tool": "ctree", "action": "get_logic_flow", "reason": "Abstract away to logic flow"},
        
        # Examine related functions via bridges
        {"type": "bridge_explore", "tool": "bridgerag", "action": "search", "reason": "Find functions sharing APIs"},
        {"type": "bridge_explore", "tool": "bridgerag", "action": "bridges", "reason": "Extract bridge entities from current"},
        
        # Search by different criteria
        {"type": "alternative_search", "tool": "search", "action": "string", "reason": "Search for error messages"},
        {"type": "alternative_search", "tool": "search", "action": "immediate", "reason": "Explore constants used"},
        
        # Classification / summarization
        {"type": "classify", "tool": "classify", "action": "induce_schema", "reason": "Get structured function schema"},
        {"type": "classify", "tool": "classify", "action": "function", "reason": "Classify function purpose"},
        
        # Look at data flow
        {"type": "data_flow", "tool": "ctree", "action": "var_dependency_graph", "reason": "Track variable dependencies"},
        
        # Compare with similar
        {"type": "compare", "tool": "compare", "action": "semantics", "reason": "Find semantic twins"},
        
        # Cross-reference deep dive
        {"type": "xref_deep", "tool": "xref_analysis", "action": "call_chain", "reason": "Trace call chain backward"},
    ]
    
    def suggest(
        self,
        stuck_report: StuckReport,
        current_func_ea: int,
        activity_log: List[Dict],
        memrl_bank: MemRLBank,
        top_k: int = 3,
    ) -> List[Dict]:
        """
        1. Filter strategies not yet attempted in this session
        2. Score each by MemRL Q + diversity (vs. recent strategies)
        3. Re-rank to ensure diverse types (don't suggest 3 bridge searches)
        4. Return top_k with concrete {tool, action, args, reasoning}
        """
```

### 5.4 Integration with Session Management

```python
# In agent.py or new predictor.py tool:

@tool
@idaread
def predictor(
    action="detect_stuck",
    ...
):
    if action == "detect_stuck":
        # Read activity log from session manager
        log = session_manager.get_activity_log(sid)
        
        # Detect stuck
        detector = StuckDetector()
        report = detector.detect(log["log"], current_addr)
        
        if report.is_stuck:
            # Generate breakthrough paths
            generator = BreakthroughGenerator()
            suggestions = generator.suggest(
                report, current_addr, log["log"], memrl_bank
            )
            return {"stuck": True, "report": report, "breakthroughs": suggestions}
        else:
            return {"stuck": False, "report": report}
```

---

## 6. Predictive Capability 4: Vulnerability Class Prediction

### 6.1 Goal

From function embeddings alone (before decompilation), predict the likely vulnerability class the function might harbor. This enables prioritization: flag high-risk functions early.

### 6.2 Algorithm: Multi-Label Embedding Classifier

```python
class VulnClassifier:
    """
    Predicts vulnerability class from function embeddings using:
    
    1. SchemaBoot attributes: instruction mix, API calls, entropy, complexity
       → Rule-based pre-filter (deterministic, immediate)
    
    2. TurboQuant embedding: compressed function vector
       → k-NN in embedding space against labeled training samples
       → Distance-weighted class probability
    
    3. BridgeRAG expansion: find functions that call same dangerous APIs
       → If those functions have known vuln classes, propagate
    
    4. Confidence = agreement between rule-based + embedding + bridge predictions
    """
    
    DANGEROUS_PATTERNS = {
        "buffer_overflow": {
            "apis": ["memcpy", "strcpy", "sprintf", "gets", "scanf", "wcscpy"],
            "mnemonic_ratio": {"call": (0.05, 0.3), "mov": (0.2, 0.6), "ret": (0.01, 0.1)},
            "entropy_range": (4.0, 7.5),
        },
        "format_string": {
            "apis": ["printf", "fprintf", "sprintf", "snprintf"],
            "strings_like": ["%s", "%x", "%n"],
        },
        "command_injection": {
            "apis": ["system", "popen", "exec", "CreateProcess", "ShellExecute"],
            "strings_like": ["cmd.exe", "/bin/sh", "powershell", "bash"],
        },
        "heap_overflow": {
            "apis": ["malloc", "HeapAlloc", "new", "realloc"],
            "structural_features": ["has_loops"],
        },
        "integer_overflow": {
            "mnemonic_ratio": {"add": (0.01, 0.15), "sub": (0.01, 0.1), "mul": (0.005, 0.05)},
            "cmp_ratio": (0.05, 0.2),
        },
        "use_after_free": {
            "apis": ["free", "HeapFree", "delete"],
            "structural_features": ["highly_referenced"],
        },
        "crypto_misuse": {
            "apis": ["CryptDecrypt", "CryptEncrypt", "RC4", "AES", "MD5"],
            "mnemonic_ratio": {"xor": (0.02, 0.3)},
        },
    }
    
    def predict(
        self,
        schemaboot_row: Dict,
        embedding: Optional[np.ndarray] = None,
    ) -> List[Dict]:
        """
        1. Rule-based: match DANGEROUS_PATTERNS against observed attrs
        2. Embedding: k-NN in vuln-labeled TurboQuant bank
        3. Bridge: propagate from API-sharing functions
        4. Ensemble: weighted voting
        """
```

### 6.3 Pre-Computation Pipeline

```python
def precompute_vuln_predictions(schemaboot_db: str, turboquant_bank: str):
    """
    Runs on `predictor(action="precompute_vuln")`:
    
    For each function in SchemaBoot:
    1. Apply rule-based classifier → base prediction + confidence
    2. Query TurboQuant for nearest neighbors with known vuln classes
    3. Weighted ensemble → final prediction
    4. Store in predictor_vuln_prediction table
    
    This is a one-time cost. Incremental refresh on demand.
    """
```

### 6.4 Training Data Accumulation

Vulnerability class labels come from:

1. **Manual annotations**: Analyst sets `vuln_class` via annotation tool
2. **CVE matching**: Functions whose addresses match known CVEs
3. **Decompiler analysis**: Detected patterns (format string, buffer overflow)
4. **Cross-binary propagation**: Same function in multiple binaries, known in one

---

## 7. Predictive Capability 5: Similar Case Retrieval

### 7.1 Goal

Given a function being analyzed, retrieve similar functions from a cross-binary library (known malware samples, prior analyses, CVE-related functions). This enables: "this function looks like the CnC handler in Mirai variant X."

### 7.2 Algorithm: Multi-Resolution Fingerprint Matching

```python
class SimilarCaseRetriever:
    """
    Three-tier similarity matching with increasing precision:
    
    Tier 1 (Fast):  64-bit MinHash of instruction mnemonics
                     → Candidate pool from similarity_library
    
    Tier 2 (Medium): SchemaBoot attribute cosine distance
                     → Score candidates by numeric similarity
    
    Tier 3 (Fine):   TurboQuant embedding dot product
                     → Re-rank top 50 with full precision
    """
    
    def search(
        self,
        func_ea: int,
        library_path: str = None,  # cross-binary library
        top_k: int = 5,
        min_confidence: float = 0.3,
    ) -> List[Dict]:
        """
        1. Extract feature fingerprint from current function
        2. MinHash → O(1) candidate lookup in library
        3. SchemaBoot score: z-normalized cosine similarity
        4. TurboQuant score: compressed embedding dot product
        5. MemRL boost: if this (function, candidate) pair has high Q
        6. Return ranked results with:
           - Source binary name, function name
           - Known CVE or malware family
           - Similarity breakdown (structural vs. API vs. string)
           - Suggested next analysis steps
        """
```

### 7.3 Cross-Binary Library Schema

```sql
CREATE TABLE predictor_similarity_library (
    fingerprint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_hash TEXT NOT NULL,          -- SHA256 of binary file
    binary_name TEXT NOT NULL,          -- e.g., "mirai_sample_312"
    func_ea INTEGER NOT NULL,
    func_name TEXT NOT NULL,
    minhash_64 INTEGER NOT NULL,        -- 64-bit MinHash signature
    schemaboot_json TEXT,               -- cached SchemaBoot row (JSON)
    turboquant_blob BLOB,               -- cached compressed embedding
    known_malware_family TEXT,          -- e.g., "mirai", "emotet"
    known_cve TEXT,                     -- e.g., "CVE-2021-44228"
    tags TEXT,                          -- JSON array: ["cnc", "exploit", "downloader"]
    source_url TEXT,                    -- where this sample came from
    created_at REAL NOT NULL,
    metadata TEXT                       -- freeform JSON
);

-- MinHash lookup index (5 permuted tables for LSH)
CREATE TABLE predictor_lsh_table0 (
    minhash_bucket INTEGER NOT NULL,
    fingerprint_id INTEGER NOT NULL,
    PRIMARY KEY (minhash_bucket, fingerprint_id)
);
-- ... tables 1-4
```

### 7.4 Library Population

```bash
# CLI tool to populate the library:
predictor action=add_to_library binary=malware_sample.exe name=mirai \
    tags=cnc,ddos source=virusshare
```

Or within IDA:

```
predictor(action="add_current_to_library", binary_name="target.exe",
          tags=["suspicious", "network"])
```

---

## 8. Predictive Capability 6: Pre-Computed Interestingness Scores

### 8.1 Goal

Score every function by "how interesting/important it is to analyze" before the LLM even looks at it. Expose as a resource so the LLM can prioritize.

### 8.2 Interestingness Scoring Algorithm

```python
class InterestingnessScorer:
    """
    Multi-factor interestingness score (0.0 - 10.0).
    
    Factors:
    
    1. API Dangerousness (0-3):
       - VirtualAlloc, memcpy → +1 each
       - system, CreateRemoteThread → +2 each
       - Known CVE-related APIs → +3
    
    2. Structural Anomaly (0-2):
       - Entropy Z-score > 2.5 → +1
       - Cyclomatic complexity Z-score > 2.0 → +0.5
       - XOR count Z-score > 2.0 → +0.5
    
    3. Connectivity (0-2):
       - Incoming xrefs Z-score > 2.0 → +1 (hub function)
       - Outgoing xrefs Z-score > 2.0 → +0.5
       - Is orphan (0 xrefs) → +0.5 (suspicious)
    
    4. Bridge Value (0-1.5):
       - Number of unique APIs called → weighted
       - Number of unique strings referenced → weighted
    
    5. Embedding Novelty (0-1.5):
       - Distance to nearest neighbor in TurboQuant space
       - High novelty → higher interestingness (unusual function)
    """
    
    SCORE_WEIGHTS = {
        "api_dangerousness": 3.0,
        "structural_anomaly": 2.0,
        "connectivity": 2.0,
        "bridge_value": 1.5,
        "embedding_novelty": 1.5,
    }
    
    def compute(self, schemaboot_row: Dict, embedding: np.ndarray) -> InterestBreakdown:
        return InterestBreakdown(
            total_score=round(sum(scores.values()), 2),
            breakdown=scores,
            reasons=self._generate_reasons(scores),
            priority="critical" if total > 8 else
                     "high" if total > 6 else
                     "medium" if total > 4 else "low",
        )
```

### 8.3 Resource Exposure

New resource URI:

```
ida://predictive/interestingness               → Top 50 most interesting functions
ida://predictive/interestingness/{ea}          → Single function's interestingness breakdown
ida://predictive/interestingness/segments      → Per-segment interestingness distribution
```

Resource implementation:

```python
# In resources.py, add to RESOURCE_TEMPLATES:
"ida://predictive/interestingness",
"ida://predictive/interestingness/{ea}",
"ida://predictive/interestingness/segments",

class PredictiveResourceResolver:
    def resolve(self, uri: str) -> Dict:
        if uri == "ida://predictive/interestingness":
            # Query predictor_interestingness table, ORDER BY total_score DESC
            return top_50_functions()
        elif uri.startswith("ida://predictive/interestingness/"):
            ea = extract_ea(uri)
            return get_interestingness_breakdown(ea)
```

### 8.4 Pre-Computation

```python
def precompute_interestingness(schemaboot_db: str, turboquant_bank: str):
    """
    1. Load all function attrs from SchemaBoot
    2. Load TurboQuant bank for embeddings
    3. Compute z-scores for all numeric columns
    4. For each function, compute all 5 interestingness factors
    5. Store in predictor_interestingness table
    6. Mark interestingness scores in function_attrs.interestingness
    
    Runs as: predictor(action="precompute_interestingness")
    """
```

---

## 9. Predictive Capability 7: Analyst Preference Learning

### 9.1 Goal

Use MemRL's episodic memory to learn *individual analyst preferences* across sessions, and predict their next moves based on historical behavior patterns.

### 9.2 Algorithm: User-Contextualized MemRL

```python
class PreferenceLearner:
    """
    Learns analyst preferences using a hierarchical MemRL approach:
    
    Level 1: Session-level (current binary analysis session)
    Level 2: User-level (all sessions by same analyst)
    Level 3: Global-level (all analysts, anonymized)
    
    Prediction is the weighted average of all three levels, with
    session-level having highest weight.
    """
    
    # intent_key encoding scheme:
    # session:   "session:{sid}:func:{func_ea}:ctx:{tool_sequence_hash}"
    # user:      "user:{user_id}:func_class:{function_class}:ctx:{context_hash}"
    # global:    "global:func_class:{function_class}:ctx:{context_hash}"
    
    def predict_next_move(
        self,
        current_func: Dict,         # SchemaBoot attrs of current function
        recent_actions: List[str],  # ["code:decompile", "modify:rename", ...]
        analyst_id: str,            # from session metadata or env
        sid: str,                   # current session ID
        top_k: int = 3,
    ) -> List[Dict]:
        """
        1. Build context signature from function class + recent actions
        2. Query MemRL at three levels:
           - session: exact match on SID + func_ea
           - user: match on analyst_id + function class
           - global: match on function class only
        3. Weight each level: 0.6 session, 0.3 user, 0.1 global
        4. Return top_k {tool, action, args, confidence, provenance}
        """
```

### 9.3 Preference Profiles

```python
class AnalystProfile:
    """
    Stored in session metadata or a dedicated SQLite table.
    """
    
    def __init__(self, analyst_id: str):
        self.analyst_id = analyst_id
        self.preferred_tools = {}           # {tool: frequency}
        self.preferred_actions = {}         # {action: frequency}
        self.common_renames = []            # [("sub_*", "crypto_*"), ...]
        self.typical_workflow = []          # ordered tool sequence patterns
        self.interestingness_bias = 0.5     # 0=structural, 1=API-focused
    
    def extract_from_memrl(self, memrl_bank: MemRLBank):
        """
        Query all triplets with intent_key like "user:{analyst_id}:*"
        Extract tool preferences, workflow patterns, and biases.
        """
```

### 9.4 Cross-Session Transfer

```python
def transfer_learning(source_sid: str, target_sid: str, analyst_id: str):
    """
    When starting a new session for the same analyst:
    
    1. Copy high-Q triplets from source sessions
    2. Adjust Q-values with decay factor 0.9 (recency matters)
    3. Pre-populate predictor_next_tool with learned patterns
    4. Set initial interestingness bias from profile
    """
```

---

## 10. Unified Predictor Engine: New Tool Design

### 10.1 Tool Schema

```python
@tool
@idaread  # predictions don't modify the database
def predictor(
    action: str,
    addr: Optional[str] = None,
    query: Optional[str] = None,
    top_k: int = 5,
    min_confidence: float = 0.0,
    include_factors: bool = False,
    sid: Optional[str] = None,
) -> dict:
    """
    Predictive Analysis Engine: combines SchemaBoot, TurboQuant, BridgeRAG, MemRL
    to provide seven predictive capabilities.
    
    ACTIONS:
    
    ## Next-Tool Prediction
    suggest_next_tool - Predict next useful tool/action for current function
        Params: addr (current function), top_k
        Returns: [{tool, action, args, confidence, reasoning}]
    
    suggest_next_address - Predict which address/function to examine next
        Params: addr (current), top_k
        Returns: [{addr, name, reason, confidence}]
    
    ## Function Completion
    complete_function - Predict missing attributes for a partially analyzed function
        Params: addr
        Returns: {predicted: {attr: {value, confidence, range}}, known: {...}}
    
    ## Stuck Detection
    detect_stuck - Detect if analysis is spinning wheels
        Params: sid (session ID), addr
        Returns: {is_stuck, score, reasons, breakthroughs: [...]}
    
    ## Vulnerability Prediction
    predict_vuln - Predict vulnerability class for a function
        Params: addr
        Returns: {predicted_class, confidence, top_features, similar_vuln_funcs}
    
    ## Similar Case Retrieval
    find_similar_cases - Find similar functions in cross-binary library
        Params: addr, top_k
        Returns: [{binary_name, func_name, similarity, known_malware, known_cve}]
    
    ## Interestingness
    interestingness - Get pre-computed interestingness score for a function
        Params: addr
        Returns: {total_score, breakdown, priority, reasons}
    
    interestingness_top - Get most interesting functions in the binary
        Params: top_k, segment (optional filter)
        Returns: [{addr, name, score, priority}]
    
    ## Preference Learning
    learn_profile - Extract analyst preference profile from MemRL
        Params: sid
        Returns: {preferred_tools, typical_workflow, biases}
    
    predict_analyst_next - Predict analyst's next action from learned profile
        Params: sid, addr
        Returns: [{suggested_tool, action, confidence, provenance}]
    
    ## Pre-computation
    precompute_all - Build all predictive indexes (interestingness, vuln, next-tool)
        Runs full pipeline: load schemaboot → vectorize → cluster → score → store
        Returns: {status, functions_processed, elapsed_seconds}
    
    precompute_interestingness - Build only interestingness scores
    precompute_vuln - Build only vulnerability predictions
    precompute_next_tool - Build only next-tool suggestions
    add_to_library - Add current function to cross-binary similarity library
        Params: binary_name, tags, malware_family, cve
    """
```

### 10.2 Implementation Architecture

```
┌─────────────────────────────────────────────────┐
│                   predictor.py                   │
│  (entry point, routes to sub-modules)            │
├─────────────────────────────────────────────────┤
│                                                   │
│  ┌────────────────┐  ┌────────────────────────┐  │
│  │ _next_tool.py  │  │ _function_complete.py   │  │
│  │ Markov + MemRL │  │ Embedding regression    │  │
│  └────────────────┘  └────────────────────────┘  │
│                                                   │
│  ┌────────────────┐  ┌────────────────────────┐  │
│  │ _stuck_detect  │  │ _vuln_predict.py       │  │
│  │ .py            │  │ Rule + Embedding +      │  │
│  │ Pattern-based  │  │ Bridge ensemble          │  │
│  └────────────────┘  └────────────────────────┘  │
│                                                   │
│  ┌────────────────┐  ┌────────────────────────┐  │
│  │ _similar_cases │  │ _interestingness.py     │  │
│  │ .py            │  │ Multi-factor scorer      │  │
│  │ Cross-binary   │  └────────────────────────┘  │
│  │ MinHash + LSH  │                              │
│  └────────────────┘                              │
│                                                   │
│  ┌──────────────────────────────┐                │
│  │ _preference_learner.py       │                │
│  │ Hierarchical MemRL (session  │                │
│  │  / user / global)             │                │
│  └──────────────────────────────┘                │
└─────────────────────────────────────────────────┘
```

### 10.3 Registration in Tool Registry

Add to `schemas.py`:

```python
# In TOOLS list:
"predictor",

# In TOOL_DESCRIPTIONS:
"predictor": "Predictive analysis engine: next-tool prediction, function completion, stuck detection, vulnerability prediction, similar-case retrieval, interestingness scoring, and analyst preference learning. Combines SchemaBoot, TurboQuant, BridgeRAG, and MemRL.",

# In TOOL_ACTIONS:
"predictor": [
    "suggest_next_tool", "suggest_next_address",
    "complete_function",
    "detect_stuck",
    "predict_vuln",
    "find_similar_cases",
    "interestingness", "interestingness_top",
    "learn_profile", "predict_analyst_next",
    "precompute_all", "precompute_interestingness",
    "precompute_vuln", "precompute_next_tool",
    "add_to_library",
],
```

---

## 11. Resource Exposure

Beyond the tool interface, predictive data should be exposed as MCP Resources so the LLM can "pre-fetch" interestingness data without tool calls:

```python
# New resource templates:
PREDICTIVE_RESOURCES = [
    "ida://predictive/interestingness",
    "ida://predictive/interestingness/{ea}",
    "ida://predictive/interestingness/segments",
    "ida://predictive/vuln/top_riskiest",       # Top 20 highest vuln confidence
    "ida://predictive/vuln/by_class/{class}",    # Filter by vuln class
    "ida://predictive/stuck/{sid}",              # Current stuck status
    "ida://predictive/next_tool/{ea}",           # Top next-tool suggestions for address
    "ida://predictive/landing_page",             # Dashboard: top interesting + stuck + vuln
]
```

**Landing page resource** (`ida://predictive/landing_page`):

```json
{
  "uri": "ida://predictive/landing_page",
  "mimeType": "application/json",
  "text": {
    "summary": {
      "total_functions": 1542,
      "indexed_functions": 1542,
      "interestingness_computed": true,
      "vuln_predictions": true,
      "similarity_library_size": 28741
    },
    "top_interestingness": [
      {"ea": "0x401000", "name": "sub_401000", "score": 9.2, "priority": "critical", "reasons": ["VirtualAlloc", "high_entropy", "hub_function"]},
      ...
    ],
    "high_vuln_risk": [
      {"ea": "0x405200", "name": "process_data", "predicted_class": "buffer_overflow", "confidence": 0.87}
    ],
    "stuck_status": {"is_stuck": false, "score": 0.2},
    "analyst_profile": {"preferred_tools": ["code:decompile", "data:functions", "modify:rename"]}
  }
}
```

---

## 12. Implementation Roadmap

### Phase 1: Foundation (Week 1)
- [ ] Extend SchemaBoot with predictive metadata columns
- [ ] Create `predictor_interestingness`, `predictor_vuln_prediction`, `predictor_next_tool` tables
- [ ] Add MultiResolutionEmbedding to TurboQuant
- [ ] Implement `precompute_all` pipeline

### Phase 2: Interestingness & Vulnerabilities (Week 2)
- [ ] Implement `InterestingnessScorer` with all five factors
- [ ] Implement `VulnClassifier` with rule-based + embedding ensemble
- [ ] Register new resource endpoints
- [ ] Tests: verify scores are deterministic and meaningful

### Phase 3: Next-Tool & Stuck Detection (Week 3)
- [ ] Implement `NextToolPredictor` with Markov + MemRL
- [ ] Implement `StuckDetector` and `BreakthroughGenerator`
- [ ] Integration with session activity logging
- [ ] Tests: simulate stuck patterns and verify detection

### Phase 4: Similar Case & Preference Learning (Week 4)
- [ ] Create cross-binary similarity library schema and MinHash LSH
- [ ] Implement `SimilarCaseRetriever` with three-tier matching
- [ ] Implement `PreferenceLearner` with hierarchical MemRL
- [ ] CLI tool for library population

### Phase 5: Integration & Polish (Week 5)
- [ ] Build `predictor` tool with all actions routed
- [ ] Landing page resource
- [ ] Auto-precompute on session start (background thread)
- [ ] Documentation and examples
- [ ] All 7 predictive capabilities tested end-to-end

---

## Appendix A: Examples

### Example 1: Next-Tool Prediction in Action

```
User: "What's at 0x401000?"
  → LLM calls predictor(action="suggest_next_tool", addr="0x401000")
  → Gets: [{"tool":"code", "action":"decompile", "confidence":0.9},
            {"tool":"data", "action": "functions", "query": "decrypt", "confidence":0.7}]
  → LLM calls code(action="decompile", addr="0x401000")
  → MemRL reward: +0.8 (suggestion accepted)
```

### Example 2: Stuck Detection Breakthrough

```
Activity log shows: 8 identical decompile calls on 0x401000, no renames
  → LLM calls predictor(action="detect_stuck", sid="ABC123")
  → Returns: {is_stuck: true, score: 0.72,
    breakthroughs: [
      {"type": "bridge_explore", "tool": "bridgerag", "action": "search",
       "args": {"query_constraints": {"addr": "0x401000"}},
       "reason": "Find functions sharing APIs with current"},
      {"type": "perspective_switch", "tool": "graph", "action": "callgraph",
       "args": {"addr": "0x401000"},
       "reason": "Visualize the call tree for context"}
    ]}
  → LLM follows breakthrough suggestion
  → MemRL reward: +1.0 (breakthrough effective)
```

### Example 3: Vulnerability-Driven Prioritization

```
User: "Which functions should I analyze first?"
  → LLM calls predictor(action="interestingness_top", top_k=5)
  → Gets: [{ea: "0x401000", score: 9.2, priority: "critical"},
            {ea: "0x405200", score: 8.1, priority: "high", predicted_vuln: "buffer_overflow"}]
  → LLM prioritizes 0x405200 due to vuln prediction
  → Later confirmed: function has unbounded memcpy → actual buffer overflow
  → MemRL reward: +1.0 (vuln prediction correct)
```

### Example 4: Cross-Binary Similar Case

```
Analyst examining sub_405100 in target.exe:
  → predictor(action="find_similar_cases", addr="0x405100")
  → Returns: [{binary: "mirai_sample.exe", func: "cnc_connect",
               similarity: 0.87, malware: "mirai", tags: ["cnc", "ddos"]}]
  → Analyst: "This is a Mirai-style CnC handler"
  → Immediately renames and recognizes the pattern
  → MemRL reward: +0.8 (similar case useful)
```

---

## Appendix B: Performance Characteristics

| Operation | Time (10K funcs) | Time (100K funcs) | Notes |
|-----------|-----------------|-------------------|-------|
| `precompute_all` | ~30s | ~5min | One-time per binary |
| `interestingness` query | <5ms | <10ms | Pre-computed table lookup |
| `predict_vuln` | <10ms | <20ms | Pre-computed table lookup |
| `suggest_next_tool` | <15ms | <30ms | Table + MemRL query |
| `find_similar_cases` | <50ms | <200ms | MinHash LSH + re-rank |
| `detect_stuck` | <5ms | <5ms | In-memory activity log analysis |
| `suggest_next_address` | <30ms | <100ms | BridgeRAG + interestingness |
| TurboQuant ingest | ~20s | ~3min | 4096-dim vectors, 3-bit compress |

---

*This design document defines the architecture for integrating SchemaBoot, TurboQuant, BridgeRAG, and MemRL into a unified predictive analysis layer for IDA Pro MCP. The system provides seven distinct predictive capabilities through a single `predictor` tool and multiple MCP resource endpoints.*
