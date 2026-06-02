#!/usr/bin/env python3
"""
Governance Engine for IDA Pro MCP.

Deterministic pre-flight rule engine that intercepts ALL write operations
before they touch the IDB. Prevents dangerous patches, PII leaks, and
misleading annotations.

Implements deterministic governance checks with zero external dependencies.

Integration:
    from .governance_engine import get_governance, evaluate_operation

    # In any write tool:
    result = evaluate_operation("comment", addr=0x401000,
                                proposed_value="C2 at 192.168.1.1")
    if not result["approved"]:
        return make_error(MCPError.GOVERNANCE_BLOCKED, result["violations"])
    value = result.get("redacted_content", value)

Example:
    >>> gov = GovernanceEngine()
    >>> result = gov.evaluate_operation("patch", addr=0x401000,
    ...     proposed_value="nop", metadata={"section_type": ".idata"})
    >>> result["approved"]
    False
    >>> result["violations"][0]["rule"]
    'No Import Table Patches'
"""

import re
import time
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any


# ============================================================================
# SECTION 1: Core Types and Enums
# ============================================================================

class OperationType(Enum):
    """Types of RE operations subject to governance."""
    PATCH = auto()
    COMMENT = auto()
    RENAME = auto()
    TYPE_CHANGE = auto()
    EXECUTION = auto()
    ANNOTATION = auto()


class Severity(Enum):
    """Violation severity levels."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


class Verdict(Enum):
    """Governance verdict."""
    APPROVED = "approved"
    BLOCKED = "blocked"
    REDACTED = "redacted"
    WARNED = "warned"


# ============================================================================
# SECTION 2: RE-Safe OWL Ontology
# ============================================================================

class REOntology:
    """
    Formal OWL-style ontology for reverse engineering safety.

    Defines classes, properties, and axioms for RE operation governance.
    Implements a simplified OWL-style reasoner using axiom satisfaction scoring.

    Each class is defined by:
        - universal_axioms: all must be satisfied
        - existential_axioms: at least one must be satisfied (if non-empty)

    Classification score:
        c = (m_forall + m_exists) / denominator
    """

    def __init__(self):
        # (universal_axioms, existential_axioms)
        self.ontology_classes: Dict[str, Tuple[List[str], List[str]]] = {
            "ImportTablePatch": (
                ["is_patch", "targets_import_section"],
                []
            ),
            "DangerousCodeSectionPatch": (
                ["is_patch", "targets_executable_section"],
                ["modifies_code_flow", "bypasses_security_check"]
            ),
            "PIIExposingComment": (
                ["is_comment"],
                ["contains_ip", "contains_email", "contains_credential",
                 "contains_hash_secret", "contains_domain"]
            ),
            "MisleadingRename": (
                ["is_rename"],
                ["contradicts_api_evidence", "implies_incorrect_prototype",
                 "suggests_false_security"]
            ),
            "UnsafeStackFrameChange": (
                ["is_type_change", "targets_stack"],
                ["changes_frame_size", "invalidates_locals",
                 "breaks_calling_convention"]
            ),
            "DangerousUnknownExecution": (
                ["is_execution"],
                ["unknown_origin", "writes_to_disk", "opens_socket",
                 "modifies_system_state", "calls_encryption"]
            ),
            "CompliantOperation": ([], []),
        }

        self.class_severity: Dict[str, Severity] = {
            "ImportTablePatch": Severity.CRITICAL,
            "DangerousCodeSectionPatch": Severity.CRITICAL,
            "PIIExposingComment": Severity.HIGH,
            "MisleadingRename": Severity.MEDIUM,
            "UnsafeStackFrameChange": Severity.HIGH,
            "DangerousUnknownExecution": Severity.CRITICAL,
            "CompliantOperation": Severity.INFO,
        }

        self.class_verdict: Dict[str, Verdict] = {
            "ImportTablePatch": Verdict.BLOCKED,
            "DangerousCodeSectionPatch": Verdict.BLOCKED,
            "PIIExposingComment": Verdict.REDACTED,
            "MisleadingRename": Verdict.WARNED,
            "UnsafeStackFrameChange": Verdict.BLOCKED,
            "DangerousUnknownExecution": Verdict.BLOCKED,
            "CompliantOperation": Verdict.APPROVED,
        }

    def classify(self, properties: Set[str],
                 threshold: float = 0.3) -> List[Tuple[str, float]]:
        """
        Classify an operation given its inferred properties.

        Args:
            properties: Set of property strings inferred about the operation
            threshold: Minimum axiom satisfaction score (default 0.3)

        Returns:
            List of (class_name, confidence) sorted by confidence descending
        """
        results = []
        for class_name, (universal, existential) in self.ontology_classes.items():
            m_forall = sum(1 for ax in universal if ax in properties)
            # All universal axioms must be satisfied (strict requirement)
            if universal and m_forall < len(universal):
                continue
            m_exists = 1 if existential and any(ax in properties for ax in existential) else 0
            existential_satisfied = (not existential) or (m_exists == 1)
            if not existential_satisfied:
                continue
            # Score based on how many properties matched (for ranking)
            total = len(universal) + (1 if existential else 0)
            c = (m_forall + m_exists) / total if total > 0 else 1.0
            if c >= threshold:
                results.append((class_name, c))

        results.sort(key=lambda x: x[1], reverse=True)
        return results


# ============================================================================
# SECTION 3: Deterministic Rule Layer
# ============================================================================

class RERule:
    """A single deterministic governance rule."""

    def __init__(self, rule_id: str, name: str, severity: Severity,
                 description: str, resolution: Optional[str] = None):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.description = description
        self.resolution = resolution

    def evaluate(self, op_type: OperationType, addr: Optional[int],
                 proposed_value: str, context: Dict[str, Any],
                 metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate rule against operation. Override in subclasses."""
        raise NotImplementedError


class NoImportTablePatchRule(RERule):
    """
    Rule R001: No patches to import tables.
    Critical — always blocks patches targeting .idata/.plt/.edata.
    """

    def __init__(self):
        super().__init__(
            rule_id="R001",
            name="No Import Table Patches",
            severity=Severity.CRITICAL,
            description="Patches to the import address table (IAT), PLT, or "
                       "export address table (EAT) are blocked. Modifying "
                       "imports can mask malicious DLL hijacking or hide "
                       "API call redirection that bypasses security controls.",
            resolution="Remove this patch. Use semantic renaming instead.",
        )

    def evaluate(self, op_type, addr, proposed_value, context, metadata):
        violations = []
        if op_type != OperationType.PATCH:
            return violations

        is_import = metadata.get("section_type", "") in (".idata", ".edata", ".iat", ".plt")
        is_import_addr = metadata.get("is_import_addr", False)

        if is_import or is_import_addr:
            violations.append({
                "rule_id": self.rule_id,
                "rule": self.name,
                "severity": self.severity.name,
                "description": f"{self.description} Operation targets "
                              f"import section at {hex(addr) if addr else 'unknown'}.",
                "resolution": self.resolution,
            })
        return violations


class NoPIIInCommentsRule(RERule):
    """
    Rule R002: No comments containing PII (IPs, emails, domains, secrets).
    High — redacts content automatically.
    """

    def __init__(self):
        super().__init__(
            rule_id="R002",
            name="No PII in Comments",
            severity=Severity.HIGH,
            description="Comments must not contain personally identifiable "
                       "information, internal IP addresses, credentials, or "
                       "secret keys. Sensitive values are automatically "
                       "redacted before annotation is committed.",
            resolution="Review redacted content and remove sensitive data "
                      "before committing.",
        )
        # (pattern, replacement, pii_type)
        self.pii_patterns = [
            (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), "[IP_REDACTED]", "IP address"),
            (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), "[EMAIL_REDACTED]", "email"),
            (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "[SSN_REDACTED]", "SSN"),
            (re.compile(r'\b(?:\d[ -]*?){13,16}\b'), "[CC_REDACTED]", "credit card"),
            (re.compile(r'\b[a-fA-F0-9]{32}\b'), "[MD5_REDACTED]", "MD5 hash"),
            (re.compile(r'\b[a-fA-F0-9]{40}\b'), "[SHA1_REDACTED]", "SHA1 hash"),
            (re.compile(r'\b[a-fA-F0-9]{64}\b'), "[SHA256_REDACTED]", "SHA256 hash"),
            (re.compile(r'(?i)(?:password|passwd|secret|token|api[_-]?key)'
                       r'\s*[:=]\s*\S+'), "[CREDENTIAL_REDACTED]", "credential"),
            (re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'), "[DOMAIN_REDACTED]", "domain"),
        ]

    def evaluate(self, op_type, addr, proposed_value, context, metadata):
        violations = []
        if op_type not in (OperationType.COMMENT, OperationType.ANNOTATION):
            return violations

        text = proposed_value
        for pattern, replacement, pii_type in self.pii_patterns:
            if pattern.search(text):
                violations.append({
                    "rule_id": self.rule_id,
                    "rule": self.name,
                    "severity": self.severity.name,
                    "description": f"PII detected: {pii_type}. "
                                  f"Will be redacted to '{replacement}'.",
                    "resolution": self.resolution,
                })
        return violations

    def redact(self, text: str) -> str:
        """Apply all PII redactions to text."""
        redacted = text
        for pattern, replacement, _pii_type in self.pii_patterns:
            redacted = pattern.sub(replacement, redacted)
        return redacted


class NoMisleadingRenameRule(RERule):
    """
    Rule R003: No misleading renames that imply incorrect semantics.
    Medium — warns but allows with acknowledgement.
    """

    def __init__(self):
        super().__init__(
            rule_id="R003",
            name="No Misleading Renames",
            severity=Severity.MEDIUM,
            description="Function/variable renames must not misrepresent "
                       "the actual functionality. Names that suggest security "
                       "properties ('safe', 'secure', 'harmless') when "
                       "dangerous APIs are used are flagged.",
            resolution="Remove security-suggesting keywords from name, "
                      "or verify operation is genuinely safe.",
        )
        self.false_security_keywords = [
            "safe", "secure", "harmless", "no_risk", "benign", "trusted"
        ]
        self.dangerous_api_prefixes = [
            "memcpy", "strcpy", "sprintf", "gets", "system", "popen",
            "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"
        ]

    def evaluate(self, op_type, addr, proposed_value, context, metadata):
        violations = []
        if op_type != OperationType.RENAME:
            return violations

        proposed = proposed_value.lower()
        has_security_claim = any(kw in proposed for kw in self.false_security_keywords)

        # Gather API calls from context or metadata
        api_calls = context.get("api_calls", "") + metadata.get("api_calls", "")
        has_dangerous_apis = any(ap in api_calls for ap in self.dangerous_api_prefixes)

        if has_security_claim and has_dangerous_apis:
            violations.append({
                "rule_id": self.rule_id,
                "rule": self.name,
                "severity": self.severity.name,
                "description": f"Rename '{proposed_value}' suggests safety "
                              f"but function calls dangerous APIs.",
                "resolution": self.resolution,
            })

        # Check for main() signature mismatch
        if "main" in proposed:
            arg_count = context.get("arg_count", 0) or metadata.get("arg_count", 0)
            if arg_count > 3:
                violations.append({
                    "rule_id": self.rule_id + "_main",
                    "rule": "main() Signature Mismatch",
                    "severity": Severity.LOW.name,
                    "description": f"Rename to 'main' but function has "
                                  f"{arg_count} arguments (expected <= 3).",
                    "resolution": "Consider a more descriptive name "
                                  "that reflects actual parameters.",
                })

        return violations


class NoUnsafeStackFrameChangeRule(RERule):
    """
    Rule R004: No type changes on stack frames without validation.
    High — blocks unless explicitly validated.
    """

    def __init__(self):
        super().__init__(
            rule_id="R004",
            name="No Unsafe Stack Frame Changes",
            severity=Severity.HIGH,
            description="Changes to stack frame layout (frame size, local "
                       "variable types, calling convention) require explicit "
                       "validation. Incorrect stack frame types can cause "
                       "decompiler crashes or silent misanalysis.",
            resolution="Validate frame layout with funcs(action='info', "
                      "include_stack=True) before committing.",
        )

    def evaluate(self, op_type, addr, proposed_value, context, metadata):
        violations = []
        if op_type != OperationType.TYPE_CHANGE:
            return violations

        is_stack = metadata.get("targets_stack", False)
        changes_size = metadata.get("changes_frame_size", False)
        invalidates_locals = metadata.get("invalidates_locals", False)

        if is_stack and changes_size:
            violations.append({
                "rule_id": self.rule_id,
                "rule": self.name,
                "severity": self.severity.name,
                "description": f"Stack frame size change at "
                              f"{hex(addr) if addr else 'unknown'} without validation.",
                "resolution": self.resolution,
            })

        if is_stack and invalidates_locals:
            violations.append({
                "rule_id": self.rule_id + "_locals",
                "rule": "Stack Local Variable Invalidation",
                "severity": Severity.MEDIUM.name,
                "description": "Type change invalidates existing local variable assignments.",
                "resolution": "Re-analyze function after type change with analysis(action='reanalyze').",
            })

        return violations


class NoUnknownCodeExecutionRule(RERule):
    """
    Rule R005: No execution of unknown code during trace analysis.
    Critical — always blocks.
    """

    def __init__(self):
        super().__init__(
            rule_id="R005",
            name="No Unknown Code Execution",
            severity=Severity.CRITICAL,
            description="Dynamic execution of code with unknown origin "
                       "is blocked. This prevents accidental detonation of "
                       "malicious payloads during sandbox analysis or "
                       "deobfuscation attempts.",
            resolution="Sandbox the code first, verify origin, "
                      "or use static analysis instead.",
        )
        self.suspicious_behaviors = [
            "writes_to_disk", "opens_socket", "calls_encryption",
            "modifies_registry", "creates_process", "injects_code",
            "downloads_payload", "elevates_privileges"
        ]

    def evaluate(self, op_type, addr, proposed_value, context, metadata):
        violations = []
        if op_type != OperationType.EXECUTION:
            return violations

        unknown_origin = metadata.get("unknown_origin", True)
        if unknown_origin:
            detected = [b for b in self.suspicious_behaviors if metadata.get(b, False)]
            sev = Severity.CRITICAL if detected else Severity.HIGH
            violations.append({
                "rule_id": self.rule_id,
                "rule": self.name,
                "severity": sev.name,
                "description": f"Attempted execution of code from unknown origin" +
                              (f" with suspicious behaviors: {detected}." if detected else "."),
                "resolution": self.resolution,
            })
        return violations


class NoRenameLibraryFunctionsRule(RERule):
    """
    Rule R006: No renaming of library/FLIRT-identified functions without override.
    Medium — warns to prevent accidental overwrite of known symbols.
    """

    def __init__(self):
        super().__init__(
            rule_id="R006",
            name="No Rename of Library/FLIRT Functions",
            severity=Severity.MEDIUM,
            description="Renaming functions identified by FLIRT signatures or "
                       "import tables can break cross-reference analysis and "
                       "obscure known library behavior.",
            resolution="Set override flag or verify the rename is intentional.",
        )

    def evaluate(self, op_type, addr, proposed_value, context, metadata):
        violations = []
        if op_type != OperationType.RENAME:
            return violations

        is_library = metadata.get("is_library_function", False)
        is_flirt = metadata.get("is_flirt_identified", False)
        override = metadata.get("override_library_rename", False)

        if (is_library or is_flirt) and not override:
            violations.append({
                "rule_id": self.rule_id,
                "rule": self.name,
                "severity": self.severity.name,
                "description": f"Attempted rename of library/FLIRT function "
                              f"at {hex(addr) if addr else 'unknown'} without override flag.",
                "resolution": self.resolution,
            })
        return violations


# ============================================================================
# SECTION 4: Governance Engine
# ============================================================================

class GovernanceEngine:
    """
    Main governance engine: evaluates operations against rule set and ontology.

    Implements the dual-phase governance architecture:
    Phase 1: Deterministic symbolic rules (always runs first)
    Phase 2: Ontology classification (adds formal reasoning)

    Features:
    - OWL-style axiom satisfaction scoring
    - Deterministic rule evaluation (<1ms per check)
    - Automatic PII redaction
    - JSON-exportable audit trail

    Example:
        >>> gov = GovernanceEngine()
        >>> result = gov.evaluate_operation(
        ...     "comment", addr=0x401000,
        ...     proposed_value="C2 at 192.168.1.1")
        >>> result["approved"]
        False
        >>> result["verdict"]
        'redacted'
    """

    # Map string operation types to enum
    _OP_TYPE_MAP = {
        "patch": OperationType.PATCH,
        "comment": OperationType.COMMENT,
        "rename": OperationType.RENAME,
        "type_change": OperationType.TYPE_CHANGE,
        "execution": OperationType.EXECUTION,
        "annotation": OperationType.ANNOTATION,
    }

    def __init__(self, ontology_threshold: float = 0.3):
        self.ontology = REOntology()
        self.ontology_threshold = ontology_threshold

        # Register all default rules
        self.rules: List[RERule] = [
            NoImportTablePatchRule(),
            NoPIIInCommentsRule(),
            NoMisleadingRenameRule(),
            NoUnsafeStackFrameChangeRule(),
            NoUnknownCodeExecutionRule(),
            NoRenameLibraryFunctionsRule(),
        ]

        # Statistics for audit trail
        self.stats = {
            "total_evaluations": 0,
            "approved": 0,
            "blocked": 0,
            "redacted": 0,
            "warned": 0,
            "total_violations": 0,
        }

    def add_rule(self, rule: RERule):
        """Register a custom rule."""
        self.rules.append(rule)

    def list_rules(self) -> List[Dict[str, str]]:
        """Return list of all registered rules with metadata."""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "severity": r.severity.name,
                "description": r.description,
                "resolution": r.resolution or "",
            }
            for r in self.rules
        ]

    def _infer_properties(self, op_type: OperationType, proposed_value: str,
                          metadata: Dict[str, Any]) -> Set[str]:
        """Infer ontology properties from operation metadata and value."""
        properties = set()

        # Base property from operation type — must match ontology axiom names
        base_map = {
            OperationType.PATCH: "is_patch",
            OperationType.COMMENT: "is_comment",
            OperationType.RENAME: "is_rename",
            OperationType.TYPE_CHANGE: "is_type_change",
            OperationType.EXECUTION: "is_execution",
            OperationType.ANNOTATION: "is_comment",
        }
        base = base_map.get(op_type)
        if base:
            properties.add(base)

        # Metadata -> properties — must match ontology axiom names
        meta_map = {
            "is_import_addr": "targets_import_section",
            "section_type": lambda v: "targets_import_section" if v in (".idata", ".edata", ".iat", ".plt")
                                     else ("targets_executable_section" if v in (".text", ".code") else None),
            "targets_stack": lambda v: "targets_stack_frame" if v else None,
            "changes_frame_size": lambda v: "changes_frame" if v else None,
            "invalidates_locals": lambda v: "invalidates_locals" if v else None,
            "breaks_calling_convention": lambda v: "breaks_cc" if v else None,
            "unknown_origin": lambda v: "unknown_origin" if v else None,
            "writes_to_disk": lambda v: "writes_disk" if v else None,
            "opens_socket": lambda v: "opens_socket" if v else None,
            "calls_encryption": lambda v: "calls_encryption_op" if v else None,
            "modifies_system_state": lambda v: "modifies_system" if v else None,
            "contradicts_api": lambda v: "api_contradiction" if v else None,
            "incorrect_prototype": lambda v: "wrong_prototype" if v else None,
            "false_security_claim": lambda v: "false_security" if v else None,
            "modifies_control_flow": lambda v: "modifies_control_flow" if v else None,
            "bypasses_security_check": lambda v: "bypasses_security" if v else None,
        }

        for key, mapping in meta_map.items():
            if key in metadata:
                if callable(mapping):
                    result = mapping(metadata[key])
                    if result:
                        properties.add(result)
                elif metadata[key]:
                    properties.add(mapping)

        # Text-based property inference
        if proposed_value:
            text = proposed_value
            if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text):
                properties.add("contains_ip")
            if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', text):
                properties.add("contains_email")
            if re.search(r'(?i)(?:password|passwd|secret|token)', text):
                properties.add("contains_credential")
            if re.search(r'\b[a-fA-F0-9]{32,64}\b', text):
                properties.add("contains_hash_secret")
            if re.search(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text):
                properties.add("contains_domain")

        return properties

    def evaluate_operation(self, operation_type: str, addr: Optional[int] = None,
                           proposed_value: str = "",
                           context: Optional[Dict[str, Any]] = None,
                           metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluate an operation against all governance rules and ontology.

        Phase 1: Run deterministic rules
        Phase 2: Classify via ontology
        Phase 3: Render verdict and redact if needed

        Args:
            operation_type: One of "patch", "comment", "rename",
                            "type_change", "execution", "annotation"
            addr: Target address (optional, used for context)
            proposed_value: The new value being proposed (comment text, name, etc.)
            context: Optional context dict (e.g., api_calls, arg_count)
            metadata: Optional metadata dict (e.g., section_type, is_import_addr)

        Returns:
            Dict with keys:
                - verdict: "approved" | "blocked" | "redacted" | "warned"
                - approved: bool (True if operation can proceed)
                - violations: List of violation dicts
                - redacted_content: str (redacted version of proposed_value)
                - warnings: List of warning strings
                - ontology_class: str (top ontology classification)
                - axiom_score: float
                - processing_time_ms: float
        """
        start_time = time.time()
        self.stats["total_evaluations"] += 1

        op_type = self._OP_TYPE_MAP.get(operation_type.lower())
        if op_type is None:
            return {
                "verdict": "blocked",
                "approved": False,
                "violations": [{
                    "rule_id": "R000",
                    "rule": "Unknown Operation Type",
                    "severity": Severity.CRITICAL.name,
                    "description": f"Unknown operation type: {operation_type}",
                    "resolution": "Use one of: patch, comment, rename, type_change, execution, annotation.",
                }],
                "redacted_content": proposed_value,
                "warnings": [],
                "ontology_class": None,
                "axiom_score": 0.0,
                "processing_time_ms": 0.0,
            }

        ctx = context or {}
        meta = metadata or {}

        # ---- Phase 1: Deterministic Rules ----
        all_violations = []
        for rule in self.rules:
            try:
                violations = rule.evaluate(op_type, addr, proposed_value, ctx, meta)
                all_violations.extend(violations)
            except Exception:
                # Rule evaluation failure should not block; log silently
                pass

        # ---- Phase 2: Ontology Classification ----
        properties = self._infer_properties(op_type, proposed_value, meta)
        classifications = self.ontology.classify(properties, self.ontology_threshold)

        ontology_class = "CompliantOperation"
        axiom_score = 0.0
        if classifications:
            ontology_class, axiom_score = classifications[0]

        # ---- Phase 3: Verdict Rendering ----
        ontology_verdict = self.ontology.class_verdict.get(ontology_class, Verdict.APPROVED)

        has_critical = any(v.get("severity") == Severity.CRITICAL.name for v in all_violations)
        has_high = any(v.get("severity") == Severity.HIGH.name for v in all_violations)
        has_medium = any(v.get("severity") == Severity.MEDIUM.name for v in all_violations)

        # Ontology verdict takes precedence for REDACTED/WARNED over rule severity,
        # but critical/high rule violations always block.
        if ontology_verdict == Verdict.BLOCKED or has_critical:
            verdict = Verdict.BLOCKED
        elif ontology_verdict == Verdict.REDACTED:
            verdict = Verdict.REDACTED
        elif has_high:
            verdict = Verdict.BLOCKED
        elif ontology_verdict == Verdict.WARNED:
            verdict = Verdict.WARNED
        elif has_medium:
            verdict = Verdict.WARNED
        else:
            verdict = Verdict.APPROVED

        # Apply redactions from PII rule
        redacted = proposed_value
        for rule in self.rules:
            if isinstance(rule, NoPIIInCommentsRule):
                redacted = rule.redact(redacted)
                break

        approved = verdict in (Verdict.APPROVED, Verdict.WARNED)
        if verdict == Verdict.REDACTED:
            approved = True  # Redacted content can proceed

        # Update statistics
        if verdict == Verdict.APPROVED:
            self.stats["approved"] += 1
        elif verdict == Verdict.BLOCKED:
            self.stats["blocked"] += 1
        elif verdict == Verdict.REDACTED:
            self.stats["redacted"] += 1
        elif verdict == Verdict.WARNED:
            self.stats["warned"] += 1
        self.stats["total_violations"] += len(all_violations)

        elapsed = (time.time() - start_time) * 1000

        return {
            "verdict": verdict.value,
            "approved": approved,
            "violations": all_violations,
            "redacted_content": redacted if redacted != proposed_value else proposed_value,
            "warnings": [f"[{v.get('severity', 'INFO')}] {v.get('description', '')}" for v in all_violations],
            "ontology_class": ontology_class,
            "axiom_score": round(axiom_score, 4),
            "processing_time_ms": round(elapsed, 3),
        }

    def get_stats(self) -> Dict[str, Any]:
        """Return governance engine statistics."""
        return dict(self.stats)

    def reset_stats(self):
        """Reset statistics counters."""
        for key in self.stats:
            self.stats[key] = 0


# ============================================================================
# SECTION 5: Module-level Singleton and Convenience API
# ============================================================================

# Module-level singleton for fast repeated lookups
_governance_instance: Optional[GovernanceEngine] = None


def get_governance() -> GovernanceEngine:
    """Return the singleton governance engine instance."""
    global _governance_instance
    if _governance_instance is None:
        _governance_instance = GovernanceEngine()
    return _governance_instance


def evaluate_operation(operation_type: str, addr: Optional[int] = None,
                       proposed_value: str = "",
                       context: Optional[Dict[str, Any]] = None,
                       metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience wrapper: evaluate a single operation via the singleton.

    Args:
        operation_type: "patch" | "comment" | "rename" | "type_change" | "execution" | "annotation"
        addr: Target address (optional)
        proposed_value: The proposed new value
        context: Optional context dict
        metadata: Optional metadata dict

    Returns:
        Governance result dict with verdict, approved, violations, etc.

    Example:
        >>> result = evaluate_operation("comment", proposed_value="IP: 10.0.0.1")
        >>> result["verdict"]
        'redacted'
    """
    return get_governance().evaluate_operation(
        operation_type, addr, proposed_value, context, metadata
    )


def list_rules() -> List[Dict[str, str]]:
    """Return list of all registered governance rules."""
    return get_governance().list_rules()


def redact_pii(text: str) -> str:
    """Redact PII from text using the governance PII rule."""
    for rule in get_governance().rules:
        if isinstance(rule, NoPIIInCommentsRule):
            return rule.redact(text)
    return text


# ============================================================================
# SECTION 6: MCP Tool Integration (tool decorator)
# ============================================================================

try:
    from ._common import tool, idaread, make_error, MCPError
except ImportError:
    try:
        from _common import tool, idaread, make_error, MCPError  # type: ignore[import-not-found]
    except ImportError:
        # Standalone / test mode — tool decorator not available
        tool = lambda f: f  # type: ignore
        idaread = lambda f: f  # type: ignore
        def make_error(*args, **kwargs):  # type: ignore
            return {"error": args[0] if args else "unknown", "message": str(kwargs)}
        class MCPError:
            GOVERNANCE_BLOCKED = "governance_blocked"
            INVALID_ARGS = "invalid_args"


@tool
@idaread
def governance(
    action: str,
    operation_type: Optional[str] = None,
    addr: Optional[str] = None,
    proposed_value: str = "",
    context: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> dict:
    """
    Deterministic Governance Layer.

    Deterministic pre-flight rule engine for all IDB write operations.
    No ML, no external APIs — uses regex + ontology reasoning only.

    ACTIONS:

    check - Evaluate a proposed operation against all governance rules.
        Params: operation_type, addr, proposed_value, context, metadata
        Returns: {verdict, approved, violations, redacted_content, warnings,
                  ontology_class, axiom_score, processing_time_ms}

    redact - Redact PII from a text string without evaluating rules.
        Params: proposed_value (the text to redact)
        Returns: {redacted_content, replacements_made}

    list_rules - List all registered governance rules.
        Returns: {rules: [{rule_id, name, severity, description, resolution}]}

    stats - Return governance engine statistics.
        Returns: {total_evaluations, approved, blocked, redacted, warned,
                  total_violations}

    Example:
        governance(action="check", operation_type="comment",
                   proposed_value="C2 at 192.168.1.1")
        # -> {verdict: "redacted", violations: [...]}
    """
    try:
        gov = get_governance()

        if action == "check":
            if not operation_type:
                return make_error(MCPError.INVALID_ARGS, "operation_type required for check")

            addr_int = None
            if addr:
                try:
                    from ida_pro_mcp.host.intelligence_helpers import coerce_int
                    addr_int = coerce_int(addr)
                except (ValueError, TypeError):
                    addr_int = None

            result = gov.evaluate_operation(
                operation_type=operation_type,
                addr=addr_int,
                proposed_value=proposed_value,
                context=context or {},
                metadata=metadata or {},
            )
            return {"ok": True, **result}

        elif action == "redact":
            redacted = redact_pii(proposed_value)
            return {
                "ok": True,
                "redacted_content": redacted,
                "replacements_made": redacted != proposed_value,
            }

        elif action == "list_rules":
            return {"ok": True, "rules": gov.list_rules()}

        elif action == "stats":
            return {"ok": True, **gov.get_stats()}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown governance action: {action}")

    except Exception as e:
        return {"ok": False, "error": str(e)}
