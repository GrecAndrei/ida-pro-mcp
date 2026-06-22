"""Vulnerability Reasoner using Bayesian Noisy-OR probability networks."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from ida_pro_mcp.capsule.store import CapsuleStore

# Define vulnerability classes, supporting behaviors, and link probabilities (weights)
VULNERABILITY_PROFILES = {
    "Memory Corruption": {
        "behaviors": {
            "buffer_overflow": 0.85,
            "use_after_free": 0.80,
            "heap_spray": 0.60,
            "memory_manipulation": 0.40,
            "rop_gadget": 0.30,
        },
        "background_leak": 0.05,
        "description": "Evidence suggests memory corruption hazards, stack/heap manipulation, or ROP gadget preparation."
    },
    "Improper Input Validation": {
        "behaviors": {
            "format_string_vuln": 0.90,
            "path_traversal": 0.80,
            "integer_overflow": 0.75,
            "buffer_overflow": 0.50,
        },
        "background_leak": 0.05,
        "description": "Evidence suggests format string bugs, integer overflows/underflows, or path traversal opportunities."
    },
    "Evasion & Anti-Analysis": {
        "behaviors": {
            "anti_debug": 0.85,
            "anti_vm": 0.85,
            "evasion": 0.70,
            "string_decrypt": 0.60,
        },
        "background_leak": 0.02,
        "description": "Evidence suggests debugger detection, hypervisor checks, data evasion, or rolling key string decryption."
    },
    "Privileged Command Execution": {
        "behaviors": {
            "process_injection": 0.85,
            "privilege_escalation": 0.80,
            "c2_communication": 0.75,
        },
        "background_leak": 0.01,
        "description": "Evidence suggests local process injection, privilege adjustments, or command-and-control beaconing."
    },
    "Cryptographic Activity": {
        "behaviors": {
            "crypto_symmetric": 0.90,
            "crypto_hash": 0.75,
        },
        "background_leak": 0.02,
        "description": "Evidence suggests block cipher structures, rounds, or hashing functions are implemented."
    }
}

class VulnerabilityReasoner:
    """
    Reasoning engine using Noisy-OR gates to aggregate low-level evidence cards
    and behavior hits into joint-confidence high-level vulnerability profiles.
    """

    def __init__(self, profiles: Optional[Dict[str, Any]] = None):
        self.profiles = profiles or VULNERABILITY_PROFILES

    def reason(self, behavior_hits: List[Dict[str, Any]], evidence_cards: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Aggregate low-level findings and compute joint confidence scores
        using Noisy-OR formula: P(V) = 1 - (1 - leak) * Product(1 - w_i * p_i)
        """
        evidence_cards = evidence_cards or []
        
        # Consolidate behavior/evidence probabilities by key
        indicators: Dict[str, float] = {}
        sources: Dict[str, List[Dict[str, Any]]] = {}

        # 1. Process behavior hits (e.g. from behavior_hits table)
        for hit in behavior_hits:
            bh = str(hit.get("behavior") or "").strip()
            conf = float(hit.get("confidence") or 0.0)
            if bh:
                if conf > indicators.get(bh, 0.0):
                    indicators[bh] = conf
                sources.setdefault(bh, []).append({
                    "type": "behavior_hit",
                    "id": hit.get("id"),
                    "confidence": conf,
                    "item_id": hit.get("item_id"),
                })

        # 2. Process existing evidence cards (exclude synthesized vulnerabilities to avoid feedback loop)
        for card in evidence_cards:
            claim_type = str(card.get("claim_type") or "").strip()
            if claim_type == "synthesized_vulnerability":
                continue
            claim = str(card.get("claim") or "").strip()
            conf = float(card.get("confidence") or 0.0)
            
            # Map common claim formats to corresponding indicator name
            indicator_key = claim_type
            if claim in indicators or claim_type in indicators:
                indicator_key = claim if claim in indicators else claim_type
            
            if indicator_key:
                if conf > indicators.get(indicator_key, 0.0):
                    indicators[indicator_key] = conf
                sources.setdefault(indicator_key, []).append({
                    "type": "evidence_card",
                    "id": card.get("id"),
                    "claim": claim,
                    "confidence": conf,
                })

        synthesized: List[Dict[str, Any]] = []

        # 3. Apply Noisy-OR logic for each vulnerability profile
        for vuln_name, rules in self.profiles.items():
            behaviors = rules.get("behaviors", {})
            leak = float(rules.get("background_leak", 0.0))
            
            # Find which indicator signals are active for this vulnerability profile
            active_evidence: List[Dict[str, Any]] = []
            product_term = 1.0
            
            for indicator_name, weight in behaviors.items():
                if indicator_name in indicators:
                    p = indicators[indicator_name]
                    product_term *= (1.0 - weight * p)
                    active_evidence.append({
                        "indicator": indicator_name,
                        "weight": weight,
                        "observed_confidence": p,
                        "sources": sources.get(indicator_name, [])
                    })
            
            # Calculate joint confidence
            joint_conf = 1.0 - (1.0 - leak) * product_term
            
            # If joint confidence exceeds a minimal threshold and we have active evidence, trigger it
            if active_evidence and joint_conf > leak + 0.05:
                synthesized.append({
                    "claim": vuln_name,
                    "claim_type": "synthesized_vulnerability",
                    "confidence": round(joint_conf, 4),
                    "evidence": active_evidence,
                    "description": rules.get("description", ""),
                    "metadata": {
                        "leak": leak,
                        "generator": "VulnerabilityReasoner",
                    }
                })
                
        return synthesized

    def reason_on_capsule(self, capsule: CapsuleStore) -> List[Dict[str, Any]]:
        """
        Query database of an initialized CapsuleStore, perform Noisy-OR calculations,
        save the results back into the capsule, and clean up historical runs.
        """
        capsule._assert_initialized()
        
        # Load behavior hits
        behavior_hits: List[Dict[str, Any]] = []
        for row in capsule.conn.execute("SELECT * FROM behavior_hits").fetchall():
            behavior_hits.append(dict(row))
            
        # Load evidence cards
        evidence_cards: List[Dict[str, Any]] = []
        for row in capsule.conn.execute("SELECT * FROM evidence_cards").fetchall():
            evidence_cards.append(dict(row))
            
        # Execute reasoning
        hypotheses = self.reason(behavior_hits, evidence_cards)
        
        # Transaction context: clean up older synthesized cards and insert new ones
        capsule.conn.execute("DELETE FROM evidence_cards WHERE claim_type='synthesized_vulnerability'")
        
        # Insert new synthesized cards
        for hyp in hypotheses:
            capsule.add_evidence_card(
                claim=hyp["claim"],
                claim_type=hyp["claim_type"],
                confidence=hyp["confidence"],
                evidence=hyp["evidence"],
                source_refs=[],
                metadata={
                    "description": hyp["description"],
                    **hyp["metadata"]
                }
            )
            
        capsule.conn.commit()
        return hypotheses
