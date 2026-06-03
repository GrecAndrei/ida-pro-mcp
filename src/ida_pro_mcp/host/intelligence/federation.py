from __future__ import annotations

import os
import sqlite3
import json
from typing import Any, Dict, List, Optional


class FederationBridge:
    """Federation Bridge for peer-to-peer blackboard and Q-weights synchronization.
    
    Resolves conflicts using metadata version numbers, confidence metrics, and timestamps.
    """

    def __init__(self, local_bb_path: str):
        self.local_bb_path = local_bb_path

    def federate_blackboards(self, remote_paths: List[str]) -> Dict[str, int]:
        """Merge findings from remote Blackboard databases into the local one."""
        stats = {"inserted": 0, "updated": 0, "skipped": 0}
        if not self.local_bb_path:
            return stats

        # Ensure local database exists and is initialized
        if not os.path.exists(self.local_bb_path):
            try:
                from ..blackboard_store import BlackboardStore
                store = BlackboardStore(self.local_bb_path)
            except Exception:
                pass

        try:
            local_conn = sqlite3.connect(self.local_bb_path)
            local_cur = local_conn.cursor()
        except Exception:
            return stats

        for path in remote_paths:
            if not os.path.exists(path) or os.path.abspath(path) == os.path.abspath(self.local_bb_path):
                continue
            try:
                remote_conn = sqlite3.connect(path)
                remote_cur = remote_conn.cursor()
                
                # Fetch blackboard entries
                remote_cur.execute(
                    """
                    SELECT id, category, title, content, addr, addr_end, tags, confidence,
                           created_at, updated_at, q_value, source, evidence, source_type, version,
                           entropy, xref_count, calibrated, resolved, contradicted, contradiction_reason
                    FROM blackboard
                    """
                )
                rows = remote_cur.fetchall()
                for r in rows:
                    (bb_id, category, title, content, addr, addr_end, tags, confidence,
                     created_at, updated_at, q_value, source, evidence, source_type, version,
                     entropy, xref_count, calibrated, resolved, contradicted, contradiction_reason) = r

                    local_cur.execute("SELECT version, confidence, updated_at FROM blackboard WHERE id = ?", (bb_id,))
                    local_row = local_cur.fetchone()
                    if not local_row:
                        # Direct Insert
                        local_cur.execute(
                            """
                            INSERT INTO blackboard
                            (id, category, title, content, addr, addr_end, tags, confidence,
                             created_at, updated_at, q_value, source, evidence, source_type, version,
                             entropy, xref_count, calibrated, resolved, contradicted, contradiction_reason)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (bb_id, category, title, content, addr, addr_end, tags, confidence,
                             created_at, updated_at, q_value, source, evidence, source_type, version,
                             entropy, xref_count, calibrated, resolved, contradicted, contradiction_reason)
                        )
                        stats["inserted"] += 1
                    else:
                        local_version, local_confidence, local_updated = local_row
                        # Policy rules: newer version wins, higher confidence wins, or newer update timestamp wins
                        if (version > local_version or 
                            (version == local_version and confidence > local_confidence) or
                            (version == local_version and confidence == local_confidence and updated_at > local_updated)):
                            
                            local_cur.execute(
                                """
                                UPDATE blackboard SET
                                category=?, title=?, content=?, addr=?, addr_end=?, tags=?, confidence=?,
                                updated_at=?, q_value=?, source=?, evidence=?, source_type=?, version=?,
                                entropy=?, xref_count=?, calibrated=?, resolved=?, contradicted=?, contradiction_reason=?
                                WHERE id=?
                                """,
                                (category, title, content, addr, addr_end, tags, confidence,
                                 updated_at, q_value, source, evidence, source_type, version,
                                 entropy, xref_count, calibrated, resolved, contradicted, contradiction_reason, bb_id)
                            )
                            stats["updated"] += 1
                        else:
                            stats["skipped"] += 1
                remote_conn.close()
            except Exception:
                pass

        local_conn.commit()
        local_conn.close()
        return stats

    def federate_preferences(self, remote_capsule_paths: List[str]) -> Dict[str, int]:
        """Merge RL preferences/Q-triplets from other sideband files into local capsule."""
        stats = {"merged_triplets": 0, "merged_suggestions": 0}
        local_cap_path = self.local_bb_path.replace(".blackboard.db", ".sideband")
        if not os.path.exists(local_cap_path):
            # Try to find a sibling sideband
            local_dir = os.path.dirname(self.local_bb_path)
            local_cap_path = os.path.join(local_dir, "capsule.sideband")

        try:
            from ...capsule import CapsuleStore
            with CapsuleStore.open(local_cap_path) as local_cap:
                for path in remote_capsule_paths:
                    if not os.path.exists(path) or os.path.abspath(path) == os.path.abspath(local_cap_path):
                        continue
                    try:
                        with CapsuleStore.open(path) as other_cap:
                            res = local_cap.merge_capsule_preferences(other_cap)
                            stats["merged_triplets"] += res.get("merged_triplets", 0)
                            stats["merged_suggestions"] += res.get("merged_suggestions", 0)
                    except Exception:
                        pass
        except Exception:
            pass
        return stats
