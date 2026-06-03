from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


class AgentMacroCrystallizer:
    """
    Sequence Miner & Macro Synthesizer for self-improving agent crystallization.
    Analyzes session command trajectories and registers high-reward sequences as L3 skills.
    """

    @staticmethod
    def calculate_step_reward(entry: Dict[str, Any]) -> float:
        """Assigns a numeric reward score based on the outcome of a logged action."""
        tool = str(entry.get("tool") or "").strip().lower()
        action = str(entry.get("action") or "").strip().lower()
        result = str(entry.get("result") or "").strip()

        # 1. High value validation outcomes (Hypothesis confirmation, Crystallization)
        if tool == "session":
            if "confirm" in action:
                return 10.0
            if "crystallize" in action:
                return 8.0
            if "note" in action or "append" in action:
                return 3.0

        # 2. Knowledge retention & evidence accumulation (Blackboard writes)
        if tool == "blackboard":
            if action in ("write", "add_evidence", "calibrate", "add_system", "add_struct"):
                return 5.0

        # 3. Successful queries/findings
        reward = 0.5
        if result:
            # Check for standard error objects or failure signals
            if "error" in result.lower() or "false" in result.lower():
                reward = 0.1
            elif "ok" in result.lower() or "true" in result.lower() or len(result) > 20:
                reward = 1.5

        return reward

    @classmethod
    def mine_sequences(
        cls, activity_log: List[Dict[str, Any]], min_support: int = 2
    ) -> List[Dict[str, Any]]:
        """
        Identifies repeating subsequences of length 2 to 4 in the activity log.
        Computes frequency, rewards, and ranks them by overall utility.
        """
        if not activity_log or len(activity_log) < 2:
            return []

        # Convert activity log into a sequence of tool.action representations
        steps: List[str] = []
        rewards: List[float] = []
        for entry in activity_log:
            tool = str(entry.get("tool") or "").strip()
            action = str(entry.get("action") or "").strip()
            if tool and action:
                steps.append(f"{tool}.{action}")
                rewards.append(cls.calculate_step_reward(entry))

        n = len(steps)
        sequence_stats: Dict[Tuple[str, ...], Dict[str, Any]] = {}

        # Scan for subsequence lengths from 2 to 4
        for length in (2, 3, 4):
            for i in range(n - length + 1):
                subseq = tuple(steps[i : i + length])
                subseq_rewards = rewards[i : i + length]

                if subseq not in sequence_stats:
                    sequence_stats[subseq] = {
                        "sequence": list(subseq),
                        "count": 0,
                        "total_reward": 0.0,
                    }

                sequence_stats[subseq]["count"] += 1
                sequence_stats[subseq]["total_reward"] += sum(subseq_rewards)

        # Filter by minimum frequency (support) and compute final score
        ranked_sequences: List[Dict[str, Any]] = []
        for subseq, stats in sequence_stats.items():
            if stats["count"] >= min_support:
                # Score is frequency weighted by average sequence reward
                avg_reward = stats["total_reward"] / stats["count"]
                stats["score"] = round(stats["count"] * avg_reward, 3)
                ranked_sequences.append(stats)

        # Sort by score descending
        ranked_sequences.sort(key=lambda x: x["score"], reverse=True)
        return ranked_sequences

    @staticmethod
    def synthesize_macro(sequence: List[str]) -> Dict[str, Any]:
        """
        Generates a clean skill macro (name, description, and steps)
        from a mined sequence of actions.
        """
        if not sequence:
            return {}

        # Deconstruct components to auto-generate readable descriptions
        tools = []
        for step in sequence:
            parts = step.split(".", 1)
            t = parts[0].capitalize()
            if t not in tools:
                tools.append(t)

        tool_flow = " -> ".join(tools)
        step_flow = " -> ".join(sequence)

        # Auto-generate dynamic names and descriptions based on sequence length/flow
        name = f"Mined Macro: {' & '.join(tools)}"
        description = f"Automatically crystallized workflow sequence: {step_flow}"

        return {
            "name": name,
            "description": description,
            "steps": list(sequence),
            "tags": ["auto-crystallized", "mined-sequence"],
            "memrl_reward": 0.5,
        }

    def crystallize_from_log(
        self, session_mgr: Any, sid: str, min_support: int = 2
    ) -> Dict[str, Any]:
        """
        Mines the session's activity log and registers the highest ranking sequence
        as a crystallized L3 skill.
        """
        # Load the skills/activity data
        with session_mgr._lock:
            session = session_mgr.sessions.get(sid)
            if not session:
                return {"ok": False, "error": "session_not_found"}

            skills_data = session_mgr._load_skills(sid)
            activity_log = skills_data.get("activity_log", [])

        if not activity_log:
            return {
                "ok": False,
                "message": "Activity log is empty. Execute some tool actions first.",
            }

        # 1. Mine sequences
        ranked = self.mine_sequences(activity_log, min_support=min_support)
        if not ranked:
            return {
                "ok": False,
                "message": f"No repeating sequences found with support >= {min_support}.",
            }

        # 2. Synthesize the top ranked macro
        top_seq = ranked[0]["sequence"]
        macro = self.synthesize_macro(top_seq)

        # 3. Save as crystallized L3 skill
        res = session_mgr.crystallize_skill(
            sid,
            name=macro["name"],
            description=macro["description"],
            steps=macro["steps"],
            tags=macro["tags"],
        )

        if res.get("ok"):
            return {
                "ok": True,
                "skill_id": res["skill_id"],
                "score": ranked[0]["score"],
                "frequency": ranked[0]["count"],
                "sequence": top_seq,
                "skill": res["skill"],
            }
        return res
