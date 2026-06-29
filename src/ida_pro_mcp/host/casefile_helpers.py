from __future__ import annotations

from typing import Any


def build_risk_summary(findings: list[dict[str, Any]], hypotheses: list[dict[str, Any]], ai_records: list[dict[str, Any]]) -> dict[str, Any]:
    high_findings = 0
    low_evidence = 0
    for f in findings:
        tags = [str(x).lower() for x in (f.get("tags") or [])]
        title = str(f.get("title") or "").lower()
        if any(t in {"dangerous", "injection", "privesc", "persistence", "anti_debug"} for t in tags) or any(
            x in title for x in ("injection", "remote thread", "privilege", "persistence", "anti-debug")
        ):
            high_findings += 1
        if len(f.get("evidence") or []) < 2:
            low_evidence += 1

    unresolved = sum(1 for h in hypotheses if str(h.get("status") or "") not in ("supported", "refuted"))
    unreviewed_ai = sum(1 for r in ai_records if not r.get("approved"))
    debt_index = unresolved * 2 + low_evidence + unreviewed_ai
    risk_level = "high" if debt_index >= 25 or high_findings >= 10 else ("medium" if debt_index >= 10 or high_findings >= 3 else "low")

    return {
        "risk_level": risk_level,
        "high_risk_findings": high_findings,
        "unresolved_hypotheses": unresolved,
        "low_evidence_findings": low_evidence,
        "unreviewed_ai_annotations": unreviewed_ai,
        "knowledge_debt_index": debt_index,
    }


def build_chain_of_custody(sessions: list[dict[str, Any]], replay_steps: list[dict[str, Any]], ai_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for s in sessions:
        events.append(
            {
                "type": "session",
                "timestamp": s.get("created_at") or s.get("updated_at"),
                "actor": "analyst",
                "detail": f"session:{s.get('session_id')} binary={s.get('binary_path')}",
            }
        )
    for st in replay_steps[-1000:]:
        events.append(
            {
                "type": "tool_step",
                "timestamp": st.get("timestamp"),
                "actor": "automation",
                "detail": f"{st.get('tool')}:{st.get('action_name')}",
            }
        )
    for r in ai_records[-1000:]:
        events.append(
            {
                "type": "ai_review",
                "timestamp": r.get("timestamp"),
                "actor": r.get("reviewer") or "reviewer",
                "detail": f"{r.get('target')} approved={bool(r.get('approved'))}",
            }
        )
    events.sort(key=lambda x: str(x.get("timestamp") or ""))
    return events[-2000:]


def to_markdown_casefile(payload: dict[str, Any]) -> str:
    summ = payload.get("summary") or {}
    risk = payload.get("risk_summary") or {}
    lines = [
        "# Casefile Export",
        "",
        f"Generated: {payload.get('generated_at')}",
        "",
        "## Summary",
        f"- Sessions: {summ.get('sessions', 0)}",
        f"- Findings: {summ.get('findings', 0)}",
        f"- Hypotheses: {summ.get('hypotheses', 0)}",
        f"- AI Records: {summ.get('ai_records', 0)}",
        "",
        "## Risk",
        f"- Level: {risk.get('risk_level', 'unknown')}",
        f"- High-risk findings: {risk.get('high_risk_findings', 0)}",
        f"- Knowledge debt index: {risk.get('knowledge_debt_index', 0)}",
        "",
        "## Integrity",
        f"- SHA256: {(payload.get('integrity') or {}).get('sha256', '')}",
    ]
    return "\n".join(lines) + "\n"
