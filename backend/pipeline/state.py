"""
Shared LangGraph state.
LangGraph passes a single "state" dictionary between every node in the graph.
Each node receives the full state, does its work, and returns an updated copy.
"""

from typing import TypedDict, Optional


class AuditState(TypedDict):
    # ── Input ─────────────────────────────────────────────────────────────────
    contract_code: str
    contract_name: str

    # ── Supervisor / planning ─────────────────────────────────────────────────
    task_plan: list[str]
    contract_tags: list[str]

    # ── Detection phase ───────────────────────────────────────────────────────
    llm_detection_findings: list[dict]  # raw findings from detect node
    contract_info: Optional[dict]       # {solidity_version, contract_names, total_lines}
    detect_finished_at:   Optional[float]  # time.time() after detect LLM call completes
    critique_finished_at: Optional[float]  # time.time() after critique LLM call completes
    verify_finished_at:   Optional[float]  # time.time() after verify LLM call completes

    # ── Static analysis ───────────────────────────────────────────────────────
    slither_report: Optional[dict]      # normalised Slither output

    # ── Debate pipeline ───────────────────────────────────────────────────────
    # all_findings_to_review: deduplicated findings entering the debate (set by critique, read by verify)
    all_findings_to_review: list[dict]

    # confirmed_findings: auto-confirmed by both agents, or confirmed by tiebreaker
    confirmed_findings: list[dict]

    # uncertain_findings: agents disagreed → goes to tiebreaker
    uncertain_findings: list[dict]

    # debate_history: {finding_id: {critique_score, critique_verdict, critique_reasoning}}
    # set by critique, available for inspection/logging
    debate_history: dict

    # ── Final ─────────────────────────────────────────────────────────────────
    final_report: Optional[dict]

    # ── Metadata ──────────────────────────────────────────────────────────────
    errors: list[str]
    started_at: str
