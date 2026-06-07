"""
LangGraph audit pipeline — parallel-scoring debate architecture.

Graph structure (linear — no loops):

  START → validate → supervisor_plan → llm_detect → slither_analysis
        ↓ abort                                           ↓
      abort → END                                     critique
                                                   (scores all findings independently,
                                                    stores in all_findings_to_review)
                                                          ↓
                                                       verify
                                                   (scores independently, then compares:
                                                    both confirm → confirmed_findings
                                                    both reject  → dropped
                                                    disagree     → uncertain_findings)
                                                          ↓
                                                     tiebreaker
                                                   (arbitrates uncertain_findings,
                                                    appends to confirmed_findings)
                                                          ↓
                                                     merge → END
"""

import logging
from datetime import datetime, timezone
from typing import Literal

from langgraph.graph import StateGraph, START, END

from pipeline.state import AuditState
from pipeline.nodes.llm_node import run_llm_detect_node
from pipeline.nodes.slither_node import run_slither_node
from pipeline.nodes.critique_node import run_critique_node
from pipeline.nodes.verify_node import run_verify_node
from pipeline.nodes.tiebreaker_node import run_tiebreaker_node
from pipeline.nodes.merge_node import run_merge_node

logger = logging.getLogger(__name__)


# ── Validate node ─────────────────────────────────────────────────────────────

def validate_node(state: AuditState) -> AuditState:
    code   = state.get("contract_code", "").strip()
    errors = list(state.get("errors", []))
    if not code:
        errors.append("Contract code is empty.")
    elif len(code) < 20:
        errors.append("Contract code is too short to be valid Solidity.")
    elif (
        "pragma solidity" not in code
        and "contract " not in code
        and "interface " not in code
    ):
        errors.append(
            "Does not look like a valid Solidity file "
            "(missing 'pragma solidity' / 'contract' / 'interface')."
        )
    return {**state, "errors": errors}


def should_abort(state: AuditState) -> Literal["run", "abort"]:
    return "abort" if not state.get("contract_code", "").strip() else "run"


def abort_node(state: AuditState) -> AuditState:
    return {
        **state,
        "final_report": {
            "meta": {
                "contract_name":   state.get("contract_name", "unknown"),
                "audit_timestamp": datetime.now(timezone.utc).isoformat(),
                "pipeline_errors": state.get("errors", []),
            },
            "overall_risk":    "INFO",
            "summary":         "Audit aborted: invalid input.",
            "statistics":      {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "vulnerabilities": [],
        },
    }


# ── Supervisor ────────────────────────────────────────────────────────────────

_TAG_PATTERNS: dict[str, list[str]] = {
    "defi":  ["swap", "liquidity", "flashloan", "flash_loan", "uniswap", "pancake",
               "price", "amm", "vault", "yield", "borrow", "lend"],
    "erc20": ["IERC20", "ERC20", "balanceOf", "transferFrom", "allowance", "approve"],
    "proxy": ["delegatecall", "upgradeable", "Proxy", "initialize", "implementation"],
    "nft":   ["ERC721", "ERC1155", "tokenURI", "ownerOf", "safeTransferFrom"],
    "dao":   ["vote", "proposal", "governance", "quorum", "timelock"],
}


def supervisor_plan_node(state: AuditState) -> AuditState:
    tags = [tag for tag, kws in _TAG_PATTERNS.items()
            if any(kw in state.get("contract_code", "") for kw in kws)]
    plan = "detect → slither → critique ‖ verify (independent) → tiebreaker → merge"
    logger.info("[Supervisor] Contract tags: %s", tags or ["generic"])
    logger.info("[Supervisor] Plan: %s", plan)
    return {
        **state,
        "task_plan":              [plan],
        "contract_tags":          tags,
        "llm_detection_findings": [],
        "all_findings_to_review": [],
        "contract_info":          None,
        "detect_finished_at":     None,
        "critique_finished_at":   None,
        "verify_finished_at":     None,
        "confirmed_findings":     [],
        "uncertain_findings":     [],
        "debate_history":         {},
    }


# ── Graph construction ────────────────────────────────────────────────────────

def _build_graph() -> StateGraph:
    g = StateGraph(AuditState)

    g.add_node("validate",         validate_node)
    g.add_node("abort",            abort_node)
    g.add_node("supervisor_plan",  supervisor_plan_node)
    g.add_node("llm_detect",       run_llm_detect_node)
    g.add_node("slither_analysis", run_slither_node)
    g.add_node("critique",         run_critique_node)
    g.add_node("verify",           run_verify_node)
    g.add_node("tiebreaker",       run_tiebreaker_node)
    g.add_node("merge_reports",    run_merge_node)

    g.add_edge(START, "validate")
    g.add_conditional_edges("validate", should_abort, {"run": "supervisor_plan", "abort": "abort"})
    g.add_edge("abort",           END)

    g.add_edge("supervisor_plan",  "llm_detect")
    g.add_edge("llm_detect",       "slither_analysis")
    g.add_edge("slither_analysis", "critique")
    g.add_edge("critique",         "verify")
    g.add_edge("verify",           "tiebreaker")
    g.add_edge("tiebreaker",       "merge_reports")
    g.add_edge("merge_reports",    END)

    return g.compile()


_pipeline = _build_graph()


# ── Public entry point ────────────────────────────────────────────────────────

async def run_audit(contract_code: str, contract_name: str) -> dict:
    logger.info("═" * 60)
    logger.info("Audit started: %s", contract_name)

    initial: AuditState = {
        "contract_code":          contract_code,
        "contract_name":          contract_name,
        "task_plan":              [],
        "contract_tags":          [],
        "llm_detection_findings": [],
        "all_findings_to_review": [],
        "contract_info":          None,
        "detect_finished_at":     None,
        "critique_finished_at":   None,
        "verify_finished_at":     None,
        "slither_report":         None,
        "confirmed_findings":     [],
        "uncertain_findings":     [],
        "debate_history":         {},
        "final_report":           None,
        "errors":                 [],
        "started_at":             datetime.now(timezone.utc).isoformat(),
    }

    result = await _pipeline.ainvoke(initial)
    logger.info("Audit finished: %s", contract_name)
    logger.info("═" * 60)

    final = result.get("final_report")
    if not final:
        return {"error": "Pipeline produced no final report", "errors": result.get("errors", [])}
    return final
