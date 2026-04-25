"""
LangGraph audit pipeline. 
This file wires all the individual nodes together into a directed graph
and exposes a single async function (run_audit) for the API to call.
Graph structure:
  START → validate ──(ok)──► llm_analysis → slither_analysis → merge_reports → END
                   └─(bad)─► abort → END
"""

import logging
from datetime import datetime, timezone
from typing import Literal

from langgraph.graph import StateGraph, START, END

from pipeline.state import AuditState
from pipeline.nodes.llm_node import run_llm_node
from pipeline.nodes.slither_node import run_slither_node
from pipeline.nodes.merge_node import run_merge_node

logger = logging.getLogger(__name__)


# Validate node ──────────────────────────────────────────────────────────────

def validate_node(state: AuditState) -> AuditState:
    """
    First node in the graph. Performs basic sanity checks on the contract code
    before we spend time and tokens calling the LLM or Slither.
 
    It doesn't raise exceptions, it just appends human-readable error messages
    to state["errors"]. The router function below decides what to do with them.
    """
     
    code = state.get("contract_code", "").strip()
    errors = list(state.get("errors", [])) # copy the list so we don't mutate shared state

    if not code:
        errors.append("Contract code is empty.")
    elif len(code) < 20:
        errors.append("Contract code is too short to be valid Solidity.")

    # None of the typical Solidity keywords are present -> then probably has the wrong file type
    elif "pragma solidity" not in code and "contract " not in code and "interface " not in code:
        errors.append(
            "Does not look like a valid Solidity file "
            "(missing 'pragma solidity' / 'contract' / 'interface')."
        )
    return {**state, "errors": errors}


def should_abort(state: AuditState) -> Literal["run", "abort"]:
    """
    Conditional router called after validate_node.
 
    LangGraph uses the return value to decide which edge to follow:
      "abort" -> go to abort_node (skip all analysis)
      "run"   -> go to llm_analysis (continue normally)
 
    We only abort if the contract code is completely empty. Other validation
    warnings are saved in errors[] but don't stop the pipeline as the LLM
    and Slither may still produce useful findings.
    """
    return "abort" if not state.get("contract_code", "").strip() else "run"


def abort_node(state: AuditState) -> AuditState:
    """
    Called when the input is so bad we can't run any analysis.
    Produces a minimal final_report so the API still returns a response in the correct format
    instead of an error. This way the frontend can handle it easier.
    """
    return {
        **state,
        "final_report": {
            "meta": {
                "contract_name": state.get("contract_name", "unknown"),
                "audit_timestamp": datetime.now(timezone.utc).isoformat(),
                "pipeline_errors": state.get("errors", []),
            },
            "overall_risk": "INFO",
            "summary": "Audit aborted: invalid input.",
            "statistics": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},  # All counts are zero because we found nothing
            "vulnerabilities": [],
        },
    }


# Build and compile graph ────────────────────────────────────────────────────

def _build_graph() -> StateGraph:
    """
    Constructs the LangGraph pipeline and compiles it into an executable object.
 
    Nodes are the processing steps and edges define the order they run in.
    Conditional edges decide which branch to go into based on runtime state (for example abort on bad input).
    """
    g = StateGraph(AuditState)

    g.add_node("validate", validate_node)
    g.add_node("abort", abort_node)
    g.add_node("llm_analysis", run_llm_node)
    g.add_node("slither_analysis", run_slither_node)
    g.add_node("merge_reports", run_merge_node)

    
    g.add_edge(START, "validate") # The graph always starts at "validate"
    g.add_conditional_edges("validate", should_abort, {"run": "llm_analysis", "abort": "abort"}) # After validation, we call should_abort() to decide which branch to take
    g.add_edge("abort", END) # The abort path goes straight to the end
    g.add_edge("llm_analysis", "slither_analysis")
    g.add_edge("slither_analysis", "merge_reports")
    g.add_edge("merge_reports", END)

    return g.compile() # compile() validates the graph structure and returns a runnable object



_pipeline = _build_graph()


# Public entry point ─────────────────────────────────────────────────────────

async def run_audit(contract_code: str, contract_name: str) -> dict:
    """
    The only function the API layer needs to call.
    It builds the initial state, feeds it into the compiled pipeline,
    waits for all nodes to finish, and then returns the final_report dict.
    """

    logger.info("═" * 60)
    logger.info("Audit started: %s", contract_name)

     # Seting up the starting state, where all intermediate fields start as None/empty
    initial: AuditState = {
        "contract_code": contract_code,
        "contract_name": contract_name,
        "llm_report": None, # filled in by run_llm_node
        "slither_report": None, # filled in by run_slither_node
        "final_report": None, # filled in by run_merge_node
        "errors": [],
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    result = await _pipeline.ainvoke(initial)

    logger.info("Audit finished: %s", contract_name)
    logger.info("═" * 60)

    # Extract and return just the final_report (the rest of the state is internal)
    return result.get("final_report", {})
