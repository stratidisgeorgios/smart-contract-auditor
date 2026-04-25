"""
Shared LangGraph state. 
LangGraph passes a single "state" dictionary between every node in the graph,
that every node can read and write. 
Each node receives the full state, does its work, and returns an updated copy.
"""

from typing import TypedDict, Optional


class AuditState(TypedDict):
    # Input
    contract_code: str # The raw Solidity source code as a plain string
    contract_name: str # The original filename (used in reports and logs)

    # Intermediate outputs (filled in by individual nodes)
    llm_report: Optional[dict]  # The structured JSON report produced by the LLM node.
    slither_report: Optional[dict]  # The structured JSON report produced by the Slither static-analysis node.

    # Final (filled in by the merge node at the end)
    final_report: Optional[dict]

    # Metadata

    # A list of non-fatal error messages collected during the run.
    # Nodes append to this list instead of crashing, so we can still return
    # a partial report even if one step fails.
    errors: list[str]

    # ISO-8601 timestamp of when the audit was kicked off. Used in the report metadata
    started_at: str
