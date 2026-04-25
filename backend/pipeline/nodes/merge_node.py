"""
This is the final node in the pipeline. It takes the findings from the
LLM and Slither, deduplicates them, and creates the structured JSON report
that is returned to the frontend.

Deduplication:
  - If LLM and Slither detect the same issue then we merge into one finding and tag it as: "BOTH"
  - The LLM provides semantic analysis like descriptions, exploitation scenarios, recommendations, etc
  - Slither provides precise, static analysis
  - Unmatched findings from each source are kept as they are
  - The final list is sorted from highest severity to lowest (CRITICAL → INFO)
"""

import json
import logging
from datetime import datetime, timezone

from pipeline.state import AuditState

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1} # Numeric index for each severity level, used for sorting and comparison. A higher number means more severity.

_DEFAULT_LLM_MODEL = "llama-3.3-70b-versatile" # Default model name used in the report metadata if the LLM didn't report which model it used


def _overall_risk(vulns: list[dict]) -> str:
    """Determines the single highest severity found across all vulnerabilities and defaults to INFO if no vulnerabilities were found"""
    if not vulns:
        return "INFO"
    return max(
        (v.get("severity", "INFO") for v in vulns),
        key=lambda s: SEVERITY_RANK.get(s, 1),
    )


def _stats(vulns: list[dict]) -> dict:
    """
    Counts the findings by severity level and returns a summary dict that is used to populate the statistics panel in the frontend dashboard.
    """
    out = {"total": len(vulns), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        key = v.get("severity", "INFO").lower()
        out[key] = out.get(key, 0) + 1
    return out


def _are_same(a: dict, b: dict) -> bool:
    """Decide if two findings (one from the LLM and the other from Slither) belong to 
    the same vulnerability. We consider them duplicates if they share the same SWC ID or >40% category overlap."""
    swc_a, swc_b = a.get("swc_id"), b.get("swc_id")
    if swc_a and swc_b and swc_a == swc_b:
        return True
    
    # Fall back to comparing category keywords (for example "reentrancy eth" vs "reentrancy no eth")
    cat_a = set(a.get("category", "").lower().split())
    cat_b = set(b.get("category", "").lower().split())
    if cat_a and cat_b:
        overlap = len(cat_a & cat_b) / max(len(cat_a), len(cat_b))  # Jaccard overlap: shared words / total unique words
        return overlap > 0.4 # more than 40% keyword overlap -> we treat as duplicate
    return False


def _merge(llm_v: dict, sli_v: dict) -> dict:
    """
    Combining an LLM finding and its matching Slither finding into one entry.
    The merge process:
      - Start with the LLM finding as the base
      - Override with Slither's line numbers if it has them, as it's more precise
      - Take the more severe of the two severity ratings
      - Tag the result as coming from "BOTH" sources
    """
    
    merged = {**llm_v, "source": "BOTH", "slither_check": sli_v.get("slither_check")} # Starting from the LLM finding and add Slither-specific fields

    # We prefer Slither line numbers because they are exact. If none, then we fall back to LLM provided ones
    if sli_v.get("line_numbers"):
        merged["line_numbers"] = sli_v["line_numbers"]
    elif not merged.get("line_numbers"):
        merged["line_numbers"] = []

    # Take the more severe rating
    if (
        SEVERITY_RANK.get(sli_v.get("severity", "INFO"), 1)
        > SEVERITY_RANK.get(llm_v.get("severity", "INFO"), 1)
    ):
        merged["severity"] = sli_v["severity"]

    return merged


def run_merge_node(state: AuditState) -> AuditState:
    """LangGraph node that merges LLM and Slither findings and builds the final report."""
    logger.info("[LOG] Merge node")
    errors = list(state.get("errors", []))

    # Extract vulnerability lists from previous nodes 
    llm_analysis   = (state.get("llm_report") or {}).get("llm_analysis", {})
    llm_vulns      = llm_analysis.get("vulnerabilities", [])
    slither_vulns  = (state.get("slither_report") or {}).get("vulnerabilities", [])

    merged: list[dict] = []  # the final combined list we'll build up
    slither_used: set[int] = set() # track which Slither findings have already been merged

     # Step 1: Match each LLM finding against Slither findings
    for llm_v in llm_vulns:
        llm_v = {**llm_v, "source": "LLM"}

        if "line_numbers" not in llm_v:
            llm_v["line_numbers"] = []

        matched = False
        for i, sli_v in enumerate(slither_vulns):
            if i not in slither_used and _are_same(llm_v, sli_v):
                merged.append(_merge(llm_v, sli_v))
                slither_used.add(i)
                matched = True
                break
        if not matched:
            merged.append(llm_v)

    # Step 2: Append findings found only by Slither
    for i, sli_v in enumerate(slither_vulns):
        if i not in slither_used:
            merged.append({**sli_v, "source": "SLITHER"})

    # Step 3: Sort by severity
    merged.sort(
        key=lambda v: SEVERITY_RANK.get(v.get("severity", "INFO"), 1),
        reverse=True,
    )
    for i, v in enumerate(merged):
        v["id"] = f"VULN-{i + 1:03d}"

    stats = _stats(merged)
    logger.info(
        "  [SUCCESSFUL LOG] Merge done — %d findings (CRIT:%d HIGH:%d MED:%d LOW:%d INFO:%d)",
        stats["total"],
        stats.get("critical", 0),
        stats.get("high", 0),
        stats.get("medium", 0),
        stats.get("low", 0),
        stats.get("info", 0),
    )

    # Step 4: Build the final report sent to the frontend

    final_report = {
        "meta": {
            "contract_name":    state["contract_name"],
            "audit_timestamp":  datetime.now(timezone.utc).isoformat(),
            "started_at":       state.get("started_at", ""),
            "llm_model":        llm_analysis.get("model_used", _DEFAULT_LLM_MODEL),
            "slither_available": (state.get("slither_report") or {}).get("success", False),
            "pipeline_errors":  errors,
        },
        "overall_risk":  _overall_risk(merged),
        "summary":       llm_analysis.get("summary", "Audit completed."),
        "contract_info": {

            "solidity_version": llm_analysis.get("contract_info", {}).get("solidity_version", ""),
            "contract_names":   llm_analysis.get("contract_info", {}).get("contract_names", []),
            "total_lines":      llm_analysis.get("contract_info", {}).get("total_lines", 0),
        },
        "statistics":       stats,
        "vulnerabilities":  merged,
    }

    # Final report (debug log)
    logger.info("━" * 50)
    logger.info("FINAL REPORT")
    logger.info("━" * 50)
    logger.info(json.dumps(final_report, indent=2, ensure_ascii=False))
    logger.info("━" * 50)

    return {**state, "final_report": final_report, "errors": errors}