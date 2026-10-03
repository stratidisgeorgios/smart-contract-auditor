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

_DEFAULT_LLM_MODEL = "openai/gpt-oss-120b"


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

    # Line number strategy —> we prefer LLM lines over Slither lines. Slither often reports entire function bodies or includes called-function lines, producing wide ranges like [93..119] that miss the GT.
    # The LLM resolver gives targeted lines. Only fall back to Slither if LLM has none.
    llm_lines = llm_v.get("line_numbers", [])
    sli_lines = sli_v.get("line_numbers", [])
    if llm_lines:
        merged["line_numbers"] = llm_lines # trust the resolver
    elif sli_lines:
        merged["line_numbers"] = sli_lines # fallback: at least Slither has something
    else:
        merged["line_numbers"] = []

    # Take the more severe rating
    if (
        SEVERITY_RANK.get(sli_v.get("severity", "INFO"), 1)
        > SEVERITY_RANK.get(llm_v.get("severity", "INFO"), 1)
    ):
        merged["severity"] = sli_v["severity"]

    return merged


def _dedup_slither(vulns: list[dict]) -> list[dict]:
    """
    Deduplicate Slither's internal sub-checks that map to the same category.

    Slither reports reentrancy-eth, reentrancy-no-eth, reentrancy-benign as
    separate findings —> all normalize to "reentrancy" in the evaluation.
    If multiple sub-checks point to overlapping lines in the same contract,
    keeping all of them inflates FP count unfairly.

    Strategy: for each normalized category, keep only the finding whose line
    range best covers the smallest span (most precise). Remove others that
    overlap within ±5 lines.
    """
    if not vulns:
        return vulns

    kept = []
    for vuln in vulns:
        cat   = vuln.get("category", "").lower().replace("-", " ")
        lines = vuln.get("line_numbers", [])

        duplicate = False
        for existing in kept:
            ex_cat   = existing.get("category", "").lower().replace("-", " ")
            ex_lines = existing.get("line_numbers", [])
            if ex_cat != cat:
                continue
        
            if not lines or not ex_lines:
                duplicate = True
                break
            if any(abs(l - e) <= 5 for l in lines for e in ex_lines):
                duplicate = True
                break
        if not duplicate:
            kept.append(vuln)

    if len(kept) < len(vulns):
        logger.info(
            "[Merge] Slither dedup: %d → %d findings (%d sub-check duplicates removed)",
            len(vulns), len(kept), len(vulns) - len(kept),
        )
    return kept


def run_merge_node(state: AuditState) -> AuditState:
    """
    Builds the final report exclusively from confirmed_findings — findings that
    passed the debate pipeline (critique → verify → tiebreaker).

    Anything the debate rejected or never confirmed is dropped.
    Overlapping LLM + Slither confirmed findings are tagged as BOTH.
    """
    logger.info("[LOG] Merge node")
    errors = list(state.get("errors", []))

    all_confirmed = state.get("confirmed_findings", [])

    # Split into LLM-origin and Slither-origin confirmed findings
    confirmed_llm = [f for f in all_confirmed if not f.get("id", "").startswith("SLI-")]
    confirmed_sli = _dedup_slither([f for f in all_confirmed if f.get("id", "").startswith("SLI-")])

    merged: list[dict] = []
    sli_used: set[int] = set()

    # Step 1: For each confirmed LLM finding, check if a confirmed Slither finding
    # covers the same vulnerability — if so merge them into a BOTH-source finding.
    for llm_v in confirmed_llm:
        llm_v = {**llm_v, "source": "LLM"}
        if "line_numbers" not in llm_v:
            llm_v["line_numbers"] = []

        matched = False
        for i, sli_v in enumerate(confirmed_sli):
            if i not in sli_used and _are_same(llm_v, sli_v):
                merged.append(_merge(llm_v, sli_v))
                sli_used.add(i)
                matched = True
                break
        if not matched:
            merged.append(llm_v)

    # Step 2: Add Slither-confirmed findings that have no LLM counterpart
    for i, sli_v in enumerate(confirmed_sli):
        if i not in sli_used:
            merged.append({**sli_v, "source": "SLITHER"})

    # Step 3: Stamp confidence from debate scores, sort by severity
    for v in merged:
        score = v.get("critique_score") or v.get("verify_score")
        if score is not None:
            v["confidence"] = "HIGH" if score >= 0.7 else "MEDIUM"
        elif "confidence" not in v:
            v["confidence"] = "HIGH"  # tiebreaker-confirmed findings

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
            "llm_model":        _DEFAULT_LLM_MODEL,
            "slither_available": (state.get("slither_report") or {}).get("success", False),
            "pipeline_errors":  errors,
        },
        "overall_risk":  _overall_risk(merged),
        "summary":       "Audit completed.",
        "contract_info": {
            "solidity_version": (state.get("contract_info") or {}).get("solidity_version", ""),
            "contract_names":   (state.get("contract_info") or {}).get("contract_names", []),
            "total_lines":      (state.get("contract_info") or {}).get("total_lines", 0),
        },
        "statistics":       stats,
        "vulnerabilities":  merged,
        "raw_detect":       [
            {**f, "source": "LLM"}
            for f in state.get("llm_detection_findings", [])
        ],
        "raw_slither":      [
            {**f, "source": "SLITHER"}
            for f in (state.get("slither_report") or {}).get("vulnerabilities", [])
            if f.get("severity", "").upper() not in {"INFO", "OPTIMIZATION", "LOW"}
            and f.get("category", "").lower() not in {"informational", "optimization"}
        ],
    }

    # Final report —> debug only
    logger.debug("━" * 50)
    logger.debug("FINAL REPORT")
    logger.debug("━" * 50)
    logger.debug(json.dumps(final_report, indent=2, ensure_ascii=False))
    logger.debug("━" * 50)

    return {**state, "final_report": final_report, "errors": errors}