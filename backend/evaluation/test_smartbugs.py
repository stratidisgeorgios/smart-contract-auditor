#!/usr/bin/env python3
"""
Batch evaluation against the SmartBugs Curated dataset (143 contracts).
Measures Precision / Recall / F1 across four modes:
  - Raw detector output   (pre-debate)
  - Raw Slither output    (pre-debate, MEDIUM+ only)
  - Debate-confirmed LLM  (post-debate)
  - Debate-confirmed Both (post-debate, LLM + Slither)
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import aiohttp
import sys

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")  # load GROQ / Langfuse keys

from metrics import calculate_metrics

# ── Paths ─────────────────────────────────────────────────────────────────────
_REPO_ROOT   = Path(__file__).parent.parent.parent
DATASET_PATH = _REPO_ROOT / "smartbugs-curated" / "dataset"
GT_FILE      = _REPO_ROOT / "smartbugs-curated" / "vulnerabilities.json"
BACKEND_URL  = "http://localhost:8000/api/v1/audit"

# ── Timing ────────────────────────────────────────────────────────────────────
# Each pipeline run uses 3 separate Groq keys (KEY1: detect+tiebreaker,
# KEY2: critique, KEY3: verify). The tiebreaker guards 65s after detect on KEY1,
# so 90s between contracts leaves 25s of headroom before the next detect.
DELAY_BETWEEN_CONTRACTS = 90   # seconds between contracts
BACKEND_TIMEOUT         = 400  # max seconds to wait for one audit API call

# ── Run options ───────────────────────────────────────────────────────────────
VERBOSE       = True   # print GT vs detected per contract
MAX_CONTRACTS = None   # None = all 143; set e.g. 20 for a quick test


# ── Category normalisation ────────────────────────────────────────────────────
# Maps every Slither detector name and LLM category variant → the GT canonical name.
CATEGORY_ALIASES: Dict[str, str] = {
    # unchecked_low_level_calls
    "unchecked lowlevel":           "unchecked_low_level_calls",
    "unchecked_lowlevel":           "unchecked_low_level_calls",
    "unchecked send":               "unchecked_low_level_calls",
    "unchecked_send":               "unchecked_low_level_calls",
    "unchecked transfer":           "unchecked_low_level_calls",
    "unchecked_transfer":           "unchecked_low_level_calls",
    "unchecked return values":      "unchecked_low_level_calls",
    "unchecked_return_values":      "unchecked_low_level_calls",
    "unchecked low level calls":    "unchecked_low_level_calls",
    "unchecked_low_level_calls":    "unchecked_low_level_calls",
    "unchecked low-level calls":    "unchecked_low_level_calls",
    "unchecked low-level call":     "unchecked_low_level_calls",
    "unchecked low level call":     "unchecked_low_level_calls",
    "arbitrary send eth":           "unchecked_low_level_calls",
    "arbitrary_send_eth":           "unchecked_low_level_calls",
    "arbitrary send":               "unchecked_low_level_calls",
    "arbitrary_send":               "unchecked_low_level_calls",

    # reentrancy
    "reentrancy":                   "reentrancy",
    "reentrancy eth":               "reentrancy",
    "reentrancy_eth":               "reentrancy",
    "reentrancy no eth":            "reentrancy",
    "reentrancy_no_eth":            "reentrancy",
    "reentrancy events":            "reentrancy",
    "reentrancy_events":            "reentrancy",
    "reentrancy benign":            "reentrancy",
    "reentrancy_benign":            "reentrancy",
    "reentrancy read before write": "reentrancy",
    "reentrancy unlimited gas":     "reentrancy",
    "reentrancy_unlimited_gas":     "reentrancy",

    # integer overflow / underflow
    "integer overflow":             "arithmetic",
    "integer_overflow":             "arithmetic",
    "integer underflow":            "arithmetic",
    "integer_underflow":            "arithmetic",
    "overflow":                     "arithmetic",
    "underflow":                    "arithmetic",
    "arithmetic":                   "arithmetic",
    "tainted divide":               "arithmetic",

    # access control
    "access control":               "access_control",
    "access_control":               "access_control",
    "unprotected ether withdrawal": "access_control",
    "unprotected upgrade":          "access_control",
    "unprotected selfdestruct":     "access_control",
    "unprotected_selfdestruct":     "access_control",
    "unprotected self destruct":    "access_control",
    "suicide":                      "access_control",
    "selfdestruct":                 "access_control",
    "tx origin":                    "access_control",
    "tx.origin":                    "access_control",
    "tx-origin":                    "access_control",
    "suicidal":                     "access_control",
    "controlled delegatecall":      "access_control",

    # time manipulation
    "time manipulation":            "time_manipulation",
    "time_manipulation":            "time_manipulation",
    "timestamp":                    "time_manipulation",
    "timestamp dependence":         "time_manipulation",
    "timestamp_dependence":         "time_manipulation",
    "block timestamp":              "time_manipulation",
    "block_timestamp":              "time_manipulation",

    # denial of service
    "denial of service":            "denial_of_service",
    "denial_of_service":            "denial_of_service",
    "dos":                          "denial_of_service",

    # bad randomness
    "bad randomness":               "bad_randomness",
    "bad_randomness":               "bad_randomness",
    "weak prng":                    "bad_randomness",
    "weak_prng":                    "bad_randomness",
    "weak randomness":              "bad_randomness",
    "weak sources of randomness":   "bad_randomness",

    # front running
    "front running":                "front_running",
    "front_running":                "front_running",
    "front-running":                "front_running",

    # short address
    "short address":                "short_address",
    "short_address":                "short_address",
    "short addresses":              "short_address",
    "short_addresses":              "short_address",

    # LLM sometimes uses "informational" when it means "other" -> treat as "other"
    "informational":                "other",

    # informational -> skipped during matching as they are not considered in GT
    "low level calls":              "informational",
    "low_level_calls":              "informational",
    "naming convention":            "informational",
    "solc version":                 "informational",
    "dead code":                    "informational",
    "deprecated standards":         "informational",
    "boolean equal":                "informational",
    "events maths":                 "informational",
    "missing zero check":           "informational",
    "constable states":             "informational",
    "external function":            "informational",
    "shadowing builtin":            "informational",
    "shadowing state":              "informational",
    "shadowing local":              "informational",
    "locked ether":                 "informational",
    "missing inheritance":          "informational",
    "unindexed event address":      "informational",
    "unused state":                 "informational",
    "incorrect modifier":           "informational",
    "calls loop":                   "informational",
    "controlled array length":      "informational",
    "tautology":                    "informational",
    "write after write":            "informational",
    "msg value loop":               "informational",
    "divide before multiply":       "informational",
    "uninitialized local":          "informational",
    "constant function asm":        "informational",
    "incorrect equality":           "informational",
    "unused return":                "informational",
    "events access":                "informational",
    "assembly":                     "informational",
    "function init state":          "informational",
    "return bomb":                  "informational",
    "uninitialized state":          "informational",
    "uninitialized storage":        "informational",
    "costly loop":                  "informational",
    "erc20 interface":              "informational",
    "cache array length":           "informational",
    "redundant statements":         "informational",
    "too many digits":              "informational",
    "other":                        "other", 
}


def normalize_category(raw: str) -> str:
    """Map a raw detector/LLM category string to the GT canonical name."""
    lowered = raw.lower().strip()
    key_spaces = lowered.replace("_", " ")
    if key_spaces in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[key_spaces]
    if lowered in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[lowered]
    return lowered 


# ── Data loading ──────────────────────────────────────────────────────────────

def load_ground_truth(gt_path: Path) -> List[Dict]:
    with open(gt_path) as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("contracts", [])


def find_contracts(dataset_path: Path) -> List[Tuple[str, Path]]:
    contracts = []
    for sol_file in dataset_path.rglob("*.sol"):
        contracts.append((sol_file.stem, sol_file))
    return sorted(contracts)


def find_contracts_balanced(
    dataset_path: Path,
    max_contracts: Optional[int] = None,
) -> List[Tuple[str, Path]]:
    """
    Round-robin selection across vulnerability categories, shortest-first within each.
    Ensures every category is represented before any category gets a second contract.
    """
    from collections import defaultdict, Counter

    by_category: dict = defaultdict(list)
    for sol_file in dataset_path.rglob("*.sol"):
        category = sol_file.parent.name
        try:
            lines = len(sol_file.read_text(encoding="utf-8", errors="replace").splitlines())
        except Exception:
            lines = 0
        by_category[category].append((sol_file.stem, sol_file, lines))

    for cat in by_category:
        by_category[cat].sort(key=lambda x: (x[2], x[0]))  # shortest first, alphabetical for ties

    categories = sorted(by_category.keys())
    selected = []
    round_num = 0

    while True:
        added_this_round = False
        for cat in categories:
            if round_num < len(by_category[cat]):
                selected.append(by_category[cat][round_num])
                added_this_round = True
                if max_contracts and len(selected) >= max_contracts:
                    break
        if not added_this_round or (max_contracts and len(selected) >= max_contracts):
            break
        round_num += 1

    cat_counts = Counter(sol_file.parent.name for _, sol_file, _ in selected)
    print(f"\n✓ Balanced selection: {len(selected)} contracts across {len(cat_counts)} categories")
    print(f"  {'Category':<30} {'Count':>5}  {'Lines (min-max)'}")
    print(f"  {'-'*55}")
    for cat in sorted(cat_counts.keys()):
        cat_contracts = [(n, p, l) for n, p, l in selected if p.parent.name == cat]
        min_l = min(l for _, _, l in cat_contracts)
        max_l = max(l for _, _, l in cat_contracts)
        print(f"  {cat:<30} {cat_counts[cat]:>5}  ({min_l}-{max_l} lines)")

    # Contracts >200 lines trigger llama-4-scout (larger model) in the pipeline
    over_200 = [(n, p, l) for n, p, l in selected if l > 200]
    if over_200:
        print("\n" + "=" * 60)
        print(f"  WARNING: {len(over_200)} contract(s) exceed 200 lines -- LLM may fail")
        print("=" * 60)
        for name, _, lcount in over_200:
            print(f"  >> {name}: {lcount} lines")
        print("=" * 60 + "\n")
    else:
        print(f"\n  All {len(selected)} contracts are <= 200 lines\n")

    return [(name, path) for name, path, _ in selected]
def match_ground_truth(contract_name: str, contracts_gt: List[Dict]) -> Optional[Dict]:
    contract_lower = contract_name.lower().replace(".sol", "")
    for gt in contracts_gt:
        gt_name = gt.get("name", "").replace(".sol", "").lower()
        if contract_lower == gt_name:
            return gt
    return None


# ── API ───────────────────────────────────────────────────────────────────────

def _strip_smartbugs_header(source: str) -> str:
    """
    Redact SmartBugs answer-key hints before sending to the LLM.
    Operates in-place so line numbers are never shifted.

    Removes:
      @vulnerable_at_lines: N,M,...   → replaced with [redacted]  (header)
      // <yes> <report> CATEGORY      → comment stripped, code kept  (inline)
    """
    source = re.sub(r"@vulnerable_at_lines:[^\n]*", "@vulnerable_at_lines: [redacted]", source)
    source = re.sub(r"\s*//\s*<\w+>\s*<report>\s*[\w_]+", "", source)
    return source


async def audit_contract(file_path: Path) -> Optional[Dict]:
    """Send a contract to the backend and return the audit JSON."""
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
        file_content = _strip_smartbugs_header(raw).encode("utf-8")

        data = aiohttp.FormData()
        data.add_field(
            "file", file_content,
            filename=file_path.name,
            content_type="text/plain",
        )

        async with aiohttp.ClientSession() as session:
            async with session.post(
                BACKEND_URL,
                data=data,
                timeout=aiohttp.ClientTimeout(total=BACKEND_TIMEOUT),
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    text = await resp.text()
                    print(f"\n API Error {resp.status}: {text[:200]}")
                    return None

    except asyncio.TimeoutError:
        print(f"\n Timeout after {BACKEND_TIMEOUT}s")
        return None
    except Exception as e:
        print(f"\n Exception: {e}")
        return None


# ── Matching ──────────────────────────────────────────────────────────────────

def deduplicate_gt(gt_list: List[Dict]) -> List[Dict]:
    """Drop duplicate GT entries (same category + overlapping lines)."""
    seen = []
    deduped = []
    for truth in gt_list:
        norm_cat = normalize_category(truth.get("category", "unknown"))
        lines = set(truth.get("lines", []))
        duplicate = False
        for seen_cat, seen_lines in seen:
            if seen_cat != norm_cat:
                continue
            if not lines or not seen_lines or lines & seen_lines:
                duplicate = True
                break
        if not duplicate:
            seen.append((norm_cat, lines))
            deduped.append(truth)
    return deduped


def deduplicate_detected(detected_list: List[Dict]) -> List[Dict]:
    """
    Collapse Slither-only duplicates (same category, same line).
    LLM/BOTH findings are never collapsed — each instance can match a distinct GT entry.
    Informational findings pass through unchanged.
    """
    seen = []
    deduped = []
    tolerance = 0

    for finding in detected_list:
        norm_cat = normalize_category(finding.get("category", "unknown"))
        if norm_cat == "informational":
            deduped.append(finding)
            continue

        if finding.get("source") in ("LLM", "BOTH"):
            deduped.append(finding)
            continue

        lines = set(finding.get("line_numbers", []))
        duplicate = False
        for seen_cat, seen_lines in seen:
            if seen_cat != norm_cat:
                continue
            if not lines or not seen_lines:
                duplicate = True
                break
            if any(abs(l - s) <= tolerance for l in lines for s in seen_lines):
                duplicate = True
                break
        if not duplicate:
            seen.append((norm_cat, lines))
            deduped.append(finding)
    return deduped


def match_findings(detected_list: List[Dict], gt_list: List[Dict]) -> Dict:
    """
    Score detected findings against ground truth.
    Returns {tp, fp, fn, per_category}.

    A detection matches a GT entry when:
      - categories are the same (after normalisation), AND
      - GT line falls within [min(detected) − 7, max(detected) + 7]
      - access_control uses ±25 instead (function-level vulnerability)
    Each GT entry can only be matched once.
    """
    gt_list = deduplicate_gt(gt_list)
    detected_list = deduplicate_detected(detected_list)

    tp = 0
    matched_truth = set()
    unmatched_detected = []
    per_category: Dict = {}

    for detected in detected_list:
        detected_cat_raw = detected.get("category", "unknown")
        detected_cat = normalize_category(detected_cat_raw)
        detected_lines: List[int] = detected.get("line_numbers", [])

        # Skip informational noise
        if detected_cat == "informational":
            continue

        found_match = False

        for truth_idx, truth in enumerate(gt_list):
            if truth_idx in matched_truth:
                continue

            truth_cat = normalize_category(truth.get("category", "unknown"))
            truth_lines: List[int] = truth.get("lines", [])

            if detected_cat != truth_cat:
                continue

            if not detected_lines or not truth_lines:
                line_match = True
            else:
                dl_min = min(detected_lines) - 7
                dl_max = max(detected_lines) + 7
                line_match = any(dl_min <= tl <= dl_max for tl in truth_lines)

                if not line_match and detected_cat == "access_control":
                    line_match = any(
                        abs(dl - tl) <= 25
                        for dl in detected_lines
                        for tl in truth_lines
                    )

            if line_match:
                tp += 1
                found_match = True
                matched_truth.add(truth_idx)
                per_category.setdefault(truth_cat, {"tp": 0, "fp": 0, "fn": 0})
                per_category[truth_cat]["tp"] += 1
                break

        if not found_match:
            unmatched_detected.append(detected)
            per_category.setdefault(detected_cat, {"tp": 0, "fp": 0, "fn": 0})
            per_category[detected_cat]["fp"] += 1

    fp = len(unmatched_detected)

    for truth_idx, truth in enumerate(gt_list):
        if truth_idx not in matched_truth:
            truth_cat = normalize_category(truth.get("category", "unknown"))
            per_category.setdefault(truth_cat, {"tp": 0, "fp": 0, "fn": 0})
            per_category[truth_cat]["fn"] += 1

    fn = len(gt_list) - len(matched_truth)
    return {"tp": tp, "fp": fp, "fn": fn, "per_category": per_category}


def compare_findings(
    detected_findings: List[Dict],
    raw_detect: List[Dict],
    raw_slither: List[Dict],
    ground_truth_vulns: List[Dict],
) -> Tuple[Dict, Dict, Dict, Dict]:
    """
    Returns (debate_both, debate_llm, detect_only, slither_only).

    debate_both   — post-debate confirmed findings (LLM + Slither + BOTH)
    debate_llm    — post-debate confirmed LLM/BOTH findings only
    detect_only   — raw LLM detect output before any debate filtering
    slither_only  — raw Slither MEDIUM+ output before any debate filtering
    """
    debate_llm_findings = [
        f for f in detected_findings
        if f.get("source") in ("LLM", "BOTH")
    ]

    debate_both   = match_findings(detected_findings,    ground_truth_vulns)
    debate_llm    = match_findings(debate_llm_findings,  ground_truth_vulns)
    detect_only   = match_findings(raw_detect,           ground_truth_vulns)
    slither_only  = match_findings(raw_slither,          ground_truth_vulns)

    return debate_both, debate_llm, detect_only, slither_only



def generate_report(
    evaluated: int, skipped: int, failed: int, total_contracts: int,
    total_tp_both: int, total_fp_both: int, total_fn_both: int,
    total_tp_llm: int, total_fp_llm: int, total_fn_llm: int,
    total_tp_detect: int, total_fp_detect: int, total_fn_detect: int,
    total_tp_slither: int, total_fp_slither: int, total_fn_slither: int,
    metrics_both: Dict, metrics_llm: Dict,
    metrics_detect: Dict, metrics_slither: Dict,
    per_cat_both: Dict, per_cat_llm: Dict,
    per_cat_detect: Dict, per_cat_slither: Dict,
) -> Path:
    """Generate an evaluation report and save it to disk."""

    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = Path(__file__).parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    report_path = reports_dir / f"evaluation_{timestamp}.txt"

    W = 72

    def section(title):
        return ["", "=" * W, f"  {title}", "=" * W]

    def row(label, val, width=30):
        return f"  {label:<{width}} {val}"

    def metrics_block(tp, fp, fn, m):
        out = []
        out.append(row("True Positives  (TP):", tp))
        out.append(row("False Positives (FP):", fp))
        out.append(row("False Negatives (FN):", fn))
        out.append("")
        out.append(row("Precision:", f"{m['precision']:.1%}"))
        out.append(row("Recall:",    f"{m['recall']:.1%}"))
        out.append(row("F1-Score:",  f"{m['f1_score']:.4f}"))
        return out

    def delta_block(label_a, m_a, label_b, m_b):
        """Show metric deltas: m_b − m_a (positive = m_b is better)."""
        out = []
        out.append(f"  {'':28} {'Precision':>9} {'Recall':>7} {'F1':>7}")
        out.append("  " + "-" * (W - 2))
        def _sign(v): return f"{v:+.1%}" if "%" not in f"{v}" else f"{v:+.4f}"
        dp = m_b["precision"] - m_a["precision"]
        dr = m_b["recall"]    - m_a["recall"]
        df = m_b["f1_score"]  - m_a["f1_score"]
        out.append(f"  {label_a:<28} {m_a['precision']:>8.1%} {m_a['recall']:>6.1%} {m_a['f1_score']:>6.3f}")
        out.append(f"  {label_b:<28} {m_b['precision']:>8.1%} {m_b['recall']:>6.1%} {m_b['f1_score']:>6.3f}")
        out.append(f"  {'Delta (b − a)':<28} {dp:>+8.1%} {dr:>+6.1%} {df:>+6.3f}")
        return out

    def cat_table(per_cat):
        out = []
        out.append(f"  {'Vulnerability':<28} {'TP':>4} {'FP':>4} {'FN':>4}  "
                   f"{'Precision':>9} {'Recall':>7} {'F1':>7}")
        out.append("  " + "-" * (W - 2))
        rows = []
        for cat, v in per_cat.items():
            if cat == "informational":
                continue
            m = calculate_metrics(v["tp"], v["fp"], v["fn"])
            rows.append((cat, v, m))
        rows.sort(key=lambda x: x[2]["f1_score"], reverse=True)
        for cat, v, m in rows:
            out.append(
                f"  {cat:<28} {v['tp']:>4} {v['fp']:>4} {v['fn']:>4}  "
                f"{m['precision']:>8.1%} {m['recall']:>6.1%} {m['f1_score']:>6.3f}"
            )
        if not rows:
            out.append("  (no data)")
        return out

    lines = []
    lines.append("=" * W)
    lines.append("  SMART CONTRACT AUDITOR — EVALUATION REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * W)

    # ── Run statistics ────────────────────────────────────────────────────────
    lines += section("RUN STATISTICS")
    lines.append(row("Total contracts in dataset:", total_contracts))
    lines.append(row("Contracts evaluated:", evaluated))
    lines.append(row("Skipped (no ground truth):", skipped))
    lines.append(row("Failed (API error):", failed))

    # ── Detector raw (pre-debate) ─────────────────────────────────────────────
    lines += section("RAW DETECTOR ONLY  (pre-debate, LLM detect node)")
    lines += metrics_block(total_tp_detect, total_fp_detect, total_fn_detect, metrics_detect)

    # ── Slither raw (pre-debate) ──────────────────────────────────────────────
    lines += section("RAW SLITHER ONLY   (pre-debate, MEDIUM+ findings)")
    lines += metrics_block(total_tp_slither, total_fp_slither, total_fn_slither, metrics_slither)

    # ── Debate-confirmed: LLM-only ────────────────────────────────────────────
    lines += section("DEBATE — LLM CONFIRMED  (post-debate, LLM/BOTH source)")
    lines += metrics_block(total_tp_llm, total_fp_llm, total_fn_llm, metrics_llm)

    # ── Debate-confirmed: both engines ────────────────────────────────────────
    lines += section("DEBATE — BOTH ENGINES   (post-debate, LLM + Slither)")
    lines += metrics_block(total_tp_both, total_fp_both, total_fn_both, metrics_both)

    # ── Impact of debate on LLM findings ─────────────────────────────────────
    lines += section("DEBATE IMPACT — LLM findings: raw detect vs post-debate")
    lines.append("  Does the debate pipeline improve on raw detector output?")
    lines.append("")
    lines += delta_block("Detector (raw)", metrics_detect, "Debate-LLM", metrics_llm)

    # ── Impact of adding Slither ──────────────────────────────────────────────
    lines += section("SLITHER IMPACT — debate-LLM vs debate-both")
    lines.append("  Does adding Slither confirmed findings improve on LLM-only debate?")
    lines.append("")
    lines += delta_block("Debate-LLM", metrics_llm, "Debate-Both", metrics_both)

    # ── Summary comparison table ──────────────────────────────────────────────
    lines += section("SUMMARY COMPARISON")
    lines.append(f"  {'Mode':<32} {'Precision':>9} {'Recall':>7} {'F1':>7}")
    lines.append("  " + "-" * (W - 2))
    for label, m in [
        ("Detector raw (pre-debate)",    metrics_detect),
        ("Slither raw  (pre-debate)",    metrics_slither),
        ("Debate — LLM confirmed",       metrics_llm),
        ("Debate — Both engines",        metrics_both),
    ]:
        lines.append(
            f"  {label:<32} {m['precision']:>8.1%} {m['recall']:>6.1%} {m['f1_score']:>6.3f}"
        )

    # ── Per-category breakdowns ───────────────────────────────────────────────
    lines += section("PER-VULNERABILITY — DETECTOR RAW")
    lines += cat_table(per_cat_detect)

    lines += section("PER-VULNERABILITY — SLITHER RAW")
    lines += cat_table(per_cat_slither)

    lines += section("PER-VULNERABILITY — DEBATE LLM")
    lines += cat_table(per_cat_llm)

    lines += section("PER-VULNERABILITY — DEBATE BOTH ENGINES")
    lines += cat_table(per_cat_both)

    lines.append("")
    lines.append("=" * W)
    lines.append("  END OF REPORT")
    lines.append("=" * W)

    report_path.write_text("\n".join(lines))
    return report_path


def preflight_check() -> bool:
    """
    Runs before the evaluation to verify all required resources are reachable.
    Prints a status for each check so that we know exactly what is and is not
    working before waiting 70 minutes.
    Returns True if OK to proceed, False if a blocking problem was found.
    """
    import os
    import importlib.util
    ok = True

    print("\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510")
    print("\u2502  PRE-FLIGHT CHECK                                       \u2502")
    print("\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518")

    if DATASET_PATH.exists():
        sol_count = len(list(DATASET_PATH.rglob("*.sol")))
        print(f"  OK  Dataset found  ({sol_count} .sol files)  {DATASET_PATH}")
    else:
        print(f"  FAIL  Dataset NOT found — expected: {DATASET_PATH}")
        ok = False

    if GT_FILE.exists():
        print(f"  OK  Ground-truth file found  -> {GT_FILE.name}")
    else:
        print(f"  FAIL  Ground-truth NOT found — expected: {GT_FILE}")
        ok = False

    if os.getenv("GROQ_API_KEY"):
        print(f"  OK  GROQ_API_KEY is set")
    else:
        print(f"  WARN  GROQ_API_KEY not set — backend LLM calls will fail")

    langfuse_installed = importlib.util.find_spec("langfuse") is not None
    lf_pub = bool(os.getenv("LANGFUSE_PUBLIC_KEY"))
    lf_sec = bool(os.getenv("LANGFUSE_SECRET_KEY"))

    if not langfuse_installed:
        print(f"  --  Langfuse not installed — prompts read from local .txt files")
    elif not lf_pub or not lf_sec:
        print(f"  --  Langfuse keys not set — prompts read from local .txt files")
    else:
        try:
            from langfuse import Langfuse
            client = Langfuse(
                public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
                secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
                host=os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com"),
            )
            prompt_obj = client.get_prompt("audit-detect-prompt", label="production")
            preview = prompt_obj.compile()[:70].replace("\n", " ")
            print(f"  OK  Langfuse connected — audit-detect-prompt loaded  \"{preview}...\"")
        except Exception as exc:
            print(f"  WARN  Langfuse keys set but fetch failed: {exc} — falling back to local files")

    print()
    return ok

# ── Main ──────────────────────────────────────────────────────────────────────

async def test_batch():
    print("╔════════════════════════════════════════════════════════╗")
    print("║     SmartBugs Evaluation                               ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    if not preflight_check():
        print("Preflight failed -- fix the issues above before running the evaluation.")
        return

    contracts_gt = load_ground_truth(GT_FILE)
    print(f"✓ Loaded {len(contracts_gt)} ground truth contracts")

    contracts = find_contracts_balanced(DATASET_PATH, max_contracts=MAX_CONTRACTS)
    print(f"✓ {len(contracts)} contracts selected")
    print(f"✓ Delay between contracts: {DELAY_BETWEEN_CONTRACTS}s\n")

    # running totals for each of the four scoring modes
    total_tp_both    = total_fp_both    = total_fn_both    = 0
    total_tp_llm     = total_fp_llm     = total_fn_llm     = 0
    total_tp_detect  = total_fp_detect  = total_fn_detect  = 0
    total_tp_slither = total_fp_slither = total_fn_slither = 0
    skipped = 0
    failed  = 0
    per_cat_both:    Dict = {}
    per_cat_llm:     Dict = {}
    per_cat_detect:  Dict = {}
    per_cat_slither: Dict = {}

    for i, (contract_name, file_path) in enumerate(contracts, 1):
        if i > 1:  # wait between contracts to respect KEY1 TPM window
            await asyncio.sleep(DELAY_BETWEEN_CONTRACTS)

        print(f"[{i:3}/{len(contracts)}] {contract_name}...", end=" ", flush=True)

        gt_data = match_ground_truth(contract_name, contracts_gt)
        if not gt_data:
            print("no ground truth")
            skipped += 1
            continue

        vulns_gt = gt_data.get("vulnerabilities", [])

        audit_result = await audit_contract(file_path)
        if not audit_result:
            print(" API error")
            failed += 1
            continue

        vulns_detected  = audit_result.get("vulnerabilities", [])
        raw_detect      = audit_result.get("raw_detect", [])
        raw_slither     = audit_result.get("raw_slither", [])
        llm_count       = len([v for v in vulns_detected if v.get("source") in ("LLM", "BOTH")])

        debate_both, debate_llm, detect_m, slither_m = compare_findings(
            vulns_detected, raw_detect, raw_slither, vulns_gt
        )

        total_tp_both    += debate_both["tp"];  total_fp_both    += debate_both["fp"];  total_fn_both    += debate_both["fn"]
        total_tp_llm     += debate_llm["tp"];   total_fp_llm     += debate_llm["fp"];   total_fn_llm     += debate_llm["fn"]
        total_tp_detect  += detect_m["tp"];     total_fp_detect  += detect_m["fp"];     total_fn_detect  += detect_m["fn"]
        total_tp_slither += slither_m["tp"];    total_fp_slither += slither_m["fp"];    total_fn_slither += slither_m["fn"]

        def _acc(store, metrics):
            for cat, vals in metrics.get("per_category", {}).items():
                store.setdefault(cat, {"tp": 0, "fp": 0, "fn": 0})
                store[cat]["tp"] += vals.get("tp", 0)
                store[cat]["fp"] += vals.get("fp", 0)
                store[cat]["fn"] += vals.get("fn", 0)

        _acc(per_cat_both,    debate_both)
        _acc(per_cat_llm,     debate_llm)
        _acc(per_cat_detect,  detect_m)
        _acc(per_cat_slither, slither_m)

        print(
            f"✓  GT:{len(vulns_gt)} | "
            f"Det(raw):{len(raw_detect)} Sli(raw):{len(raw_slither)} | "
            f"Debate LLM:{llm_count} | "
            f"TP det:{detect_m['tp']} sli:{slither_m['tp']} "
            f"deb-both:{debate_both['tp']} deb-llm:{debate_llm['tp']}"
        )

        if VERBOSE:
            from collections import Counter

            print(f"    File:    {file_path}")

            gt_parts = [f"{v.get('category','?')}@{v.get('lines',[])}" for v in vulns_gt]
            print(f"    GT:      {', '.join(gt_parts)}")

            llm_findings_v = [v for v in vulns_detected if v.get("source") in ("LLM", "BOTH")]
            if llm_findings_v:
                llm_parts = []
                for v in llm_findings_v:
                    cat   = normalize_category(v.get("category", "?"))
                    lines = v.get("line_numbers", [])
                    matched = any(
                        normalize_category(gt.get("category", "")) == cat and (
                            not lines or not gt.get("lines") or
                            any(
                                (min(lines) - 7) <= tl <= (max(lines) + 7)
                                for tl in gt.get("lines", [])
                            )
                        )
                        for gt in vulns_gt
                    )
                    flag = "OK" if matched else "MISS"
                    llm_parts.append(f"{cat}@{lines}[{flag}]")
                print(f"    LLM:     {', '.join(llm_parts)}")
            else:
                print(f"    LLM:     NONE — LLM failed or returned empty")

            sli_counts = Counter(
                normalize_category(v.get("category", "?"))
                for v in vulns_detected if v.get("source") == "SLITHER"
            )
            sli_str = ", ".join(
                f"{cat}(x{n})" if n > 1 else cat
                for cat, n in sorted(sli_counts.items())
            ) or "none"
            print(f"    Slither: {sli_str}")
            print()

    # Summary
    evaluated        = len(contracts) - skipped - failed
    metrics_both     = calculate_metrics(total_tp_both,    total_fp_both,    total_fn_both)
    metrics_llm      = calculate_metrics(total_tp_llm,     total_fp_llm,     total_fn_llm)
    metrics_detect   = calculate_metrics(total_tp_detect,  total_fp_detect,  total_fn_detect)
    metrics_slither  = calculate_metrics(total_tp_slither, total_fp_slither, total_fn_slither)

    def _print_mode(label, tp, fp, fn, m):
        print(f" {label}:")
        print(f"  TP: {tp} | FP: {fp} | FN: {fn}")
        print(f"  Precision: {m['precision']:.1%}  Recall: {m['recall']:.1%}  F1: {m['f1_score']:.4f}\n")

    print(f"\n{'='*70}")
    print(f" FINAL RESULTS  ({evaluated} contracts evaluated, {skipped} skipped, {failed} failed)")
    print(f"{'='*70}\n")
    _print_mode("DETECTOR ONLY (raw, pre-debate)",  total_tp_detect,  total_fp_detect,  total_fn_detect,  metrics_detect)
    _print_mode("SLITHER ONLY  (raw MEDIUM+, pre-debate)", total_tp_slither, total_fp_slither, total_fn_slither, metrics_slither)
    _print_mode("DEBATE — LLM only (post-debate)",  total_tp_llm,     total_fp_llm,     total_fn_llm,     metrics_llm)
    _print_mode("DEBATE — BOTH engines (post-debate)", total_tp_both, total_fp_both,    total_fn_both,    metrics_both)

    print(" DEBATE vs DETECTOR (does debate help LLM findings?):")
    for label, a, b in [
        ("Precision", metrics_llm['precision'] - metrics_detect['precision'], metrics_both['precision'] - metrics_detect['precision']),
        ("Recall",    metrics_llm['recall']    - metrics_detect['recall'],    metrics_both['recall']    - metrics_detect['recall']),
        ("F1",        metrics_llm['f1_score']  - metrics_detect['f1_score'],  metrics_both['f1_score']  - metrics_detect['f1_score']),
    ]:
        print(f"  {label:<10} debate-LLM: {a:+.1%}   debate-both: {b:+.1%}")

    # Save report
    report_path = generate_report(
        evaluated=evaluated,
        skipped=skipped,
        failed=failed,
        total_contracts=len(contracts),
        total_tp_both=total_tp_both,       total_fp_both=total_fp_both,       total_fn_both=total_fn_both,
        total_tp_llm=total_tp_llm,         total_fp_llm=total_fp_llm,         total_fn_llm=total_fn_llm,
        total_tp_detect=total_tp_detect,   total_fp_detect=total_fp_detect,   total_fn_detect=total_fn_detect,
        total_tp_slither=total_tp_slither, total_fp_slither=total_fp_slither, total_fn_slither=total_fn_slither,
        metrics_both=metrics_both,         metrics_llm=metrics_llm,
        metrics_detect=metrics_detect,     metrics_slither=metrics_slither,
        per_cat_both=per_cat_both,         per_cat_llm=per_cat_llm,
        per_cat_detect=per_cat_detect,     per_cat_slither=per_cat_slither,
    )
    print(f"\n Report saved to: {report_path}")


if __name__ == "__main__":
    asyncio.run(test_batch())