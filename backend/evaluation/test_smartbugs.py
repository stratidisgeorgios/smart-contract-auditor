#!/usr/bin/env python3
"""
SmartBugs Curated dataset evaluation script - Batch mode.
Tests all 143 contracts and measures accuracy with dual-engine comparison.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import aiohttp
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from metrics import calculate_metrics

# ─── Configuration ────────────────────────────────────────────────────────────
DATASET_PATH = Path(__file__).parent.parent.parent.parent / "smartbugs-curated" / "dataset"
GT_FILE      = Path(__file__).parent.parent.parent.parent / "smartbugs-curated" / "vulnerabilities.json"
BACKEND_URL  = "http://localhost:8000/api/v1/audit"

# Rate-limiting: Groq free tier ~30 req/min.
# Each contract = 1 LLM call, so space them out.
DELAY_BETWEEN_CONTRACTS = 8   # seconds between each audit call
BACKEND_TIMEOUT         = 180  # seconds — long enough for Groq retries inside backend


# ─── Category normalization ───────────────────────────────────────────────────
# Maps every known Slither/LLM detector name → GT canonical snake_case name.
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

    # informational — skipped entirely during matching
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
    "other":                        "informational",
}


def normalize_category(raw: str) -> str:
    """Normalize a raw category string to the GT canonical name."""
    lowered = raw.lower().strip()
    # Try spaces variant first (underscores → spaces), preserving dots
    key_spaces = lowered.replace("_", " ")
    if key_spaces in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[key_spaces]
    if lowered in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[lowered]
    return lowered  # unknown — return as-is so two unknowns can still match


# ─── Data loading ─────────────────────────────────────────────────────────────

def load_ground_truth(gt_path: Path) -> List[Dict]:
    with open(gt_path) as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("contracts", [])


def find_contracts(dataset_path: Path) -> List[Tuple[str, Path]]:
    contracts = []
    for sol_file in dataset_path.rglob("*.sol"):
        contracts.append((sol_file.stem, sol_file))
    return sorted(contracts)


def match_ground_truth(contract_name: str, contracts_gt: List[Dict]) -> Optional[Dict]:
    contract_lower = contract_name.lower().replace(".sol", "")
    for gt in contracts_gt:
        gt_name = gt.get("name", "").replace(".sol", "").lower()
        if contract_lower == gt_name:
            return gt
    return None


# ─── API call ─────────────────────────────────────────────────────────────────

async def audit_contract(file_path: Path) -> Optional[Dict]:
    """Call backend API to audit a contract. Waits up to BACKEND_TIMEOUT seconds."""
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()

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
                    print(f"\n    ❌ API Error {resp.status}: {text[:200]}")
                    return None

    except asyncio.TimeoutError:
        print(f"\n    ⏱️  Timeout after {BACKEND_TIMEOUT}s")
        return None
    except Exception as e:
        print(f"\n    ❌ Exception: {e}")
        return None


# ─── Matching ─────────────────────────────────────────────────────────────────

def deduplicate_gt(gt_list: List[Dict]) -> List[Dict]:
    """Remove duplicate GT entries (same normalized category + overlapping lines)."""
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
    Remove duplicate detections: same normalized category at overlapping lines.
    Keeps the first occurrence. Informational findings are passed through
    (they get skipped in the match loop anyway).
    """
    seen = []
    deduped = []
    tolerance = 15

    for finding in detected_list:
        norm_cat = normalize_category(finding.get("category", "unknown"))
        if norm_cat == "informational":
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
    Match detected findings against GT. Returns tp, fp, fn, per_category.
    Informational detections are skipped entirely.
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

            # Line match: if either side has no lines, accept on category alone
            if not detected_lines or not truth_lines:
                line_match = True
            else:
                line_match = any(
                    abs(dl - tl) <= 15
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
    ground_truth_vulns: List[Dict],
) -> Tuple[Dict, Dict]:
    """
    Returns (both_metrics, llm_metrics).
    both  = LLM + Slither + BOTH source findings
    llm   = LLM + BOTH source findings only
    """
    llm_findings = [
        f for f in detected_findings
        if f.get("source") in ("LLM", "BOTH")
    ]

    both_metrics = match_findings(detected_findings, ground_truth_vulns)
    llm_metrics  = match_findings(llm_findings, ground_truth_vulns)

    return both_metrics, llm_metrics



def generate_report(
    evaluated: int, skipped: int, failed: int, total_contracts: int,
    total_tp_both: int, total_fp_both: int, total_fn_both: int,
    total_tp_llm: int, total_fp_llm: int, total_fn_llm: int,
    metrics_both: Dict, metrics_llm: Dict,
    per_cat_both: Dict, per_cat_llm: Dict,
) -> Path:
    """Generate a human-readable evaluation report and save it to disk."""

    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = Path(__file__).parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    report_path = reports_dir / f"evaluation_{timestamp}.txt"

    W = 72  # line width

    def section(title):
        lines = []
        lines.append("")
        lines.append("=" * W)
        lines.append(f"  {title}")
        lines.append("=" * W)
        return lines

    def row(label, val, width=30):
        return f"  {label:<{width}} {val}"

    def cat_table(per_cat, label):
        lines = []
        lines.append(f"  {'Vulnerability':<28} {'TP':>4} {'FP':>4} {'FN':>4}  "
                     f"{'Precision':>9} {'Recall':>7} {'F1':>7}")
        lines.append("  " + "-" * (W - 2))
        # Sort by F1 descending
        rows = []
        for cat, v in per_cat.items():
            if cat == "informational":
                continue
            m = calculate_metrics(v["tp"], v["fp"], v["fn"])
            rows.append((cat, v, m))
        rows.sort(key=lambda x: x[2]["f1_score"], reverse=True)
        for cat, v, m in rows:
            lines.append(
                f"  {cat:<28} {v['tp']:>4} {v['fp']:>4} {v['fn']:>4}  "
                f"{m['precision']:>8.1%} {m['recall']:>6.1%} {m['f1_score']:>6.3f}"
            )
        if not rows:
            lines.append("  (no data)")
        return lines

    lines = []
    lines.append("=" * W)
    lines.append("  SMART CONTRACT AUDITOR — EVALUATION REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * W)

    # ── Run statistics ──────────────────────────────────────────────────────
    lines += section("RUN STATISTICS")
    lines.append(row("Total contracts in dataset:", total_contracts))
    lines.append(row("Contracts evaluated:", evaluated))
    lines.append(row("Skipped (no ground truth):", skipped))
    lines.append(row("Failed (API error):", failed))

    # ── Overall metrics ─────────────────────────────────────────────────────
    lines += section("OVERALL METRICS — BOTH ENGINES (LLM + Slither)")
    lines.append(row("True Positives (TP):", total_tp_both))
    lines.append(row("False Positives (FP):", total_fp_both))
    lines.append(row("False Negatives (FN):", total_fn_both))
    lines.append("")
    lines.append(row("Precision:", f"{metrics_both['precision']:.1%}"))
    lines.append(row("Recall:", f"{metrics_both['recall']:.1%}"))
    lines.append(row("F1-Score:", f"{metrics_both['f1_score']:.4f}"))

    lines += section("OVERALL METRICS — LLM-ONLY")
    lines.append(row("True Positives (TP):", total_tp_llm))
    lines.append(row("False Positives (FP):", total_fp_llm))
    lines.append(row("False Negatives (FN):", total_fn_llm))
    lines.append("")
    lines.append(row("Precision:", f"{metrics_llm['precision']:.1%}"))
    lines.append(row("Recall:", f"{metrics_llm['recall']:.1%}"))
    lines.append(row("F1-Score:", f"{metrics_llm['f1_score']:.4f}"))

    # ── Improvement ─────────────────────────────────────────────────────────
    lines += section("IMPROVEMENT — BOTH vs LLM-ONLY")
    p_delta  = metrics_both["precision"] - metrics_llm["precision"]
    r_delta  = metrics_both["recall"]    - metrics_llm["recall"]
    f1_delta = metrics_both["f1_score"]  - metrics_llm["f1_score"]
    lines.append(row("Precision delta:", f"{p_delta:+.1%}"))
    lines.append(row("Recall delta:", f"{r_delta:+.1%}"))
    lines.append(row("F1-Score delta:", f"{f1_delta:+.4f}"))
    if total_tp_llm > 0:
        tp_delta = ((total_tp_both - total_tp_llm) / total_tp_llm) * 100
        lines.append(row("TP improvement:", f"{tp_delta:+.1f}%"))

    # ── Interpretation ───────────────────────────────────────────────────────
    lines += section("INTERPRETATION")
    b_p = metrics_both["precision"]
    b_r = metrics_both["recall"]
    b_f = metrics_both["f1_score"]
    l_p = metrics_llm["precision"]
    l_r = metrics_llm["recall"]
    l_f = metrics_llm["f1_score"]

    if b_f >= 0.7:
        quality = "strong"
    elif b_f >= 0.5:
        quality = "moderate"
    elif b_f >= 0.3:
        quality = "weak"
    else:
        quality = "poor"

    lines.append(
        f"  The combined (LLM + Slither) engine achieves {quality} overall performance"
    )
    lines.append(
        f"  with an F1-score of {b_f:.3f} (Precision {b_p:.1%}, Recall {b_r:.1%})."
    )
    lines.append("")

    if b_r > b_p:
        lines.append(
            f"  Recall ({b_r:.1%}) outpaces Precision ({b_p:.1%}), meaning the system"
        )
        lines.append(
            "  catches most real vulnerabilities but also flags some false positives."
        )
    elif b_p > b_r:
        lines.append(
            f"  Precision ({b_p:.1%}) outpaces Recall ({b_r:.1%}), meaning confirmed"
        )
        lines.append(
            "  findings are reliable but some real vulnerabilities are missed."
        )
    else:
        lines.append("  Precision and Recall are well balanced.")
    lines.append("")

    if f1_delta > 0.05:
        lines.append(
            f"  Adding Slither improves F1 by {f1_delta:+.4f} over LLM-only, indicating"
        )
        lines.append("  the static analyser contributes meaningfully to detection coverage.")
    elif f1_delta < -0.05:
        lines.append(
            "  Slither introduces more false positives than true positives in this run."
        )
    else:
        lines.append(
            "  Slither has minimal net impact on F1 — most detections come from the LLM."
        )

    # ── Per-category breakdown ───────────────────────────────────────────────
    lines += section("PER-VULNERABILITY BREAKDOWN — BOTH ENGINES")
    lines += cat_table(per_cat_both, "both")

    lines += section("PER-VULNERABILITY BREAKDOWN — LLM-ONLY")
    lines += cat_table(per_cat_llm, "llm")

    lines.append("")
    lines.append("=" * W)
    lines.append("  END OF REPORT")
    lines.append("=" * W)

    report_text = "\n".join(lines)
    report_path.write_text(report_text)
    return report_path

# ─── Main ─────────────────────────────────────────────────────────────────────

async def test_batch():
    print("╔════════════════════════════════════════════════════════╗")
    print("║     SmartBugs Evaluation (Batch Mode)                  ║")
    print("║     (Both Engines vs LLM-Only)                         ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    contracts_gt = load_ground_truth(GT_FILE)
    print(f"✓ Loaded {len(contracts_gt)} ground truth contracts")

    contracts = find_contracts(DATASET_PATH)
    print(f"✓ Found {len(contracts)} .sol files")
    print(f"✓ Delay between contracts: {DELAY_BETWEEN_CONTRACTS}s\n")

    total_tp_both = total_fp_both = total_fn_both = 0
    total_tp_llm  = total_fp_llm  = total_fn_llm  = 0
    skipped = 0
    failed  = 0
    # per-category accumulators
    per_cat_both: Dict = {}
    per_cat_llm:  Dict = {}

    for i, (contract_name, file_path) in enumerate(contracts, 1):
        # Rate-limit: wait before every call except the first
        if i > 1:
            await asyncio.sleep(DELAY_BETWEEN_CONTRACTS)

        print(f"[{i:3}/{len(contracts)}] {contract_name}...", end=" ", flush=True)

        gt_data = match_ground_truth(contract_name, contracts_gt)
        if not gt_data:
            print("⚠️  no ground truth")
            skipped += 1
            continue

        vulns_gt = gt_data.get("vulnerabilities", [])

        audit_result = await audit_contract(file_path)
        if not audit_result:
            print("❌ API error")
            failed += 1
            continue

        vulns_detected = audit_result.get("vulnerabilities", [])
        llm_count = len([v for v in vulns_detected if v.get("source") in ("LLM", "BOTH")])

        both_metrics, llm_metrics = compare_findings(vulns_detected, vulns_gt)

        total_tp_both += both_metrics["tp"]
        total_fp_both += both_metrics["fp"]
        total_fn_both += both_metrics["fn"]
        total_tp_llm  += llm_metrics["tp"]
        total_fp_llm  += llm_metrics["fp"]
        total_fn_llm  += llm_metrics["fn"]

        for cat, vals in both_metrics.get("per_category", {}).items():
            per_cat_both.setdefault(cat, {"tp": 0, "fp": 0, "fn": 0})
            per_cat_both[cat]["tp"] += vals.get("tp", 0)
            per_cat_both[cat]["fp"] += vals.get("fp", 0)
            per_cat_both[cat]["fn"] += vals.get("fn", 0)
        for cat, vals in llm_metrics.get("per_category", {}).items():
            per_cat_llm.setdefault(cat, {"tp": 0, "fp": 0, "fn": 0})
            per_cat_llm[cat]["tp"] += vals.get("tp", 0)
            per_cat_llm[cat]["fp"] += vals.get("fp", 0)
            per_cat_llm[cat]["fn"] += vals.get("fn", 0)

        print(
            f"✓  GT:{len(vulns_gt)} | Det:{len(vulns_detected)} (LLM:{llm_count}) | "
            f"Both TP:{both_metrics['tp']} FP:{both_metrics['fp']} FN:{both_metrics['fn']} | "
            f"LLM TP:{llm_metrics['tp']} FP:{llm_metrics['fp']} FN:{llm_metrics['fn']}"
        )

    # ── Summary ───────────────────────────────────────────────────────────────
    evaluated = len(contracts) - skipped - failed
    metrics_both = calculate_metrics(total_tp_both, total_fp_both, total_fn_both)
    metrics_llm  = calculate_metrics(total_tp_llm,  total_fp_llm,  total_fn_llm)

    print(f"\n{'='*70}")
    print(f"📊 FINAL RESULTS  ({evaluated} contracts evaluated, "
          f"{skipped} skipped, {failed} failed)")
    print(f"{'='*70}\n")

    print("🔗 BOTH MODE (LLM + Slither):")
    print(f"  TP: {total_tp_both} | FP: {total_fp_both} | FN: {total_fn_both}")
    print(f"  Precision: {metrics_both['precision']:.1%}")
    print(f"  Recall:    {metrics_both['recall']:.1%}")
    print(f"  F1-Score:  {metrics_both['f1_score']:.4f}\n")

    print("🧠 LLM-ONLY MODE:")
    print(f"  TP: {total_tp_llm} | FP: {total_fp_llm} | FN: {total_fn_llm}")
    print(f"  Precision: {metrics_llm['precision']:.1%}")
    print(f"  Recall:    {metrics_llm['recall']:.1%}")
    print(f"  F1-Score:  {metrics_llm['f1_score']:.4f}\n")

    print("🚀 IMPROVEMENT (Both vs LLM-Only):")
    if total_tp_llm > 0:
        tp_delta = ((total_tp_both - total_tp_llm) / total_tp_llm) * 100
        print(f"  TP:        {tp_delta:+.1f}%")
    p_delta  = metrics_both['precision'] - metrics_llm['precision']
    r_delta  = metrics_both['recall']    - metrics_llm['recall']
    f1_delta = metrics_both['f1_score']  - metrics_llm['f1_score']
    print(f"  Precision: {p_delta:+.1%}")
    print(f"  Recall:    {r_delta:+.1%}")
    print(f"  F1-Score:  {f1_delta:+.4f}")

    # Save report
    report_path = generate_report(
        evaluated=evaluated,
        skipped=skipped,
        failed=failed,
        total_contracts=len(contracts),
        total_tp_both=total_tp_both,
        total_fp_both=total_fp_both,
        total_fn_both=total_fn_both,
        total_tp_llm=total_tp_llm,
        total_fp_llm=total_fp_llm,
        total_fn_llm=total_fn_llm,
        metrics_both=metrics_both,
        metrics_llm=metrics_llm,
        per_cat_both=per_cat_both,
        per_cat_llm=per_cat_llm,
    )
    print(f"\n📄 Report saved to: {report_path}")


if __name__ == "__main__":
    asyncio.run(test_batch())