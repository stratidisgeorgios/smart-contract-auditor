"""
Metrics calculation module for evaluating audit results.

Calculates precision, recall, F1-score, and other evaluation metrics.
"""

from typing import Dict, List, Tuple


def calculate_metrics(tp: int, fp: int, fn: int) -> Dict[str, float]:
    """
    Calculate precision, recall, F1-score from TP, FP, FN.
    
    Args:
        tp: True positives (correct findings)
        fp: False positives (incorrect findings)
        fn: False negatives (missed findings)
    
    Returns:
        Dict with precision, recall, f1_score, and accuracy metrics
    """
    
    # Precision = TP / (TP + FP)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    
    # Recall = TP / (TP + FN)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    # F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
    f1_score = (
        2 * (precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    
    # Accuracy = TP / (TP + FP + FN)
    accuracy = tp / (tp + fp + fn) if (tp + fp + fn) > 0 else 0.0
    
    # False Positive Rate = FP / (FP + TN) - but we don't have TN, so use FP / (TP + FP)
    fpr = fp / (tp + fp) if (tp + fp) > 0 else 0.0
    
    # False Negative Rate = FN / (FN + TP)
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def match_categories(
    detected_category: str,
    ground_truth_category: str,
) -> bool:
    """
    Check if detected category matches ground truth category with leniency.
    
    Handles variations in category naming and SWC ID matching.
    
    Args:
        detected_category: Category from auditor (e.g., "Reentrancy")
        ground_truth_category: Category from ground truth (e.g., "reentrancy")
    
    Returns:
        True if categories match (with leniency), False otherwise
    """
    
    # Normalize to lowercase and replace spaces with underscores for comparison
    detected_lower = detected_category.lower().strip().replace(" ", "_").replace("-", "_")
    truth_lower = ground_truth_category.lower().strip().replace(" ", "_").replace("-", "_")
    
    # Exact match (after normalization)
    if detected_lower == truth_lower:
        return True
    
    # Mapping of possible category variations
    category_aliases = {
        "reentrancy": [
            "reentrancy", "reentrant", 
            "reentrancy_eth", "reentrancy-eth",
            "reentrancy_no_eth", "reentrancy-no-eth",
            "reentrancy_all", "reentrancy-all",
            "cross_function_reentrancy", "cross-function-reentrancy",
        ],
        "arithmetic": [
            "arithmetic", 
            "integer_overflow", "integer-overflow",
            "integer_underflow", "integer-underflow",
            "overflow", "underflow"
        ],
        "access_control": [
            "access_control", "access-control", "accesscontrol",
            "tx_origin", "tx-origin", "txorigin",
            "shadowing_state", "shadowing-state",
            "shadowing",
            "unprotected_selfdestruct", "unprotected-selfdestruct",
            "unprotected_self_destruct", "unprotected-self-destruct",
            "suicide", "selfdestruct", "self-destruct"
        ],
        "unchecked_low_level_calls": [
            "unchecked_low_level_calls", "unchecked-low-level-calls",
            "unchecked_lowlevel", "unchecked-lowlevel",
            "unchecked_call", "unchecked-call",
            "unchecked", 
            "low_level", "low-level",
            "arbitrary_send", "arbitrary-send",
            "arbitrary_send_eth", "arbitrary-send-eth",
            "unchecked_return_values", "unchecked-return-values",
            "unchecked_return", "unchecked-return",
            "low_level_calls", "low-level-calls"
        ],
        "denial_of_service": [
            "denial_of_service", "denial-of-service",
            "dos",
            "incorrect_modifier", "incorrect-modifier",
            "controlled_array_length", "controlled-array-length"
        ],
        "bad_randomness": [
            "bad_randomness", "bad-randomness",
            "randomness",
            "weak_prng", "weak-prng"
        ],
        "front_running": [
            "front_running", "front-running",
            "front_run", "front-run"
        ],
        "time_manipulation": [
            "time_manipulation", "time-manipulation",
            "timestamp",
            "deprecated_standards", "deprecated-standards",
            "timestamp_dependence", "timestamp-dependence"
        ],
        "short_addresses": [
            "short_address", "short-address",
            "short_addresses", "short-addresses",
            "shortaddress"
        ],
        "other": [
            "naming_convention", "naming-convention",
            "solc_version", "solc-version",
            "missing_zero_check", "missing-zero-check",
            "external_function", "external-function",
            "locked_ether", "locked-ether",
            "constable_states", "constable-states"
        ],
    }
    
    # Check if both belong to same category group
    for category_key, aliases in category_aliases.items():
        if (detected_lower in aliases) and (truth_lower in aliases):
            return True
    
    return False


def match_line_numbers(
    detected_lines: List[int],
    ground_truth_lines: List[int],
    tolerance: int = 5,
) -> Tuple[int, List[int]]:
    """
    Match detected line numbers with ground truth line numbers within tolerance.
    
    Args:
        detected_lines: Line numbers from auditor
        ground_truth_lines: Line numbers from ground truth
        tolerance: Number of lines to allow variance (default 5)
    
    Returns:
        Tuple of (matches_count, matched_lines)
    """
    
    if not detected_lines or not ground_truth_lines:
        return (0, [])
    
    matched_lines = []
    
    for truth_line in ground_truth_lines:
        # Check if any detected line is within tolerance of this truth line
        for detected_line in detected_lines:
            if abs(detected_line - truth_line) <= tolerance:
                matched_lines.append(detected_line)
                break
    
    return (len(matched_lines), matched_lines)


def aggregate_metrics(
    per_category_results: Dict[str, Dict],
) -> Dict:
    """
    Aggregate metrics from individual categories into overall metrics.
    
    Args:
        per_category_results: Dict of category → metrics dict
    
    Returns:
        Overall aggregated metrics
    """
    
    total_tp = 0
    total_fp = 0
    total_fn = 0
    
    for category, metrics in per_category_results.items():
        total_tp += metrics.get("tp", 0)
        total_fp += metrics.get("fp", 0)
        total_fn += metrics.get("fn", 0)
    
    return calculate_metrics(total_tp, total_fp, total_fn)


def generate_summary_report(
    overall_metrics: Dict,
    per_category_metrics: Dict,
    failed_contracts: List[str],
    total_contracts: int,
) -> str:
    """
    Generate a human-readable summary report.
    
    Args:
        overall_metrics: Overall evaluation metrics
        per_category_metrics: Per-category evaluation metrics
        failed_contracts: List of contracts that failed to audit
        total_contracts: Total number of contracts tested
    
    Returns:
        Formatted report string
    """
    
    report = []
    report.append("╔════════════════════════════════════════════════════════╗")
    report.append("║      Smart Contract Auditor - Evaluation Results       ║")
    report.append("╚════════════════════════════════════════════════════════╝")
    report.append("")
    
    # Overall statistics
    report.append("📊 OVERALL STATISTICS")
    report.append("─" * 54)
    report.append(f"Total Contracts Tested:  {total_contracts}")
    report.append(f"Successful Audits:       {total_contracts - len(failed_contracts)}")
    report.append(f"Failed Audits:           {len(failed_contracts)}")
    report.append("")
    
    # Overall metrics
    report.append("📈 OVERALL METRICS")
    report.append("─" * 54)
    report.append(f"Precision:               {overall_metrics['precision']:.2%}")
    report.append(f"Recall:                  {overall_metrics['recall']:.2%}")
    report.append(f"F1-Score:                {overall_metrics['f1_score']:.2%}")
    report.append(f"Accuracy:                {overall_metrics['accuracy']:.2%}")
    report.append("")
    report.append(f"True Positives:          {overall_metrics['tp']}")
    report.append(f"False Positives:         {overall_metrics['fp']}")
    report.append(f"False Negatives:         {overall_metrics['fn']}")
    report.append("")
    
    # Per-category metrics
    report.append("🔍 BY CATEGORY")
    report.append("─" * 54)
    
    # Sort by F1-score descending
    sorted_categories = sorted(
        per_category_metrics.items(),
        key=lambda x: x[1].get("f1_score", 0),
        reverse=True
    )
    
    for category, metrics in sorted_categories:
        if metrics.get("tp", 0) == 0 and metrics.get("fp", 0) == 0 and metrics.get("fn", 0) == 0:
            continue  # Skip categories with no data
        
        report.append(
            f"{category.upper():20} | "
            f"P: {metrics['precision']:.1%} | "
            f"R: {metrics['recall']:.1%} | "
            f"F1: {metrics['f1_score']:.1%}"
        )
    
    report.append("")
    
    # Failed contracts
    if failed_contracts:
        report.append("❌ FAILED CONTRACTS")
        report.append("─" * 54)
        for contract in sorted(failed_contracts)[:20]:  # Show first 20
            report.append(f"  • {contract}")
        if len(failed_contracts) > 20:
            report.append(f"  ... and {len(failed_contracts) - 20} more")
        report.append("")
    
    return "\n".join(report)