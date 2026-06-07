"""
Shared utilities for the debate pipeline nodes (critique, verify, tiebreaker).
"""

BATCH_SIZE = 8  # findings per LLM call


def extract_relevant_code(contract_code: str, findings: list[dict], context: int = 5) -> str:
    """
    Return only the contract lines relevant to the given findings, with ±context lines of
    surrounding context and gap indicators between non-contiguous regions.

    This keeps per-batch token counts low for large contracts: instead of sending the full
    contract with every batch call, each batch only receives the lines it actually needs.
    Falls back to the full contract if no findings have line numbers.
    """
    lines = contract_code.splitlines()
    total = len(lines)

    relevant: set[int] = set()
    for f in findings:
        for ln in (f.get("line_numbers") or []):
            if 1 <= ln <= total:
                for i in range(max(0, ln - 1 - context), min(total, ln + context)):
                    relevant.add(i)

    if not relevant:
        return contract_code

    result: list[str] = []
    prev_idx: int | None = None
    for i in sorted(relevant):
        if prev_idx is not None and i > prev_idx + 1:
            result.append(f"// ... (lines {prev_idx + 2}–{i})")
        result.append(f"{i + 1:4d} | {lines[i]}")
        prev_idx = i

    return "\n".join(result)


def format_finding_for_critique(f: dict) -> dict:
    """
    Format a finding for independent critique or verify scoring.
    No snippet truncation — full snippet is included so the model can assess
    the vulnerability conditions accurately from the code.
    """
    return {
        "id":                f.get("id", ""),
        "title":             f.get("title", ""),
        "severity":          f.get("severity", "LOW"),
        "category":          f.get("category", "other"),
        "affected_function": f.get("affected_function", ""),
        "code_snippet":      f.get("affected_code_snippet") or "",
        "line_numbers":      f.get("line_numbers") or [],
    }


def format_finding_for_tiebreaker(f: dict) -> dict:
    """
    Format a finding for tiebreaker arbitration.
    Includes the full snippet and both agents' scores and reasoning so the
    tiebreaker can make an informed code-grounded decision.
    """
    return {
        "id":                f.get("id", ""),
        "title":             f.get("title", ""),
        "severity":          f.get("severity", "LOW"),
        "category":          f.get("category", "other"),
        "affected_function": f.get("affected_function", ""),
        "code_snippet":      f.get("affected_code_snippet") or "",
        "line_numbers":      f.get("line_numbers") or [],
        "critique": {
            "score":    round(float(f.get("critique_score", 0.5)), 2),
            "verdict":  f.get("critique_verdict", "uncertain"),
            "reasoning":f.get("critique_reasoning", ""),
        },
        "verify": {
            "score":    round(float(f.get("verify_score", 0.5)), 2),
            "verdict":  f.get("verify_verdict", "uncertain"),
            "reasoning":f.get("verify_reasoning", ""),
        },
    }


def batch(items: list, size: int = BATCH_SIZE) -> list[list]:
    """Split a list into batches of at most `size` items."""
    return [items[i:i + size] for i in range(0, len(items), size)]
