"""
LLM node — detection pass: find all vulnerabilities, resolve line numbers.
Uses _invoke_llm for TPM-safe Groq calls with retry logic.
"""

import json
import logging
import os
import re
import time
from typing import Optional

from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from pipeline.state import AuditState
from pipeline import langfuse_client

logger = logging.getLogger(__name__)

LLM_MODEL_SMALL     = "llama-3.1-8b-instant"                       # detect ≤200 lines: 6K TPM
LLM_MODEL_LARGE     = "meta-llama/llama-4-scout-17b-16e-instruct"  # detect >200 lines + all debate nodes: 30K TPM
LLM_MODEL_DEBATE    = LLM_MODEL_LARGE                              # critique/verify/tiebreaker always use this
LLM_LINES_THRESHOLD = 200
LLM_TEMPERATURE     = 0.1
LLM_MAX_TOKENS      = 4096


def _select_model(contract_code: str) -> str:
    """Return the appropriate model based on contract size."""
    return (
        LLM_MODEL_LARGE
        if len(contract_code.splitlines()) > LLM_LINES_THRESHOLD
        else LLM_MODEL_SMALL
    )


# ── Per-node API keys ─────────────────────────────────────────────────────────
# Each pipeline node uses a dedicated Groq key so their TPM buckets never overlap.
# Falls back to GROQ_API_KEY if the node-specific var is not set.

def _api_key(env_var: str = "GROQ_API_KEY") -> Optional[str]:
    return os.getenv(env_var) or os.getenv("GROQ_API_KEY")


# ── Shared helpers ────────────────────────────────────────────────────────────

TPM_MAX_RETRIES = 2  # 2 × 65s = 130s covers two full TPM windows; more than enough


def _invoke_llm(
    messages: list,
    invoke_config: dict,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    caller: str = "llm",
) -> str:
    """
    Call the LLM. On a per-minute token limit (TPM, Groq 413) wait 65s and retry
    up to TPM_MAX_RETRIES times. All other errors are re-raised immediately.
    Pass api_key explicitly so each node can use its own dedicated Groq key.
    Pass model to override the default (used for large-contract routing).
    Pass caller for log attribution (e.g. "detect", "critique", "verify", "tiebreaker").
    """
    api_key = api_key or _api_key()
    if not api_key:
        raise RuntimeError("GROQ_API_KEY not set.")
    model = model or LLM_MODEL_SMALL

    tpm_retries = 0
    while True:
        try:
            llm = ChatGroq(
                model=model,
                temperature=LLM_TEMPERATURE,
                api_key=api_key,
                max_tokens=LLM_MAX_TOKENS,
            )
            return llm.invoke(messages, config=invoke_config).content
        except Exception as exc:
            exc_str = str(exc)
            is_tpm = (
                ("413" in exc_str and "tpm" in exc_str.lower())
                or "tokens_per_min" in exc_str.lower()
            )
            if is_tpm:
                tpm_retries += 1
                if tpm_retries > TPM_MAX_RETRIES:
                    raise RuntimeError(
                        f"TPM rate limit persists after {TPM_MAX_RETRIES} retries — "
                        "increase DELAY_BETWEEN_CONTRACTS."
                    ) from exc
                logger.warning(
                    "[%s] TPM rate limit (413) — waiting 65s… (retry %d/%d)",
                    caller, tpm_retries, TPM_MAX_RETRIES,
                )
                time.sleep(65)
                continue
            raise


def _extract_json(raw: str) -> dict:
    """
    Parse the JSON object from a raw LLM response string.
    Handles common 8b model failure modes:
      1. Markdown fences (```json ... ```)
      2. Truncated JSON — missing 1-3 closing braces
      3. Literal newlines inside string values (replace with \\n)
      4. Unescaped single/double quotes inside string values
    """
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    start = cleaned.find("{")
    if start == -1:
        raise ValueError("No JSON object found in LLM response")
    candidate = cleaned[start:]

    # Attempt 1: parse as-is
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    # Attempt 2: add missing closing braces (truncation)
    open_b  = candidate.count("{")
    close_b = candidate.count("}")
    missing = open_b - close_b
    if 0 < missing <= 3:
        repaired = candidate + "}" * missing
        try:
            result = json.loads(repaired)
            logger.warning("[LLM] JSON truncated — added %d missing brace(s) and recovered.", missing)
            return result
        except json.JSONDecodeError:
            pass

    # Attempt 3: replace literal newlines inside strings with \n escape
    # This fixes the most common 8b model failure: multi-line string values
    def _escape_newlines_in_strings(text: str) -> str:
        result = []
        in_string = False
        escape_next = False
        for ch in text:
            if escape_next:
                result.append(ch)
                escape_next = False
            elif ch == "\\":
                result.append(ch)
                escape_next = True
            elif ch == '"':
                in_string = not in_string
                result.append(ch)
            elif in_string and ch == "\n":
                result.append("\\n")
            elif in_string and ch == "\r":
                result.append("\\r")
            else:
                result.append(ch)
        return "".join(result)

    escaped = _escape_newlines_in_strings(candidate)
    try:
        return json.loads(escaped)
    except json.JSONDecodeError:
        pass

    # Attempt 4: truncate at the last complete top-level closing brace
    end = candidate.rfind("}") + 1
    return json.loads(candidate[:end] if end > 0 else candidate)


def _extract_contract_info(code: str, contract_name: str) -> dict:
    """Extract contract metadata from source without calling the LLM."""
    lines = code.splitlines()
    version_match = re.search(r"pragma\s+solidity\s+([^;]+)", code)
    version = version_match.group(1).strip() if version_match else "unknown"
    contract_names = re.findall(r"\bcontract\s+(\w+)", code)
    return {
        "solidity_version": version,
        "contract_names": contract_names or [contract_name.replace(".sol", "")],
        "total_lines": len(lines),
    }


# ── Chunking helpers ─────────────────────────────────────────────────────────



# ── Line-number resolution helpers (unchanged logic from original llm_node) ───

def _resolve_lines_from_snippet(contract_code: str, snippet) -> list[int]:
    """Search for the most distinctive line of the snippet in the contract."""
    if isinstance(snippet, list):
        snippet = "\n".join(str(s) for s in snippet)
    if not snippet or not snippet.strip():
        return []
    contract_lines = contract_code.splitlines()
    candidates = [
        " ".join(part.split())
        for part in snippet.strip().splitlines()
        if len(part.strip()) >= 10
    ]
    if not candidates:
        return []
    for target in sorted(candidates, key=len, reverse=True):
        found = [i for i, line in enumerate(contract_lines, 1)
                 if target in " ".join(line.split())]
        if found:
            return found
    return []


def _find_function_body_lines(contract_code: str, function_name: str) -> list[int]:
    """Return all 1-based line numbers belonging to a named function."""
    if not function_name or function_name.lower() in ("contract-level", ""):
        return []
    lines = contract_code.splitlines()
    pattern = re.compile(rf'\bfunction\s+{re.escape(function_name)}\b')
    start = next((i for i, l in enumerate(lines) if pattern.search(l)), None)
    if start is None:
        return []
    depth, entered, result = 0, False, []
    for i, line in enumerate(lines[start:], start):
        depth += line.count('{') - line.count('}')
        result.append(i + 1)
        if depth > 0:
            entered = True
        if entered and depth <= 0:
            break
    return result


def _dedup_llm_findings(findings: list[dict]) -> list[dict]:
    """
    Remove duplicate LLM findings: same category at overlapping line numbers (±3).
    Keeps the first occurrence. Prevents a single root-cause being reported twice,
    which would pass the debate pipeline as 1 TP + 1 FP.
    """
    seen: list[tuple[str, set]] = []
    result: list[dict] = []
    for f in findings:
        cat = f.get("category", "").lower()
        lines = set(f.get("line_numbers") or [])
        dup = False
        for seen_cat, seen_lines in seen:
            if seen_cat != cat:
                continue
            if not lines or not seen_lines:
                dup = True
                break
            if lines & seen_lines or any(abs(a - b) <= 3 for a in lines for b in seen_lines):
                dup = True
                break
        if dup:
            logger.info("[LLM:detect] Dedup dropped duplicate %s@%s", cat, sorted(lines))
        else:
            seen.append((cat, lines))
            result.append(f)
    return result


def _resolve_all_snippets(contract_code: str, vulns: list[dict]) -> None:
    """
    Fix line numbers for every finding using a three-strategy cascade:
      1. Snippet search  — verbatim match in source
      2. Function range  — walk function body by brace counting
      3. Range filter    — strip line numbers beyond contract length
    """
    total_lines = len(contract_code.splitlines())
    for vuln in vulns:
        vid      = vuln.get("id", "?")
        original = list(vuln.get("line_numbers") or [])
        snippet  = vuln.get("affected_code_snippet", "")
        fn_name  = vuln.get("affected_function", "")

        found = _resolve_lines_from_snippet(contract_code, snippet)
        if found:
            vuln["line_numbers"] = found
            if found != original:
                logger.info("[LLM] %s [snippet]  %s → %s", vid, original, found)
            continue

        found = _find_function_body_lines(contract_code, fn_name)
        if found:
            vuln["line_numbers"] = found
            logger.info("[LLM] %s [fn:%s]  %s → lines %d..%d",
                        vid, fn_name, original, found[0], found[-1])
            continue

        valid = [l for l in original if 1 <= l <= total_lines]
        if valid != original:
            vuln["line_numbers"] = valid
            logger.warning("[LLM] %s [trim]  %s → %s  (contract has %d lines)",
                           vid, original, valid, total_lines)
        else:
            logger.warning("[LLM] %s [no match] snippet not found, fn '%s' not found, keeping %s",
                           vid, fn_name, original)


# ── Error logging helper ──────────────────────────────────────────────────────

def _log_llm_error(label: str, exc: Exception) -> None:
    exc_type = type(exc).__name__
    exc_str  = str(exc)
    if "rate_limit" in exc_str.lower() or "429" in exc_str or "RateLimit" in exc_type:
        logger.error("[LLM] %s ✗ RATE LIMIT (429) — increase DELAY_BETWEEN_CONTRACTS. %s", label, exc_str[:200])
    elif "tokens_per_min" in exc_str.lower() or "tpm" in exc_str.lower():
        logger.error("[LLM] %s ✗ TOKENS/MIN exceeded — increase DELAY_BETWEEN_CONTRACTS. %s", label, exc_str[:200])
    elif "requests_per_min" in exc_str.lower() or "rpm" in exc_str.lower():
        logger.error("[LLM] %s ✗ REQUESTS/MIN exceeded. %s", label, exc_str[:200])
    elif "connection" in exc_str.lower() or "timeout" in exc_str.lower():
        logger.error("[LLM] %s ✗ NETWORK ERROR (%s): %s", label, exc_type, exc_str[:200])
    elif "context_length" in exc_str.lower() or "maximum context" in exc_str.lower():
        logger.error("[LLM] %s ✗ CONTEXT LENGTH EXCEEDED. %s", label, exc_str[:200])
    else:
        logger.exception("[LLM] %s ✗ Unexpected error (%s): %s", label, exc_type, exc_str[:200])


# ── Node 1: Detection ─────────────────────────────────────────────────────────

def run_llm_detect_node(state: AuditState) -> AuditState:
    """
    Detection pass — sends the full contract to the LLM in a single call.
    Selects llama-4-scout-17b (30K TPM) for contracts over 200 lines so that
    large contracts don't exhaust the 6K TPM budget of llama-3.1-8b-instant.
    """
    logger.info("[LLM:detect] Starting — %s", state["contract_name"])
    errors = list(state.get("errors", []))

    if not _api_key():
        msg = "GROQ_API_KEY not set"
        logger.error("[LLM:detect] %s", msg)
        errors.append(msg)
        return {**state, "llm_detection_findings": [], "contract_info": None, "errors": errors}

    model         = _select_model(state["contract_code"])
    system_prompt = langfuse_client.get_prompt("audit-detect-prompt")
    contract_info = _extract_contract_info(state["contract_code"], state["contract_name"])
    total_lines   = len(state["contract_code"].splitlines())

    if model != LLM_MODEL_SMALL:
        logger.info("[LLM:detect] Large contract (%d lines) — using %s", total_lines, model)

    prompt_obj = langfuse_client.get_prompt_obj("audit-detect-prompt")
    callback = langfuse_client.get_callback(
        trace_name="audit-detect",
        contract_name=state["contract_name"],
        metadata={"model": model, "node": "llm_detect", "total_lines": total_lines},
    )
    if callback is not None and prompt_obj is not None:
        try:
            callback.prompt = prompt_obj
        except Exception:
            pass
    invoke_config = {"callbacks": [callback]} if callback else {}

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=(
            f"Audit the following Solidity smart contract "
            f"(filename: {state['contract_name']}):\n\n"
            f"```solidity\n{state['contract_code']}\n```"
        )),
    ]

    try:
        raw      = _invoke_llm(messages, invoke_config, api_key=_api_key("GROQ_API_KEY"), model=model, caller="detect")
        finished_at = time.time()
        parsed   = _extract_json(raw)
        findings = parsed.get("vulnerabilities", [])

        findings = _dedup_llm_findings(findings)

        for i, f in enumerate(findings):
            f["id"] = f"LLM-{i + 1:03d}"

        _resolve_all_snippets(state["contract_code"], findings)

        # Second dedup pass: resolution can map different raw line numbers to the same
        # function body, creating identical findings that pre-resolution dedup missed.
        findings = _dedup_llm_findings(findings)
        for i, f in enumerate(findings):
            f["id"] = f"LLM-{i + 1:03d}"

        logger.info("[LLM:detect] Done — %d findings", len(findings))
        return {
            **state,
            "llm_detection_findings": findings,
            "contract_info": contract_info,
            "detect_finished_at": finished_at,
            "errors": errors,
        }

    except json.JSONDecodeError as exc:
        msg = f"LLM detect node: invalid JSON — {exc}"
        logger.error("[LLM:detect] %s", msg)
        errors.append(msg)
        return {**state, "llm_detection_findings": [], "contract_info": contract_info,
                "detect_finished_at": time.time(), "errors": errors}

    except Exception as exc:
        _log_llm_error("detect", exc)
        msg = f"LLM detect node error [{type(exc).__name__}]: {str(exc)[:200]}"
        errors.append(msg)
        return {**state, "llm_detection_findings": [], "contract_info": contract_info,
                "detect_finished_at": time.time(), "errors": errors}


