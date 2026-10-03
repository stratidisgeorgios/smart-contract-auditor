import json
import logging
import os
import re

from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from pipeline.state import AuditState
from pipeline import langfuse_client

logger = logging.getLogger(__name__)

# Model configuration 
LLM_MODEL       = "meta-llama/llama-4-scout-17b-16e-instruct"
LLM_TEMPERATURE = 0.1
LLM_MAX_TOKENS  = 4096


def _extract_json(raw: str) -> dict:
    """
    Parse the JSON object from the LLM response.
    It handles two common failure modes:
      1. Markdown fences (```json ... ```)
      2. Truncated JSON —> missing 1-2 closing braces at the end
         (model stopped generating mid-output due to token limit or rate limit)
    """
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    start = cleaned.find("{")
    if start == -1:
        raise ValueError("No JSON object found in LLM response")

    candidate = cleaned[start:]

  
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    # Repair attempt: check if braces are unbalanced (truncation)
    open_b  = candidate.count("{")
    close_b = candidate.count("}")
    missing = open_b - close_b

    if 0 < missing <= 3:
        repaired = candidate + "}" * missing
        try:
            result = json.loads(repaired)
            logger.warning(
                "[LLM] JSON was truncated — added %d missing closing brace(s) and recovered.",
                missing,
            )
            return result
        except json.JSONDecodeError:
            pass


    end = candidate.rfind("}") + 1
    return json.loads(candidate[:end] if end > 0 else candidate)


# Line number resolution 

def _resolve_lines_from_snippet(contract_code: str, snippet: str) -> list[int]:
    """
    Strategy 1: search for the most distinctive line of the snippet in the contract. Tries candidates from longest to shortest —> stops at the first match.
    """
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
    """
    Strategy 2: find all lines belonging to a named function. Walks from the function declaration to its matching closing brace.
    """
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
        result.append(i + 1)        # 1-based
        if depth > 0:
            entered = True          # seen the opening brace
        if entered and depth <= 0:
            break                   # back to zero after opening → function done
    return result


def _resolve_all_snippets(contract_code: str, vulns: list[dict]) -> None:
    """
    For each vulnerability, we derive reliable line numbers using three strategies:

      1. Snippet search  — > search affected_code_snippet verbatim in the source.
                            Works when the LLM copies code correctly .
      2. Function range   —> find the full body of affected_function.
                            Works when the snippet is hallucinated but the function
                            name is correct (common with 8b model).
      3. Range filter     —> strip line numbers beyond the contract's actual length.
                            Last resort; at least avoids impossible line numbers.
    """
    total_lines = len(contract_code.splitlines())

    for vuln in vulns:
        vid      = vuln.get("id", "?")
        original = list(vuln.get("line_numbers", []))
        snippet  = vuln.get("affected_code_snippet", "")
        fn_name  = vuln.get("affected_function", "")

        # Strategy 1 —> snippet
        found = _resolve_lines_from_snippet(contract_code, snippet)
        if found:
            vuln["line_numbers"] = found
            if found != original:
                logger.info("[LLM] %s [snippet]  %s → %s", vid, original, found)
            continue

        # Strategy 2 —> function body range
        found = _find_function_body_lines(contract_code, fn_name)
        if found:
            vuln["line_numbers"] = found
            logger.info("[LLM] %s [fn:%s]  %s → lines %d..%d",
                        vid, fn_name, original, found[0], found[-1])
            continue

        # Strategy 3 — >filter impossible lines
        valid = [l for l in original if 1 <= l <= total_lines]
        if valid != original:
            vuln["line_numbers"] = valid
            logger.warning("[LLM] %s [trim]  %s → %s  (contract has %d lines)",
                           vid, original, valid, total_lines)
        else:
            logger.warning("[LLM] %s [no match]  snippet not found, fn '%s' not found, "
                           "keeping %s", vid, fn_name, original)


# Main node

def run_llm_node(state: AuditState) -> AuditState:
    logger.info("[LLM] Starting analysis — %s", state["contract_name"])
    errors = list(state.get("errors", []))

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        msg = "GROQ_API_KEY not set"
        logger.error("[LLM] %s", msg)
        errors.append(msg)
        return {**state, "llm_report": None, "errors": errors}

    try:
        # get_prompt returns the text; get_prompt_obj returns the Langfuse object used to link the generation to the prompt in the UI 
        system_prompt = langfuse_client.get_prompt("audit-system-prompt")

        llm = ChatGroq(
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            api_key=api_key,
            max_tokens=LLM_MAX_TOKENS,
        )

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(
                content=(
                    f"Audit the following Solidity smart contract "
                    f"(filename: {state['contract_name']}):\n\n"
                    f"```solidity\n{state['contract_code']}\n```"
                )
            ),
        ]

       
        prompt_obj = langfuse_client.get_prompt_obj("audit-system-prompt")
        callback = langfuse_client.get_callback(
            trace_name="audit-llm-analysis",
            contract_name=state["contract_name"],
            metadata={"model": LLM_MODEL, "node": "llm_analysis"},
        )
        if callback is not None and prompt_obj is not None:
            try:
                callback.prompt = prompt_obj  
            except Exception:
                pass
        invoke_config = {"callbacks": [callback]} if callback else {}

        logger.info("[LLM] Sending to Groq (%s)…", LLM_MODEL)
        response = llm.invoke(messages, config=invoke_config)

        parsed = _extract_json(response.content)
        vulns  = parsed.get("llm_analysis", {}).get("vulnerabilities", [])

        # Derive reliable line numbers (because LLM line counting is unreliable)
        _resolve_all_snippets(state["contract_code"], vulns)

        logger.info("[LLM] Done — %d vulnerabilities found", len(vulns))
        logger.debug("LLM OUTPUT\n%s", json.dumps(parsed, indent=2, ensure_ascii=False))

        return {**state, "llm_report": parsed}

    except json.JSONDecodeError as exc:
        raw = locals().get("response", None)
        raw_text = getattr(raw, "content", "") if raw else ""

      
        if raw_text:
            last_chars = raw_text.strip()[-80:]
          
            open_b    = raw_text.count("{")
            close_b   = raw_text.count("}")
            is_truncated = open_b > close_b
            logger.error("[LLM] ✗ Invalid JSON — %s", exc)
            if is_truncated:
                logger.error(
                    "[LLM]   CAUSE: TRUNCATED — missing %d closing brace(s). "
                    "Repair was attempted but failed. "
                    "Increase LLM_MAX_TOKENS (currently %d) or shorten the contract.",
                    open_b - close_b, LLM_MAX_TOKENS,
                )
            else:
                logger.error("[LLM]   CAUSE: Malformed JSON (balanced braces — genuine parse error).")
            logger.error("[LLM]   Raw response length: %d chars | braces: {%d }%d",
                         len(raw_text), open_b, close_b)
            logger.error("[LLM]   Last 80 chars: %r", last_chars)
        else:
            logger.error("[LLM] ✗ Invalid JSON (no raw response available): %s", exc)

        msg = f"LLM returned invalid JSON: {exc}"
        errors.append(msg)
        return {**state, "llm_report": None, "errors": errors}

    except Exception as exc:
        exc_type = type(exc).__name__
        exc_str  = str(exc)

        # Groq specific error diagnosis 
        if "rate_limit" in exc_str.lower() or "429" in exc_str or "RateLimit" in exc_type:
            logger.error(
                "[LLM] ✗ RATE LIMIT HIT — Groq rejected the request (429). "
                "Increase DELAY_BETWEEN_CONTRACTS in test_smartbugs.py. "
                "Details: %s", exc_str[:300],
            )
        elif "tokens_per_min" in exc_str.lower() or "tpm" in exc_str.lower():
            logger.error(
                "[LLM] ✗ TOKENS PER MINUTE limit exceeded. "
                "Increase DELAY_BETWEEN_CONTRACTS. Details: %s", exc_str[:300],
            )
        elif "tokens_per_day" in exc_str.lower() or "tpd" in exc_str.lower() or "daily" in exc_str.lower():
            logger.error(
                "[LLM] ✗ DAILY TOKEN LIMIT exceeded — evaluation must stop for today. "
                "Reduce MAX_CONTRACTS or switch to a model with higher TPD limit. "
                "Details: %s", exc_str[:300],
            )
        elif "requests_per_min" in exc_str.lower() or "rpm" in exc_str.lower():
            logger.error(
                "[LLM] ✗ REQUESTS PER MINUTE limit exceeded. "
                "Increase DELAY_BETWEEN_CONTRACTS. Details: %s", exc_str[:300],
            )
        elif "connection" in exc_str.lower() or "timeout" in exc_str.lower():
            logger.error(
                "[LLM] ✗ NETWORK ERROR (%s): %s", exc_type, exc_str[:300],
            )
        elif "context_length" in exc_str.lower() or "maximum context" in exc_str.lower():
            logger.error(
                "[LLM] ✗ CONTEXT LENGTH EXCEEDED — contract is too long for this model. "
                "Details: %s", exc_str[:300],
            )
        else:
            logger.exception("[LLM] ✗ Unexpected error (%s): %s", exc_type, exc_str[:300])

        msg = f"LLM node error [{exc_type}]: {exc_str[:200]}"
        errors.append(msg)
        return {**state, "llm_report": None, "errors": errors}