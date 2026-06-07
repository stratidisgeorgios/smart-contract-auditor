"""
Tiebreaker node — neutral final arbiter.

Receives findings where critique and verify DISAGREED (uncertain_findings).
Each finding already carries both agents' scores and reasoning.

Gets the full contract code so it can apply category rules directly from the
code, rather than deferring to the agents. Makes binary confirmed/rejected
decisions — uncertain is NOT an option.

Uses GROQ_API_KEY (shared with detect; runs after several sequential nodes so
the detect TPM window has long since cleared).
"""

import json
import logging
import os
import time

from langchain_core.messages import SystemMessage, HumanMessage

from pipeline.state import AuditState
from pipeline import langfuse_client
from pipeline.nodes.debate_utils import batch, format_finding_for_tiebreaker, extract_relevant_code, BATCH_SIZE
from pipeline.nodes.llm_node import LLM_MODEL_DEBATE

logger = logging.getLogger(__name__)

LLM_TEMPERATURE = 0.1


def _api_key() -> str:
    return os.getenv("GROQ_API_KEY") or ""


def _invoke(messages: list, invoke_config: dict, model: str | None = None) -> str:
    from pipeline.nodes.llm_node import _invoke_llm
    return _invoke_llm(messages, invoke_config, api_key=_api_key(), model=model, caller="tiebreaker")


def _extract_json(raw: str) -> dict:
    from pipeline.nodes.llm_node import _extract_json as _ej
    return _ej(raw)


def _decide_batch(
    findings_batch: list[dict],
    contract_code: str,
    contract_name: str,
    system_prompt: str,
    invoke_config: dict,
    model: str | None = None,
) -> dict[str, dict]:
    """Decide one batch. Returns {finding_id: decision_dict}.
    Sends only the code lines relevant to this batch (±10 context lines)."""
    findings_text = json.dumps(
        [format_finding_for_tiebreaker(f) for f in findings_batch],
        indent=2,
    )
    relevant_code = extract_relevant_code(contract_code, findings_batch)

    human_content = (
        f"Contract filename: {contract_name}\n\n"
        f"Relevant contract code (line-numbered, gaps indicated):\n"
        f"```solidity\n{relevant_code}\n```\n\n"
        f"These findings had disagreeing scores from two independent agents.\n"
        f"Each finding shows both agents' scores and reasoning.\n"
        f"Use the contract code above to make your own evidence-based decision.\n"
        f"confirmed or rejected — no uncertain allowed.\n\n"
        f"{findings_text}"
    )

    messages = [SystemMessage(content=system_prompt), HumanMessage(content=human_content)]
    raw    = _invoke(messages, invoke_config, model=model)
    parsed = _extract_json(raw)
    return {d["id"]: d for d in parsed.get("decisions", []) if "id" in d}


_TIEBREAKER_KEY_CLEAR_SECS = 65.0  # detect + tiebreaker share KEY1; wait until TPM bucket clears


def run_tiebreaker_node(state: AuditState) -> AuditState:
    """
    Neutral arbiter. Processes uncertain findings in batches.
    Gets the full contract code + both agents' assessments per finding.

    Waits until at least _TIEBREAKER_KEY_CLEAR_SECS have elapsed since the
    detect call completed, because both nodes share GROQ_API_KEY.
    """
    logger.info("[Tiebreaker] Starting — %s", state["contract_name"])
    errors = list(state.get("errors", []))

    uncertain_findings = state.get("uncertain_findings", [])

    if not uncertain_findings:
        logger.info("[Tiebreaker] No uncertain findings — skipping")
        return state

    # Guard: tiebreaker shares GROQ_API_KEY with detect — wait until detect's window clears
    detect_finished_at = state.get("detect_finished_at")
    if detect_finished_at is not None:
        elapsed = time.time() - detect_finished_at
        wait_needed = _TIEBREAKER_KEY_CLEAR_SECS - elapsed
        if wait_needed > 0:
            logger.info(
                "[Tiebreaker] Waiting %.0fs for KEY1 TPM window to clear "
                "(detect finished %.0fs ago)…",
                wait_needed, elapsed,
            )
            time.sleep(wait_needed)

    model         = LLM_MODEL_DEBATE
    system_prompt = langfuse_client.get_prompt("audit-tiebreaker-prompt")
    callback = langfuse_client.get_callback(
        trace_name="audit-tiebreaker",
        contract_name=state["contract_name"],
        metadata={"model": model, "node": "tiebreaker"},
    )
    invoke_config = {"callbacks": [callback]} if callback else {}

    batch_size = len(uncertain_findings)  # always single call — debate model has 30K TPM
    batches = batch(uncertain_findings, size=batch_size)
    all_decisions: dict[str, dict] = {}

    logger.info("[Tiebreaker] Deciding %d finding(s) in %d batch(es) (model: %s)",
                len(uncertain_findings), len(batches), model)

    try:
        for i, b in enumerate(batches):
            logger.info("[Tiebreaker] Batch %d/%d (%d findings)…", i + 1, len(batches), len(b))
            decisions = _decide_batch(
                b, state["contract_code"], state["contract_name"],
                system_prompt, invoke_config, model=model,
            )
            all_decisions.update(decisions)

        confirmed = list(state.get("confirmed_findings", []))
        tb_confirmed = 0

        for f in uncertain_findings:
            fid      = f.get("id", "")
            decision = all_decisions.get(fid, {})
            verdict  = decision.get("verdict", "rejected")
            reasoning= decision.get("final_reasoning", "")

            logger.info("[Tiebreaker] %s  verdict=%s  %s", fid, verdict, reasoning[:80])

            if verdict == "confirmed":
                confirmed.append({**f, "tiebreaker_reasoning": reasoning})
                tb_confirmed += 1
            else:
                logger.info("[Tiebreaker] %s  REJECTED", fid)

        logger.info(
            "[Tiebreaker] Done — confirmed:%d  rejected:%d",
            tb_confirmed,
            len(uncertain_findings) - tb_confirmed,
        )

        return {
            **state,
            "confirmed_findings": confirmed,
            "uncertain_findings":  [],
            "errors":              errors,
        }

    except Exception as exc:
        from pipeline.nodes.llm_node import _log_llm_error
        _log_llm_error("tiebreaker", exc)
        errors.append(f"Tiebreaker node failed: {str(exc)[:150]}")
        # On failure: drop uncertain findings to avoid polluting the report
        return {**state, "uncertain_findings": [], "errors": errors}
