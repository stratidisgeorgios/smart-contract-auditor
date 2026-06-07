"""
Verify node — defender agent.

Scores ALL findings INDEPENDENTLY against the full contract code.
Does NOT see critique's scores or reasoning during scoring — this is intentional
so both agents give unbiased, independent assessments.

After scoring, compares verify scores vs critique scores (from state["all_findings_to_review"])
and routes each finding to one of two outcomes:

  AUTO-CONFIRMED  — both agents score >= category confirm threshold → straight to confirmed_findings
  TIEBREAKER      — everything else → uncertain_findings for tiebreaker arbitration
                    (no auto-reject: removing findings silently hurts recall)

Uses GROQ_API_KEY_3.
"""

import json
import logging
import os
import time

from langchain_core.messages import SystemMessage, HumanMessage

from pipeline.state import AuditState
from pipeline import langfuse_client
from pipeline.nodes.debate_utils import batch, format_finding_for_critique, extract_relevant_code, BATCH_SIZE
from pipeline.nodes.llm_node import LLM_MODEL_DEBATE
from pipeline.constants import CRITIQUE_CATEGORY_REJECT, CRITIQUE_CATEGORY_CONFIRM

logger = logging.getLogger(__name__)

LLM_TEMPERATURE = 0.1

_DEFAULT_REJECT  = 0.35
_DEFAULT_CONFIRM = 0.70


def _api_key() -> str:
    return os.getenv("GROQ_API_KEY_3") or ""


def _invoke(messages: list, invoke_config: dict, model: str | None = None) -> str:
    from pipeline.nodes.llm_node import _invoke_llm
    return _invoke_llm(messages, invoke_config, api_key=_api_key(), model=model, caller="verify")


def _extract_json(raw: str) -> dict:
    from pipeline.nodes.llm_node import _extract_json as _ej
    return _ej(raw)


def _reject_threshold(category: str) -> float:
    return CRITIQUE_CATEGORY_REJECT.get(category.lower(), _DEFAULT_REJECT)


def _confirm_threshold(category: str) -> float:
    return CRITIQUE_CATEGORY_CONFIRM.get(category.lower(), _DEFAULT_CONFIRM)


def _score_batch(
    findings_batch: list[dict],
    contract_code: str,
    contract_name: str,
    system_prompt: str,
    invoke_config: dict,
    model: str | None = None,
) -> dict[str, dict]:
    """Score one batch independently. Returns {finding_id: assessment_dict}.
    Sends only the code lines relevant to this batch (±5 context lines).
    Critique scores are stripped before sending — verify must not see them."""
    findings_text = json.dumps(
        [format_finding_for_critique(f) for f in findings_batch],
        indent=2,
    )
    relevant_code = extract_relevant_code(contract_code, findings_batch)

    human_content = (
        f"Contract filename: {contract_name}\n\n"
        f"Relevant contract code (line-numbered, gaps indicated):\n"
        f"```solidity\n{relevant_code}\n```\n\n"
        f"Score each of the following findings using the code above:\n\n"
        f"{findings_text}"
    )

    messages = [SystemMessage(content=system_prompt), HumanMessage(content=human_content)]
    raw    = _invoke(messages, invoke_config, model=model)
    parsed = _extract_json(raw)
    return {a["id"]: a for a in parsed.get("assessments", []) if "id" in a}


def run_verify_node(state: AuditState) -> AuditState:
    """
    Defender agent. Scores findings independently then compares with critique to route:
      - AUTO-CONFIRMED: both agree >= confirm threshold
      - TIEBREAKER:     everything else (no auto-reject — protects recall)
    """
    logger.info("[Verify] Starting — %s", state["contract_name"])
    errors = list(state.get("errors", []))

    all_findings = state.get("all_findings_to_review", [])

    if not all_findings:
        logger.info("[Verify] No findings to review — skipping")
        return {**state, "confirmed_findings": [], "uncertain_findings": [], "errors": errors}

    model         = LLM_MODEL_DEBATE
    system_prompt = langfuse_client.get_prompt("audit-verify-prompt")
    callback = langfuse_client.get_callback(
        trace_name="audit-verify",
        contract_name=state["contract_name"],
        metadata={"model": model, "node": "verify"},
    )
    invoke_config = {"callbacks": [callback]} if callback else {}

    batch_size = len(all_findings)  # always single call — debate model has 30K TPM
    batches = batch(all_findings, size=batch_size)
    all_assessments: dict[str, dict] = {}

    logger.info("[Verify] Scoring %d finding(s) in %d batch(es) (model: %s)",
                len(all_findings), len(batches), model)

    try:
        for i, b in enumerate(batches):
            logger.info("[Verify] Batch %d/%d (%d findings)…", i + 1, len(batches), len(b))
            assessments = _score_batch(
                b, state["contract_code"], state["contract_name"],
                system_prompt, invoke_config, model=model,
            )
            all_assessments.update(assessments)

        confirmed: list[dict] = []
        uncertain: list[dict] = []

        for f in all_findings:
            fid = f.get("id", "")
            cat = f.get("category", "other").lower()

            # Verify's own independent score
            a             = all_assessments.get(fid, {})
            verify_score  = float(a.get("score", 0.5))
            verify_verdict= a.get("verdict", "uncertain")
            verify_reason = a.get("reasoning", "")

            # Critique scores came from critique_node and are attached to the finding
            critique_score = float(f.get("critique_score", 0.5))

            confirm_thresh = _confirm_threshold(cat)

            both_confirm = (critique_score >= confirm_thresh) and (verify_score >= confirm_thresh)

            enriched = {
                **f,
                "verify_score":    verify_score,
                "verify_verdict":  verify_verdict,
                "verify_reasoning":verify_reason,
            }

            if both_confirm:
                logger.info(
                    "[Verify] %s (%s)  → AUTO-CONFIRMED  critique=%.2f verify=%.2f (both >= %.2f)",
                    fid, cat, critique_score, verify_score, confirm_thresh,
                )
                confirmed.append(enriched)

            else:
                logger.info(
                    "[Verify] %s (%s)  → TIEBREAKER      critique=%.2f verify=%.2f  (%s | %s)",
                    fid, cat, critique_score, verify_score,
                    f.get("critique_verdict", "?"), verify_verdict,
                )
                uncertain.append(enriched)

        logger.info(
            "[Verify] Done — auto-confirmed:%d  tiebreaker:%d",
            len(confirmed), len(uncertain),
        )
        return {
            **state,
            "confirmed_findings":  confirmed,
            "uncertain_findings":  uncertain,
            "verify_finished_at":  time.time(),
            "errors":              errors,
        }

    except Exception as exc:
        from pipeline.nodes.llm_node import _log_llm_error
        _log_llm_error("verify", exc)
        errors.append(f"Verify node failed: {str(exc)[:150]}")
        fallback = [
            {**f, "verify_score": 0.5, "verify_verdict": "uncertain",
             "verify_reasoning": "verify failed"}
            for f in all_findings
        ]
        return {
            **state,
            "confirmed_findings":  [],
            "uncertain_findings":  fallback,
            "verify_finished_at":  time.time(),
            "errors":              errors,
        }
