"""
Critique node — skeptic agent.

Scores ALL findings independently against the full contract code.
Does NOT route findings — that is verify_node's responsibility.
Stores critique assessments in state["debate_history"] and annotates
each finding with critique_score / critique_verdict / critique_reasoning.
The annotated list is stored in state["all_findings_to_review"] for verify_node.

Uses GROQ_API_KEY_2.
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
    return os.getenv("GROQ_API_KEY_2") or ""


def _invoke(messages: list, invoke_config: dict, model: str | None = None) -> str:
    from pipeline.nodes.llm_node import _invoke_llm
    return _invoke_llm(messages, invoke_config, api_key=_api_key(), model=model, caller="critique")


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
    """Score one batch. Sends only the code lines relevant to this batch (±5 context lines)."""
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


def run_critique_node(state: AuditState) -> AuditState:
    """
    Skeptic agent. Scores all LLM + Slither findings against the full contract.
    Writes annotated findings to state["all_findings_to_review"] and
    critique scores to state["debate_history"]. Does NOT confirm or reject —
    that decision is made in verify_node after independent scoring by both agents.
    """
    logger.info("[Critique] Starting — %s", state["contract_name"])
    errors = list(state.get("errors", []))

    MAX_DEBATE_FINDINGS = 15  # ~6K tokens per call — fits within free-tier TPM regardless of model
    _SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    SLITHER_SKIP = {"INFO", "OPTIMIZATION", "LOW"}
    llm_findings     = state.get("llm_detection_findings", [])
    slither_raw      = (state.get("slither_report") or {}).get("vulnerabilities", [])
    slither_findings = [
        v for v in slither_raw
        if v.get("severity", "").upper() not in SLITHER_SKIP
        and v.get("category", "").lower() not in {"informational", "optimization"}
    ]

    all_findings = llm_findings + slither_findings

    if not all_findings:
        logger.info("[Critique] No findings to score — skipping")
        return {**state, "all_findings_to_review": [], "debate_history": {}, "errors": errors}

    if len(all_findings) > MAX_DEBATE_FINDINGS:
        def _priority(f):
            sev = _SEV_RANK.get(f.get("severity", "LOW").upper(), 3)
            src = 0 if f.get("source", "LLM") in ("LLM", "BOTH") else 1
            return (sev, src)
        all_findings = sorted(all_findings, key=_priority)[:MAX_DEBATE_FINDINGS]
        logger.info("[Critique] Capped to top %d findings by severity (LLM-first)", MAX_DEBATE_FINDINGS)

    model         = LLM_MODEL_DEBATE
    system_prompt = langfuse_client.get_prompt("audit-critique-prompt")
    callback = langfuse_client.get_callback(
        trace_name="audit-critique",
        contract_name=state["contract_name"],
        metadata={"model": model, "node": "critique"},
    )
    invoke_config = {"callbacks": [callback]} if callback else {}

    batch_size = len(all_findings)  # always single call — debate model has 30K TPM
    batches = batch(all_findings, size=batch_size)
    all_assessments: dict[str, dict] = {}

    logger.info("[Critique] Scoring %d finding(s) in %d batch(es) (model: %s)",
                len(all_findings), len(batches), model)

    try:
        for i, b in enumerate(batches):
            logger.info("[Critique] Batch %d/%d (%d findings)…", i + 1, len(batches), len(b))
            assessments = _score_batch(
                b, state["contract_code"], state["contract_name"],
                system_prompt, invoke_config, model=model,
            )
            all_assessments.update(assessments)
        critique_finished_at = time.time()

        debate_history: dict = {}
        annotated: list[dict] = []

        for f in all_findings:
            fid = f.get("id", "")
            cat = f.get("category", "other").lower()
            a   = all_assessments.get(fid, {})

            score   = float(a.get("score", 0.5))
            verdict = a.get("verdict", "uncertain")
            reason  = a.get("reasoning", "")

            logger.info(
                "[Critique] %s (%s)  verdict=%s  score=%.2f  reject<%.2f confirm>=%.2f  %s",
                fid, cat, verdict, score,
                _reject_threshold(cat), _confirm_threshold(cat),
                reason[:80],
            )

            debate_history[fid] = {
                "critique_score":    score,
                "critique_verdict":  verdict,
                "critique_reasoning":reason,
            }
            annotated.append({
                **f,
                "critique_score":    score,
                "critique_verdict":  verdict,
                "critique_reasoning":reason,
            })

        logger.info("[Critique] Done — %d findings scored", len(annotated))
        return {
            **state,
            "all_findings_to_review": annotated,
            "debate_history":         debate_history,
            "critique_finished_at":   critique_finished_at,
            "errors":                 errors,
        }

    except Exception as exc:
        from pipeline.nodes.llm_node import _log_llm_error
        _log_llm_error("critique", exc)
        errors.append(f"Critique node failed: {str(exc)[:150]}")
        fallback_score = 0.5
        annotated = [
            {**f, "critique_score": fallback_score,
             "critique_verdict": "uncertain", "critique_reasoning": "critique failed"}
            for f in all_findings
        ]
        debate_history = {
            f.get("id", ""): {"critique_score": fallback_score,
                               "critique_verdict": "uncertain",
                               "critique_reasoning": "critique failed"}
            for f in all_findings
        }
        return {
            **state,
            "all_findings_to_review": annotated,
            "debate_history":         debate_history,
            "critique_finished_at":   time.time(),
            "errors":                 errors,
        }
