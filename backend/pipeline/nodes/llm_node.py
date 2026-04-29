import json
import logging
import os
import re
from pathlib import Path

from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from pipeline.state import AuditState

logger = logging.getLogger(__name__)

INSTRUCTIONS_PATH = ( # Path to the text file that contains the system prompt we send to the LLM.
    Path(__file__).parent.parent.parent
    / "data"
    / "instructions"
    / "prompt.txt"
)

# The Groq model to use. llama-3.3-70b-versatile is the best free option for code analysis at the time of writing. (april 2026)
#Change to llama-3.1-8b-instant for the evaluation in order to save cost.
LLM_MODEL = "llama-3.1-8b-instant" #"llama-3.3-70b-versatile"#
LLM_TEMPERATURE = 0.1 # Low temperature -> more focused, deterministic output. We don't want the model to be creative as we want consistent JSON and secure outputs.
LLM_MAX_TOKENS = 2048 #4096 # Reduced from 4096 for 8b model: still sufficient for vulnerability analysis, saves 50% tokens  


def _load_system_prompt() -> str:
    if not INSTRUCTIONS_PATH.exists():
        raise FileNotFoundError(f"Prompt file not found: {INSTRUCTIONS_PATH}")
    return INSTRUCTIONS_PATH.read_text(encoding="utf-8")


def _extract_json(raw: str) -> dict:
    """Parse the JSON object out of the LLM's response.
    LLMs sometimes wrap their JSON in markdown code fences like:
        ```json
        { ... }
        ```
    This function strips those fences, locates the { } pair,
    and parses just that portion to get clean data"""
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}") + 1
    if start == -1 or end == 0:
        raise ValueError("No JSON object found in LLM response")
    return json.loads(cleaned[start:end])


def run_llm_node(state: AuditState) -> AuditState:
    """
    LangGraph node that sends the Solidity contract to the LLM for analysis.
    Steps:
      1. Check the GROQ_API_KEY env var is set.
      2. Load the system prompt 
      3. Build a ChatGroq client and send the contract code.
      4. Parse the JSON response.
      5. Return the updated state with llm_report filled in.
    On any error the node records the message in errors[] and sets
    llm_report to None so the pipeline can continue without crashing.
    """
    logger.info("[LOG] LLM node — %s", state["contract_name"])
    errors = list(state.get("errors", []))

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        msg = "GROQ_API_KEY not set"
        logger.error(" [LOG] %s", msg)
        errors.append(msg)
        return {**state, "llm_report": None, "errors": errors}

    try:
        system_prompt = _load_system_prompt()

        # Inference to the LLM client with our model and settings
        llm = ChatGroq(
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            api_key=api_key,
            max_tokens=LLM_MAX_TOKENS,
        )

        # we build the conversation:
        #   - SystemMessage: the audit instructions (role, output format, rules) (basically the prompt)
        #   - HumanMessage: the contract code to analyse (provided by the user in the UI)
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

        logger.info("  Sending to Groq (%s)…", LLM_MODEL)
        response = llm.invoke(messages)
        parsed = _extract_json(response.content)

        vulns = parsed.get("llm_analysis", {}).get("vulnerabilities", [])
        logger.info(" [LOG] LLM done — %d vulnerabilities found", len(vulns)) # Log how many vulnerabilities the LLM found

        # Dump the full LLM output to the log so we can debug prompt/response issues
        logger.info("━" * 50)
        logger.info("LLM RAW OUTPUT")
        logger.info("━" * 50)
        logger.info(json.dumps(parsed, indent=2, ensure_ascii=False))
        logger.info("━" * 50)

        return {**state, "llm_report": parsed} # we store the parsed report in the state so the next nodes can use it

    except json.JSONDecodeError as exc:
        # The LLM returned something that looked like JSON but couldn't be parsed
        msg = f"LLM returned invalid JSON: {exc}"
        logger.error("  ✗ %s", msg)
        errors.append(msg)
        return {**state, "llm_report": None, "errors": errors}

    except Exception as exc:
        # Catching network errors, API errors, etc.
        msg = f"LLM node error: {exc}"
        logger.exception("  ✗ %s", msg)
        errors.append(msg)
        return {**state, "llm_report": None, "errors": errors}