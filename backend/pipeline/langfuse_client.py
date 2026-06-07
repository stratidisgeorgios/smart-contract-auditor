"""
Langfuse client helper.

Provides:
  - get_prompt()     → fetch a prompt by name from Langfuse, with a local file fallback
  - get_prompt_obj() → return the raw Langfuse prompt object (used to link generations to Prompt Metrics)
  - get_callback()   → return a LangChain CallbackHandler for tracing
  - flush()          → flush pending Langfuse events before the process exits
"""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_BASE = Path(__file__).parent.parent / "data" / "instructions"

# Local fallback paths — used when Langfuse is unavailable or keys are not set.
_FALLBACK_PATHS: dict[str, Path] = {
    "audit-detect-prompt":      _BASE / "detection_prompt.txt",
    "audit-critique-prompt":    _BASE / "critique_prompt.txt",
    "audit-verify-prompt":      _BASE / "verify_prompt.txt",
    "audit-tiebreaker-prompt":  _BASE / "tiebreaker_prompt.txt",
}

# Lazy Langfuse client
_client = None
_initialised = False   # guard to avoid repeated init attempts


def _get_client():
    """
    Lazily initialise the Langfuse client.
    Returns the client if everything is configured, or None if Langfuse is
    disabled or the SDK is not installed.
    """
    global _client, _initialised
    if _initialised:
        return _client
    _initialised = True

    if os.getenv("LANGFUSE_ENABLED", "true").lower() == "false":
        logger.info("[Langfuse] Disabled via LANGFUSE_ENABLED=false")
        return None

    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")

    if not public_key or not secret_key:
        logger.info(
            "[Langfuse] LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY not set — "
            "running without Langfuse (local prompts only)"
        )
        return None

    try:
        from langfuse import Langfuse
        _client = Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            host=os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        )
        logger.info("[Langfuse] Client initialised (host: %s)", os.getenv("LANGFUSE_HOST", "cloud"))
        return _client
    except ImportError:
        logger.warning(
            "[Langfuse] langfuse package not installed — "
            "install with: pip install langfuse"
        )
        return None
    except Exception as exc:
        logger.warning("[Langfuse] Init failed: %s — falling back to local prompts", exc)
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def get_prompt(name: str, label: str = "production") -> str:
    """Fetch prompt text by name. Falls back to local file if Langfuse is unavailable."""
    client = _get_client()

    if client is not None:
        try:
            prompt_obj = client.get_prompt(
                name,
                label=label,
                cache_ttl_seconds=300,
                fallback=_local_prompt(name),
            )
            text = prompt_obj.compile()
            logger.info(
                "[Langfuse] PROMPT SOURCE: LANGFUSE  (name='%s', label=%s, %d chars)",
                name, label, len(text),
            )
            return text
        except Exception as exc:
            logger.warning("[Langfuse] Fetch failed for '%s': %s — falling back to local file", name, exc)

    text = _local_prompt(name)
    logger.info(
        "[Langfuse] PROMPT SOURCE: LOCAL FILE  (name='%s', %d chars)",
        name, len(text),
    )
    return text


def get_prompt_obj(name: str, label: str = "production"):
    """
    Return the raw Langfuse prompt object (not just the text).
    Used to link LLM generations to the prompt in Langfuse Prompt Metrics.
    Returns None if Langfuse is unavailable.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        return client.get_prompt(name, label=label, cache_ttl_seconds=300)
    except Exception as exc:
        logger.warning("[Langfuse] get_prompt_obj failed for '%s': %s", name, exc)
        return None


def _local_prompt(name: str) -> str:
    """Read the prompt text from the registered local fallback file."""
    path = _FALLBACK_PATHS.get(name)
    if path is None:
        raise FileNotFoundError(
            f"No local fallback path registered for prompt '{name}'. "
            f"Add it to _FALLBACK_PATHS in langfuse_client.py"
        )
    if not path.exists():
        raise FileNotFoundError(
            f"Local prompt file not found: {path}\n"
            f"Either configure Langfuse or create this file."
        )
    return path.read_text(encoding="utf-8")


def get_callback(
    trace_name: str,
    contract_name: str = "",
    metadata: Optional[dict] = None,
):
    """
    Return a LangChain CallbackHandler that sends tracing data to Langfuse
    and links the generation to the prompt so it appears in Prompt Metrics.
    Returns None if Langfuse is unavailable.
    """
    client = _get_client()
    if client is None:
        return None

    try:
        try:
            from langfuse.langchain import CallbackHandler  # Langfuse v4
        except ImportError:
            from langfuse.callback import CallbackHandler   # Langfuse v2/v3

        # Try v2/v3 constructor (full args) → v4 minimal → bare
        try:
            handler = CallbackHandler(
                trace_name=trace_name,
                user_id=contract_name or "unknown",
                metadata=metadata or {},
                stateful_client=client,
            )
        except TypeError:
            try:
                handler = CallbackHandler(session_id=trace_name)
            except TypeError:
                handler = CallbackHandler()

        logger.info("[Langfuse] Callback handler created for '%s'", trace_name)
        return handler
    except ImportError:
        logger.warning("[Langfuse] LangChain callback not available in this Langfuse version")
        return None
    except Exception as exc:
        logger.warning("[Langfuse] Could not create callback: %s", exc)
        return None


def flush():
    """Flush any buffered Langfuse events before the process exits."""
    client = _get_client()
    if client is not None:
        try:
            client.flush()
        except Exception as exc:
            logger.warning("[Langfuse] flush() failed: %s", exc)
