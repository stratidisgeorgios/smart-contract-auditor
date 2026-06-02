"""
This script is a helper script for the Langfuse client.

It provides:
  - get_prompt() -> fetch a prompt by name from Langfuse, with a local file fallback
  - get_callback() -> returns a LangChain CallbackHandler for tracing 
  - flush()-> flush pending Langfuse events before the process exits
"""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

#Local fallback paths 
# If Langfuse is unavailable we fall back to these files.

_FALLBACK_PATHS: dict[str, Path] = {
    "audit-system-prompt": (
        Path(__file__).parent.parent / "data" / "instructions" / "prompt_v3_smartbugs.txt"
    ),
    "reflection-system-prompt": (
        Path(__file__).parent.parent / "data" / "instructions" / "reflection_prompt.txt"
    ),
}

# Lazy Langfuse client
_client = None       
_initialised = False # guard to avoid repeated init attempts


def _get_client():
    """
    Lazily initialise the Langfuse client. Returns the client if everything is configured, or None if Langfuse is
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


# Public API

def get_prompt(name: str, label: str = "production") -> str:
    """
    Fetch a prompt text by name.
    """
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
            logger.warning("[Langfuse] Fetch failed for '%s': %s", name, exc)
            logger.warning("[Langfuse] -> falling back to local .txt file")

    # Fallback: read from disk
    text = _local_prompt(name)
    logger.info(
        "[Langfuse] PROMPT SOURCE: LOCAL FILE  (name='%s', %d chars)"
        "  -- set LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY to use Langfuse",
        name, len(text),
    )
    return text


def get_prompt_obj(name: str, label: str = "production"):
    """
    Return the raw Langfuse prompt object (not just the text). Used by llm_node to pass prompt= to get_callback(), which links the LLM generation to the prompt in Langfuse Prompt Metrics.
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
    """Read the prompt from the local fallback file."""
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
    prompt_name: str = "audit-system-prompt",
    prompt_label: str = "production",
):
    """
    Return a LangChain CallbackHandler that sends tracing data to Langfuse and links the generation to the prompt so it appears in Prompt Metrics. The prompt linkage is done by fetching the prompt object and attaching it
    to the handler 
    """
    client = _get_client()
    if client is None:
        return None

    try:
        from langfuse.callback import CallbackHandler 

        # Fetch the prompt object so generations are linked to it in the UI
        prompt_obj = None
        try:
            prompt_obj = client.get_prompt(
                prompt_name,
                label=prompt_label,
                cache_ttl_seconds=300,
            )
        except Exception as exc:
            logger.warning("[Langfuse] Could not fetch prompt for linking: %s", exc)

        handler = CallbackHandler(
            trace_name=trace_name,
            user_id=contract_name or "unknown",
            metadata=metadata or {},
            stateful_client=client,
        )

        # Link the prompt to this trace so it appears in Prompt -> Metrics
        if prompt_obj is not None:
            try:
                handler.langfuse.trace(
                    name=trace_name,
                    metadata={**(metadata or {}), "prompt_name": prompt_name},
                )
            except Exception:
                pass # linking is best-effort, never break the audit

        return handler
    except ImportError:
        logger.warning("[Langfuse] langfuse[callback] not installed")
        return None
    except Exception as exc:
        logger.warning("[Langfuse] Could not create callback: %s", exc)
        return None


def flush():
    """
    Flush any buffered Langfuse events.
    """
    client = _get_client()
    if client is not None:
        try:
            client.flush()
        except Exception as exc:
            logger.warning("[Langfuse] flush() failed: %s", exc)