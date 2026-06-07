#!/usr/bin/env python3
"""
Push the local prompt .txt files to Langfuse under the 'production' label.

Run this from the backend/ directory after editing any local prompt file:
    python sync_prompts_to_langfuse.py

After running, restart the backend so the 5-minute prompt cache clears.
Then re-enable Langfuse in .env by removing LANGFUSE_ENABLED=false.
"""

from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv(Path(__file__).parent / ".env")

PROMPTS = {
    "audit-detect-prompt":     Path(__file__).parent / "data/instructions/detection_prompt.txt",
    "audit-critique-prompt":   Path(__file__).parent / "data/instructions/critique_prompt.txt",
    "audit-verify-prompt":     Path(__file__).parent / "data/instructions/verify_prompt.txt",
    "audit-tiebreaker-prompt": Path(__file__).parent / "data/instructions/tiebreaker_prompt.txt",
}

def main():
    pub  = os.getenv("LANGFUSE_PUBLIC_KEY")
    sec  = os.getenv("LANGFUSE_SECRET_KEY")
    host = os.getenv("LANGFUSE_HOST") or os.getenv("LANGFUSE_BASE_URL", "https://cloud.langfuse.com")

    if not pub or not sec:
        print("ERROR: LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY not set in .env")
        return

    try:
        from langfuse import Langfuse
    except ImportError:
        print("ERROR: langfuse not installed. Run: pip install langfuse")
        return

    client = Langfuse(public_key=pub, secret_key=sec, host=host)
    print(f"Connected to Langfuse at {host}\n")

    for name, path in PROMPTS.items():
        if not path.exists():
            print(f"  SKIP  {name} — local file not found: {path}")
            continue

        text = path.read_text(encoding="utf-8")
        try:
            client.create_prompt(
                name=name,
                prompt=text,
                labels=["production"],
                config={},
            )
            print(f"  OK    {name} ({len(text)} chars) → pushed as 'production'")
        except Exception as exc:
            print(f"  FAIL  {name}: {exc}")

    client.flush()
    print("\nDone. Restart the backend and set LANGFUSE_ENABLED=true in .env to re-enable tracing.")

if __name__ == "__main__":
    main()
