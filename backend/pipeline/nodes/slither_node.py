"""
Runs Slither, an open-source static analyser for Solidity, and
converts its raw output into the same vulnerability schema used by the LLM node.
"""

import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path

from pipeline.state import AuditState

logger = logging.getLogger(__name__)

# Severity / SWC maps


SLITHER_SEVERITY_MAP = { # Slither uses its own severity labels so we map them to our internal ones
    "High":          "HIGH",
    "Medium":        "MEDIUM",
    "Low":           "LOW",
    "Informational": "INFO",
    "Optimization":  "INFO",
}

# Map Slither check names to SWC IDs (Smart Contract Weakness Classification).
# Not every check has an SWC equivalent, so we only list the ones that do.
SLITHER_CHECK_TO_SWC = {
    "reentrancy-eth":         "SWC-107",
    "reentrancy-no-eth":      "SWC-107",
    "reentrancy-benign":      "SWC-107",
    "integer-overflow":       "SWC-101",
    "tx-origin":              "SWC-115",
    "timestamp":              "SWC-116",
    "weak-prng":              "SWC-120",
    "controlled-delegatecall":"SWC-112",
    "suicidal":               "SWC-106",
    "uninitialized-local":    "SWC-109",
    "uninitialized-storage":  "SWC-109",
    "unchecked-lowlevel":     "SWC-104",
    "unchecked-send":         "SWC-104",
}

# If we can't detect the pragma version, we fall back to this widely used version
FALLBACK_SOLC = "0.8.20"


# Solc version helpers


# Regex to extract pragmas like: ^0.8.9  >=0.7.0  =0.6.12  0.8.20  ~0.8.0
_PRAGMA_RE = re.compile(
    r"pragma\s+solidity\s*[^;]*?(\d+\.\d+\.\d+)",
    re.IGNORECASE,
)


def _detect_pragma_version(source: str) -> str | None:
    """Scan the contract source for a pragma and return the version string."""
    m = _PRAGMA_RE.search(source)
    return m.group(1) if m else None


def _list_installed_versions() -> set[str]:
    """Ask solc-select which compiler versions are already installed locally."""
    try:
        result = subprocess.run(
            ["solc-select", "versions"],
            capture_output=True, text=True, timeout=15,
        )
        versions = set()
        for line in result.stdout.splitlines():
            # Lines look like "0.8.20 (current, set by …)" or just "0.8.20"
            parts = line.strip().split()
            if parts and re.match(r"^\d+\.\d+\.\d+$", parts[0]):
                versions.add(parts[0])
        return versions
    except Exception as exc:
        logger.warning(" !! Could not list installed solc versions: %s", exc)
        return set()


def _install_solc(version: str) -> bool:
    """
    Download and install a specific solc version through solc-select.
    Returns True if installation succeeded, False otherwise.
    Timeout is generous (120s) because downloading a compiler binary can be slow.
    """
    logger.info("  Installing solc %s via solc-select…", version)
    try:
        result = subprocess.run(
            ["solc-select", "install", version],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            logger.info("  [SUCCESS LOG] solc %s installed", version)
            return True
        logger.warning(
            "  !! solc-select install %s failed (code %d): %s",
            version, result.returncode, result.stderr[:200],
        )
        return False
    except Exception as exc:
        logger.warning("  ⚠ Could not install solc %s: %s", version, exc)
        return False


def _use_solc(version: str) -> bool:
    """Tell solc-select to make the given version the active compiler.
    Slither will pick this up automatically when it compiles the contract.
    Returns True on success."""
    try:
        result = subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            logger.info("  ✓ Active solc set to %s", version)
            return True
        logger.warning(
            "  !! solc-select use %s failed: %s",
            version, result.stderr[:200],
        )
        return False
    except Exception as exc:
        logger.warning("  !! Could not switch solc version: %s", exc)
        return False


def _ensure_solc(version: str) -> str:
    """
    helper that makes sure the requested solc version is installed
    and active, falling back to FALLBACK_SOLC if anything goes wrong.
    """
    installed = _list_installed_versions()
    logger.info(
        "  Installed solc versions: %s",
        ", ".join(sorted(installed)) or "(none detected)",
    )

    if version not in installed:
        ok = _install_solc(version)
        if not ok:
            logger.warning(
                "  !! Could not install solc %s — trying fallback %s",
                version, FALLBACK_SOLC,
            )
            if FALLBACK_SOLC not in installed:
                _install_solc(FALLBACK_SOLC)
            _use_solc(FALLBACK_SOLC)
            return FALLBACK_SOLC

    _use_solc(version)
    return version



# Output normalization


def _normalise(idx: int, detector: dict) -> dict:
    """
    Convert a single raw Slither finding dict into our internal schema.
    Slither's JSON output has a lot of fields so we only keep the ones that
    are useful to us and rename them to match the LLM node's output format,
    so the merge node can treat both sources.
    """

    check_id         = detector.get("check", "unknown")
    impact           = detector.get("impact", "Informational")
    confidence       = detector.get("confidence", "Medium")
    description      = detector.get("description", "").strip()

    elements         = detector.get("elements", []) # "elements" describes which functions / variables / lines are affected
    affected_function = "contract-level"
    lines            = []

    for el in elements:
        if el.get("type") == "function":
            # If this element is a function, record its name
            affected_function = el.get("name", affected_function)
        # Collect all line numbers 
        lines.extend(el.get("source_mapping", {}).get("lines", []))

    # TODO: enhance Slither mapping to display it better in frontend
    return {
        "id":                   f"SLI-{idx:03d}", # unique ID within slither results
        "title":                check_id.replace("-", " ").title(), # human-readable name
        "severity":             SLITHER_SEVERITY_MAP.get(impact, "INFO"),
        "category":             check_id.replace("-", " ").title(),
        "swc_id":               SLITHER_CHECK_TO_SWC.get(check_id),
        "affected_function":    affected_function,
        "affected_code_snippet":"", # Slither doesn't give us a snippet directly
        "line_numbers":         sorted(set(lines)), # deduplicated and sorted
        "description":          description,
        "exploitation_scenario":None, # Slither doesn't provide these
        "recommendation":       None,
        "confidence":           confidence.upper(),
        "source":               "SLITHER",
        "slither_check":        check_id,
    }

# Main node

def run_slither_node(state: AuditState) -> AuditState:
    """
    LangGraph node that runs Slither on the contract and stores the results.
    Steps:
      1. Write the contract to a temporary file (Slither requires a file path).
      2. Detect the pragma version and activate the matching solc.
      3. Run Slither as a subprocess with JSON output.
      4. Parse and normalise the findings.
      5. Return the updated state with slither_report filled in.
    The node never raises errors. Errors are recorded in state["errors"] and
    slither_report["success"] is set to False so downstream nodes know
    Slither didn't produce results.
    """

    logger.info("[LOG] Slither node — %s", state["contract_name"])
    errors = list(state.get("errors", []))

    # 1. Write the contract to a temporary file
    with tempfile.TemporaryDirectory(prefix="slither_") as tmp:
        sol_path  = Path(tmp) / state["contract_name"]
        json_path = Path(tmp) / "output.json"
        sol_path.write_text(state["contract_code"], encoding="utf-8")

        # 2. Detect the pragma version and ensure the right solc is active 
        detected = _detect_pragma_version(state["contract_code"])
        if detected:
            logger.info("  Detected pragma version: %s", detected)
            active_version = _ensure_solc(detected)
        else:
            logger.info(
                "  No pragma version detected — using fallback %s", FALLBACK_SOLC
            )
            active_version = _ensure_solc(FALLBACK_SOLC)

        logger.info("  Running Slither with solc %s…", active_version)

        # 2. Run Slither as a subprocess
        try:
            result = subprocess.run(
                [
                    "slither", str(sol_path),
                    "--json", str(json_path),
                    "--json-types", "detectors",
                    "--no-fail-pedantic",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=tmp,
            )

            # Slither returns 0 = ran successfully but no findings, 1 = ran successfully but findings were detected. Any other code indicates a real error 
            if result.returncode not in (0, 1):
                msg = (
                    f"Slither exited with code {result.returncode}. "
                    f"stderr: {result.stderr[:400]}"
                )
                logger.warning("  !! %s", msg)
                errors.append(msg)

            if not json_path.exists():  # If the JSON file wasn't created, something went wrong before Slither finished
                raise FileNotFoundError("Slither produced no JSON output")

            raw = json.loads(json_path.read_text(encoding="utf-8"))
            detectors = raw.get("results", {}).get("detectors", [])
            logger.info(" [SUCCESSFUL LOG] Slither done — %d findings", len(detectors))

            normalised = [_normalise(i + 1, d) for i, d in enumerate(detectors)] # Convert every raw finding into our internal schema

            # Full Slither output for debug  
            logger.info("━" * 50)
            logger.info("SLITHER RAW OUTPUT")
            logger.info("━" * 50)
            logger.info(
                json.dumps({"findings": normalised, "raw": raw}, indent=2, ensure_ascii=False)
            )
            logger.info("━" * 50)

            return {
                **state,
                "slither_report": {
                    "success":         True,
                    "vulnerabilities": normalised,
                    "raw_output":      raw,
                },
                "errors": errors,
            }

        # error handling
        except FileNotFoundError as exc:
            msg = (
                "Slither not installed. Run: pip install slither-analyzer"
                if "slither" in str(exc)
                else str(exc)
            )
            logger.error("  x %s", msg)
            errors.append(msg)

        except subprocess.TimeoutExpired:
            msg = "Slither timed out after 120s"
            logger.error("  x %s", msg)
            errors.append(msg)

        except Exception as exc:
            msg = f"Slither node error: {exc}"
            logger.exception("  x %s", msg)
            errors.append(msg)

        return {  # If we reached this point, something went wrong so we return a failed report
            **state,
            "slither_report": {
                "success":         False,
                "vulnerabilities": [],
                "error":           msg,
            },
            "errors": errors,
        }