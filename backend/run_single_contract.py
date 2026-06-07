#!/usr/bin/env python3
"""
Run a single contract through the audit backend and print findings.
Usage:
    python run_single_contract.py <path_to_contract.sol>
    python run_single_contract.py  # defaults to smart_billions.sol
"""

import sys
import json
import requests
from pathlib import Path

BACKEND_URL = "http://localhost:8000/api/v1/audit"
TIMEOUT     = 3600   # 60 min — large contracts with chunking + debate rounds can take 25+ min

DEFAULT_CONTRACT = (
    Path(__file__).parent.parent / "smartbugs-curated"
    / "dataset" / "front_running" / "FindThisHash.sol"
)


def run(contract_path: Path):
    print(f"\nContract : {contract_path.name}")
    print(f"Size     : {contract_path.stat().st_size} bytes")
    print(f"Sending to {BACKEND_URL} …\n")

    with open(contract_path, "rb") as f:
        resp = requests.post(
            BACKEND_URL,
            files={"file": (contract_path.name, f, "text/plain")},
            timeout=TIMEOUT,
        )

    if resp.status_code != 200:
        print(f"ERROR {resp.status_code}: {resp.text[:300]}")
        return

    report = resp.json()

    vulns = report.get("vulnerabilities", [])
    meta  = report.get("meta", {})
    stats = report.get("statistics", {})

    print(f"Model    : {meta.get('llm_model', '?')}")
    print(f"Slither  : {'yes' if meta.get('slither_available') else 'no'}")
    errors = meta.get("pipeline_errors", [])
    if errors:
        print(f"Errors   : {errors}")
    print(f"\nStats    : {stats}")
    print(f"\n{'─'*70}")
    print(f"  {'ID':<10} {'SEV':<10} {'CAT':<30} {'LINES':<15} {'SRC':<8} CONF")
    print(f"{'─'*70}")

    for v in vulns:
        print(
            f"  {v.get('id','?'):<10} "
            f"{v.get('severity','?'):<10} "
            f"{v.get('category','?'):<30} "
            f"{str(v.get('line_numbers',[])):<15} "
            f"{v.get('source','?'):<8} "
            f"{v.get('confidence','?')}"
        )

    print(f"{'─'*70}")
    print(f"\nTotal findings: {len(vulns)}")

    if "--json" in sys.argv:
        print("\nFull JSON:\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = Path(args[0]) if args else DEFAULT_CONTRACT

    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    run(path)
