# Smart Contract Auditor - Evaluation Framework

This module evaluates the Smart Contract Auditor against the **SmartBugs Curated** ground truth dataset.

## Overview

The evaluation framework:
1. **Loads 200+ Solidity contracts** from the SmartBugs dataset
2. **Makes API calls** to the auditor backend for each contract
3. **Compares detected findings** against ground truth with leniency-based matching
4. **Calculates metrics**: Precision, Recall, F1-Score (overall and per-category)
5. **Generates reports**: JSON (machine-readable) + text (human-readable)

## Quick Start

### Prerequisites

```bash
# Install dependencies
pip install -r ../requirements.txt
### SMARTBUGS DATASET

In order for the script to run the dataset must be in the folder where the repo folder is. Dont change its name after cloning the dataset from 
https://github.com/smartbugs/smartbugs-curated.git

Clone it in the same folder as where you cloned this repo.

Dont forget to export the grok API key.
```bash
export GROQ_API_KEY="YOUR_API_KEY"
```

# Ensure backend is running
```bash
cd ../..
uvicorn main:app --reload --port 8000
```

### Run Full Evaluation

```bash
cd backend/
python -m evaluation.test_smartbugs
```

**Expected Runtime:** 70 minutes (depends on dataset size and API latency)

### Output Files

Reports are saved to `evaluation/reports/` with timestamp:



## Configuration

Edit `test_smartbugs.py` main() to change:

```python
evaluator = SmartBugsEvaluator(
    dataset_path=dataset_path,
    ground_truth_path=ground_truth_path,
    api_base_url="http://localhost:8000",  # ← Backend URL
    timeout=120,                            # ← Seconds per request
)
```

## Leniency-Based Matching

The framework intentionally uses **lenient matching** for real-world accuracy:

### Category Matching
Maps related vulnerability types to the same category:
- `reentrancy`, `reentrant` → Same category
- `integer overflow`, `arithmetic`, `underflow` → Same category
- `access control`, `tx.origin` → Same category
- And 6+ more category aliases

### Line Number Tolerance
- Accepts line numbers within **±5 lines** of ground truth
- Rationale: Different analysis engines may report slightly offset lines

### Scoring Logic
A finding is **True Positive (TP)** if:
- Category matches (with alias mapping) **AND**
- Line numbers match (within ±5) or ground truth has no line numbers

Otherwise:
- **False Positive (FP)**: Detected but not in ground truth
- **False Negative (FN)**: In ground truth but not detected

## Metrics Definitions

```
Precision  = TP / (TP + FP)     ← Of findings we report, how many correct?
Recall     = TP / (TP + FN)     ← Of all real bugs, how many did we find?
F1-Score   = 2 * (P * R) / (P + R) ← Harmonic mean (balance both)
```

## Report Structures

### `contract_results_*.json`

Per-contract breakdown:

```json
{
  "contract_name": "Reentrancy.sol",
  "file_path": "path/to/Reentrancy.sol",
  "status": "evaluated",
  "ground_truth_count": 2,
  "detected_count": 3,
  "tp": 2,
  "fp": 1,
  "fn": 0,
  "metrics": {
    "precision": 0.6667,
    "recall": 1.0,
    "f1_score": 0.8,
    ...
  },
  "per_category": {
    "reentrancy": {"tp": 2, "fp": 0, "fn": 0}
  }
}
```

### `summary_*.json`

Aggregated metrics:

```json
{
  "timestamp": "20260427_143022",
  "total_contracts": 203,
  "successful_audits": 198,
  "failed_audits": 5,
  "overall_metrics": {
    "precision": 0.8234,
    "recall": 0.7891,
    "f1_score": 0.8061,
    ...
  },
  "per_category_metrics": {
    "reentrancy": {"tp": 45, "fp": 3, "fn": 2, ...},
    "arithmetic": {"tp": 38, "fp": 5, "fn": 4, ...},
    ...
  }
}
```

### `report_*.txt`

Human-readable summary with categories sorted by F1-Score.

## Troubleshooting

### Backend Connection Error

```
ERROR: Connection refused (http://localhost:8000)
```

**Solution:** Start backend first:
```bash
cd backend/
uvicorn main:app --reload --port 8000
```

### Ground Truth Not Found

```
✗ Failed to load ground truth: ...
```

**Solution:** Verify SmartBugs dataset path:
```bash
ls -la ../../smartbugs-curated/vulnerabilities.json
```

### Timeout Errors

If many contracts timeout:
- Increase `timeout=180` in main()
- Check backend CPU/memory usage
- Check API rate limits (Groq free tier: ~15 audits/day)

### Failed Audits

Failed audits don't block evaluation. Check `summary_*.json`:

```json
"failed_audits": 5,
"failed_contracts": [
  "ContractA.sol",
  "ContractB.sol",
  ...
]
```

## Module Structure

```
evaluation/
├── __init__.py                  # Package marker
├── metrics.py                   # Metric calculations & reporting
├── test_smartbugs.py            # Main evaluation script
├── reports/                     # Output reports (auto-created)
└── README.md                    # This file
```

## Key Classes & Functions

### `SmartBugsEvaluator`

Main evaluator class:

- `load_ground_truth()` - Load vulnerabilities.json
- `find_all_contracts()` - Discover .sol files
- `audit_contract()` - Call backend API (async)
- `compare_findings()` - Match predictions vs ground truth
- `evaluate_contract()` - Full contract evaluation pass
- `run()` - Execute full evaluation suite

### `metrics.py` Functions

- `calculate_metrics(tp, fp, fn)` - TP/FP/FN → precision/recall/F1
- `match_categories()` - Lenient category matching with aliases
- `match_line_numbers()` - Line matching with ±5 tolerance
- `aggregate_metrics()` - Combine per-category results
- `generate_summary_report()` - Format human-readable report


