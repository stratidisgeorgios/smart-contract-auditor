# Smart Contract Auditor: Multi-Agent LLM + Static Analysis Pipeline

A web app that lets you upload a Solidity smart contract and get back a detailed security report.
It combines two detection engines (an LLM via Groq and Slither static analysis) with a
three-agent debate pipeline that validates every finding before it reaches the report.

## Branches

This repository contains two versions of the auditor:

| Branch | Approach |
|---|---|
| [`main`](../../tree/main) | **Single-agent baseline.** One LLM call plus Slither, merged and deduplicated. |
| [`agentic-implementation`](../../tree/agentic-implementation) | **Multi-agent debate (this branch).** A detector agent proposes findings, a skeptic agent and a defender agent score each one independently, and a tiebreaker agent decides the cases they disagree on. |

Both versions share the same Next.js frontend and Slither integration.

---

## How it works — the big picture

```
User uploads .sol file
        │
        ▼
  [Next.js Frontend]
  Sends file to backend via POST /api/v1/audit
        │
        ▼
  [FastAPI Backend — LangGraph pipeline]
    1. Validate       →  sanity checks on the file
    2. Supervisor     →  tags contract type, initialises state
    3. LLM detect     →  Groq LLM finds all possible vulnerabilities (high recall)
    4. Slither        →  static analysis, exact line numbers
    5. Critique       →  skeptic agent scores every finding independently
    6. Verify         →  defender agent scores independently (never sees critique's scores)
    7. Tiebreaker     →  arbitrates findings where critique and verify disagreed
    8. Merge          →  collapses duplicates, builds the final report
        │
        ▼
  Returns JSON report
        │
        ▼
  [Next.js Frontend]
  Renders the report: stats bar, sidebar list, vulnerability detail panel
```

---

## Backend

The backend is a **Python + FastAPI** app deployed on Render via Docker.

### Entry point — `main.py`

Boots the FastAPI app, sets up logging, and registers the API routes.
Configures CORS so the frontend (on a different domain) can call the API.

### API — `routes.py`

| Endpoint | What it does |
|---|---|
| `POST /api/v1/audit` | Accepts a `.sol` file, runs the pipeline, returns the JSON report |
| `GET /api/v1/health` | Liveness check used by Render |

File validation before the pipeline runs:
- Must be a `.sol` file
- Must not be empty
- Must be under 500 KB
- Must be valid UTF-8

### Pipeline — `graph.py`

Built as a **LangGraph** directed graph. Each node reads from a shared state dict, does its work,
and writes results back. The pipeline is linear — no loops.

```
START → validate → supervisor_plan → llm_detect → slither_analysis
      ↘ abort → END (empty input)                       │
                                                      critique
                                                         │
                                                       verify
                                                         │
                                                     tiebreaker
                                                         │
                                                    merge_reports → END
```

The shared state (`state.py`) acts as a whiteboard every node reads and writes:
contract code, raw findings from each engine, debate scores, confirmed findings, and errors.

---

### Node 1 — `llm_node.py` (Detection)

Sends the full contract to the **Groq API** with a high-recall prompt — the goal is to find
everything, since a later stage filters false positives.

- Model: `openai/gpt-oss-120b` for all contract sizes (`LLM_MODEL_SMALL` / `LLM_MODEL_LARGE` in `llm_node.py`).
  `openai/gpt-oss-20b` is not used because it exhausts the 4096-token output limit on reasoning
  and returns an empty response.
- Uses `GROQ_API_KEY`
- System prompt fetched from Langfuse (`audit-detect-prompt`), falls back to `data/instructions/detection_prompt.txt`

After the LLM responds, the node runs two dedup passes and a three-strategy line number resolver
per finding:

1. **Snippet search** — searches `affected_code_snippet` verbatim in the source
2. **Function body traversal** — walks the named function by brace counting
3. **Range trimming** — strips line numbers beyond the contract length

Results go into `state["llm_detection_findings"]`.

---

### Node 2 — `slither_node.py`

Runs **Slither** as a local subprocess. Detects the `pragma solidity` version, installs
the correct compiler via `solc-select`, runs Slither, and normalises findings into the
same schema as the LLM node.

**Strengths:** compiler-verified line numbers, no hallucination, fast.
**Weaknesses:** pattern-matching only, no semantic understanding, misses many vulnerability classes.

Results go into `state["slither_report"]`.

---

### Node 3 — `critique_node.py` (Skeptic agent)

Takes all LLM findings plus MEDIUM+ Slither findings (capped at 15 by severity priority).
Scores every finding independently against the relevant contract code excerpt.

- Model: `openai/gpt-oss-120b` via `GROQ_API_KEY_2`
- Prompt: `audit-critique-prompt` (Langfuse)
- Attaches `critique_score` (0–1) and `critique_verdict` to each finding
- Makes no pass/fail decisions — only scores

Results go into `state["all_findings_to_review"]`.

---

### Node 4 — `verify_node.py` (Defender agent)

Receives the same finding list as critique but **never sees critique's scores** — this
ensures an independent assessment.

- Model: `openai/gpt-oss-120b` via `GROQ_API_KEY_3`
- Prompt: `audit-verify-prompt` (Langfuse)
- Compares its own scores against critique's after scoring:
  - Both agents ≥ confirm threshold → `confirmed_findings` (auto-confirmed)
  - Everything else → `uncertain_findings` (sent to tiebreaker — no auto-reject)

---

### Node 5 — `tiebreaker_node.py` (Neutral arbiter)

Receives `uncertain_findings` with both agents' full scores and reasoning attached.
Makes a final binary confirmed/rejected decision on each. Waits up to 65s before
calling to let the detect node's TPM window clear (both share `GROQ_API_KEY`).

- Model: `openai/gpt-oss-120b` via `GROQ_API_KEY`
- Prompt: `audit-tiebreaker-prompt` (Langfuse)

Confirmed findings are appended to `confirmed_findings`.

---

### Node 6 — `merge_node.py`

Takes everything in `confirmed_findings` and builds the final report.

1. **Slither internal dedup** — collapses Slither sub-checks for the same vulnerability
   (e.g. reentrancy-eth, reentrancy-no-eth, reentrancy-benign → one finding)
2. **Cross-engine merge** — if an LLM finding and a Slither finding describe the same
   vulnerability (same SWC ID or >40% category overlap), they're merged into one finding
   tagged `source: "BOTH"`, keeping the LLM's description and the higher severity
3. Stamps confidence from debate scores, sorts by severity, assigns `VULN-XXX` IDs
4. Builds the final JSON report sent to the frontend

---

### Prompts — `data/instructions/`

Each pipeline node has its own prompt file, managed via **Langfuse** (prompt versioning
without redeployment). Local files are used as fallback when Langfuse is unavailable.

| Langfuse name | Local file | Used by |
|---|---|---|
| `audit-detect-prompt` | `detection_prompt.txt` | llm_detect |
| `audit-critique-prompt` | `critique_prompt.txt` | critique |
| `audit-verify-prompt` | `verify_prompt.txt` | verify |
| `audit-tiebreaker-prompt` | `tiebreaker_prompt.txt` | tiebreaker |

To push local prompt edits to Langfuse:
```bash
cd backend/
python sync_prompts_to_langfuse.py
```

---

## Frontend

The frontend is a **Next.js + TypeScript** app styled with **Tailwind CSS**.

### Key files

| File | Purpose |
|---|---|
| `package.json` | Dependencies and npm scripts |
| `tailwind.config.ts` | Custom dark cyberpunk colour palette and fonts |
| `globals.css` | Global styles, fonts, scrollbar, dot-grid background |
| `layout.tsx` | Root HTML shell |
| `report.ts` | TypeScript types for the full API response |

### Screen 1 — `page.tsx` (upload)

Four states: `idle → scanning → done | error`.

- **idle:** file upload box and "Detect Vulnerabilities" button
- **scanning:** animated radar with rotating status messages cycling every ~2 seconds
- **done:** unmounts upload, renders `<ReportView>`
- **error:** shows error and "Try again" button

### Upload component — `FileUpload.tsx`

Drag-and-drop file picker, `.sol` only. Shows filename and size once selected.

### Screen 2 — `ReportView.tsx` (results)

**Header card** — contract name, Solidity version, line count, engine status badges.

**Stats bar** — finding counts per severity (CRITICAL / HIGH / MEDIUM / LOW / Total).

**Two-column panel:**
- Left sidebar — scrollable vulnerability list, first 7 shown with "Show N more"
- Right panel — full detail: severity, description, exploitation scenario, code viewer,
  recommendation, confidence, detected-by badges (LLM / Slither / Both), SWC ID

**Code viewer** — shows vulnerable lines with 3 lines of context highlighted in red.
Uses a lightweight inline Solidity tokeniser (no external library).

---

## Running locally

Prerequisites: Python 3.11+, Node.js 18+, and a free [Groq API key](https://console.groq.com/keys).

**Backend**
```bash
cd backend/
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then fill in your Groq key(s)
uvicorn main:app --port 8000
```
Slither and `solc-select` are installed by `requirements.txt`. Keep the venv activated so they are
on your `PATH`; the Slither node calls them as subprocesses.

**Frontend**
```bash
cd frontend/
npm install
npm run dev                   # http://localhost:3000
```
The frontend calls `http://localhost:8000` unless `NEXT_PUBLIC_API_URL` is set.

A full audit takes about 1–2 minutes: the tiebreaker waits up to 60 s so it does not hit the
Groq per-minute token limit shared with the detect agent.

---

## Required secrets

| Variable | Where | Purpose |
|---|---|---|
| `GROQ_API_KEY` | Render / `.env` | detect node + tiebreaker |
| `GROQ_API_KEY_2` | Render / `.env` (optional) | critique node; falls back to `GROQ_API_KEY` |
| `GROQ_API_KEY_3` | Render / `.env` (optional) | verify node; falls back to `GROQ_API_KEY` |
| `LANGFUSE_PUBLIC_KEY` | Render (optional) | prompt management |
| `LANGFUSE_SECRET_KEY` | Render (optional) | prompt management |
| `NEXT_PUBLIC_API_URL` | Vercel | backend URL |

---

## Evaluation

The pipeline is benchmarked against the **SmartBugs Curated** dataset (143 Solidity contracts
with known vulnerabilities).

### Results (all 143 contracts, run 2026-06-07)

| Mode | Precision | Recall | F1 |
|---|---|---|---|
| Detector agent, raw (pre-debate) | 22.6% | 49.3% | 0.310 |
| Slither, raw (MEDIUM+) | 61.1% | 47.8% | 0.537 |
| Debate, LLM-confirmed findings | 43.4% | 42.5% | 0.429 |
| **Debate, both engines** | **44.6%** | **55.6%** | **0.495** |

The debate nearly doubles the detector's precision (22.6% → 43.4%, +0.12 F1) by rejecting false
positives, at a small cost in recall. Adding Slither's confirmed findings raises recall to 55.6%.
This run used the Llama models the pipeline was configured with at the time; the full report is in
`backend/evaluation/reports/evaluation_20260607_032323.txt`.

### Running the evaluation

Clone the dataset into the repository root first:
```bash
git clone https://github.com/smartbugs/smartbugs-curated.git
```
Then, with the backend running:

```bash
cd backend/
python -m evaluation.test_smartbugs
```

Generate visualisations from a report:
```bash
python evaluation/visualize_results.py  # uses latest report automatically
```
