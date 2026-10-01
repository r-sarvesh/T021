# AI-Powered Cybersecurity Health Assessment Platform

A capstone project (Rajalakshmi Engineering College) that turns raw Nmap scan results into a prioritised, evidence-backed security assessment, and **measures how much RAG grounding reduces LLM hallucinations** in the process.

> Base paper: *Vul-RAG* (Fudan University, ACM TOSEM 2026)

## What it does

1. Takes an **Nmap XML** scan as input.
2. Scores each finding with a **deterministic rule engine** (no LLM involved).
3. Retrieves supporting evidence from **NVD**, **CISA KEV** and **CIS Benchmark** controls.
4. Uses **Google Gemini** to write remediation guidance, grounded in the retrieved evidence.
5. **Checks every CVE the model cites** and flags anything not supported by the evidence.
6. Presents the results in a dashboard for **Admin** and **Security Analyst** roles, with PDF report export.

## Research contribution: hallucination benchmark

We compare grounded and ungrounded LLM output and classify citation failures into two types:

| Type | Meaning |
|---|---|
| `fabricated_cve` | The CVE ID does not exist. |
| `unsupported_cve` | The CVE is real but was not in the retrieved evidence. |

Example caught by the live benchmark: the ungrounded model cited CVE-2017-0144 (a sibling of the EternalBlue CVE, never provided to it) for an SMB finding.

Grounded runs reached **21/21 correct citations (100% citation precision)**. This is precision over the citations made, not over all findings.

Harnesses and results are in `eval/`.

## Architecture

```
Nmap XML ──► nmap_parser ──► rule_engine ──► retrieval ──► synthesize ──► webapp (Flask JSON API) ──► Next.js UI
                                  ▲               ▲              │
                              scoring        NVD / CISA KEV /    └─► hallucination detection (cite_extract)
                                             CIS (TF-IDF)
```

| Stage | File (in `src/`) |
|---|---|
| Parse Nmap XML | `nmap_parser.py` |
| Deterministic scoring | `rule_engine.py` |
| NVD ingestion | `ingest_nvd.py` |
| Retrieval (TF-IDF over CVE/CIS) | `retrieval.py` |
| LLM synthesis + hallucination flags | `synthesize.py`, `cite_extract.py` |
| LLM client | `llm_client.py` |
| Web API | `webapp.py` |

TF-IDF was chosen over neural embeddings on purpose: CVE and CIS text is keyword-dense. Dense retrieval is listed as future work.

`UNSCORED` is an intentional pipeline state, not a bug.

## Tech stack

- **Backend:** Python, Flask (pure JSON API)
- **Frontend:** Next.js 16, React 19, TypeScript, Tailwind, shadcn/ui
- **LLM:** Google Gemini API (free tier)
- **Data:** NVD API 2.0, CISA KEV, CIS Benchmarks
- **Reports:** ReportLab (WeasyPrint fallback)
- **Scanning:** Nmap
- **Testing:** Playwright

## Getting started

### Prerequisites

- Python 3.10+
- Node.js 18+
- A Gemini API key from https://aistudio.google.com/app/apikey

### 1. Configure the API key

Create `.env.local` in the project root (it is git-ignored):

```
GEMINI_API_KEY=your_key_here
```

Never commit this file. If a key is ever exposed, rotate it immediately.

### 2. Run the backend

```bash
pip install flask requests scikit-learn reportlab
python start_flask.py
```

Set environment variables in the same shell that launches Flask (on Windows, `Start-Process` does not inherit them reliably).

### 3. Run the frontend

```bash
npm install
npm run dev
```

Open http://localhost:3000.

### 4. Try a demo scan

Upload `vsftpd_test.xml` (a single-finding scan) through the UI — safe to run against the live free tier.

> **⚠ Do not upload `fixtures/quota_test_25findings_DO_NOT_RUN_LIVE.xml` against a live key.** Its 25 findings would request 25 syntheses against the 20/day free-tier quota. Use it only with the offline MockClient (launch Flask with `GEMINI_API_KEY` unset).

## Repository layout

```
src/        Backend pipeline (parser, rules, retrieval, synthesis, web API)
app/        Next.js pages
components/ React components
eval/       Hallucination benchmark harnesses and results
tests/      Parity tests (Jinja routes vs Next.js pages) and browser tests
fixtures/   Nmap XML test fixtures
scripts/    One-off maintenance scripts
```

Demo files `demo_dashboard.html` and `benchmark_exhibit.html` are generated from real Gemini runs and should not be edited by hand.



## License

_Add a license (e.g. MIT), or state "Academic project – all rights reserved"._
