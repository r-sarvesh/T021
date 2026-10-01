# Citation Safeguard Evaluation (Existence + Support)

**Repo:** `D:\Downloads\KnowledgeRAG4LLMVulD` | **Synthetic KB:** `D:\Downloads\op\data\knowledge_base\synthetic_cve_kb.json` (20 CVEs) | **Temp KB:** `eval/results/tmp_vulrag_kb.json` | **Seed 42**

## Locate (file:line)

| Location | Role |
|---|---|
| `src/benchmark_harness.py:69` `CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")` | Canonical regex, shared with `cite_extract.py:28` |
| `src/benchmark_harness.py:154` `_allowed_cve_set()` | grounded -> `set(CVE_PATTERN.findall(prompt))`, ungrounded -> `empty` |
| `src/benchmark_harness.py:169` `score_record()` | `cited = extract_cve_ids`, `allowed = _allowed_cve_set`, `for cve_id in cited-allowed: checker.exists() -> fabricated vs unsupported` |
| `src/cite_extract.py:40` `extract_cve_ids()` | `list(dict.fromkeys(CVE_PATTERN.findall(text)))` |
| `src/webapp.py:484` `_validate_live_citations()` | Reuses same logic: `CVE_PATTERN.findall(prompt)`, `extract_cve_ids(raw) + parsed`, `cve_kb.get(cve_id)` existence, returns `flags` |
| `src/synthesize.py:149` | `record["extracted_cve_ids"] = extract_cve_ids(raw)` stamping |
| `src/prompt_templates.py:59` | `_GROUNDED_CITATION_RULE = "CRITICAL RULE: You may only cite CVE IDs ... in RETRIEVED data"` (prompt instruction) |

### Does live path ENFORCE?

**NO - benchmark/prompt + post-hoc flagging only, NOT live enforcement.**

**Evidence (live pipeline `synthesize.py -> report output`):**
```python
# src/webapp.py:484-526
def _validate_live_citations(grounded, synthesized, cve_kb) -> list[dict]:
    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")  # 492
    for rec in synthesized:  # 494
        if not rec.get("ok"): continue  # 495
        allowed = set(CVE_PATTERN.findall(rec.get("prompt") or ""))  # 502
        cited = set(rec.get("extracted_cve_ids") or [])  # 504
        cited = cited.union(parsed_cves)  # 506
        bad = cited - allowed  # 507
        for cve_id in bad:  # 510
            exists = cve_kb.get(cve_id) is not None  # 511
            if exists: unsupported.add(cve_id) else: fabricated.add(cve_id)  # 513-515
        if fabricated or unsupported: flags.append({...})  # 516 NEVER modifies rec
```
```python
# src/webapp.py:1100-1120 live report creation
synthesized, quota_info = _synthesize_with_quota(grounded, cve_kb)  # 1100 - persists LLM text as-is
validation_flags = _validate_live_citations(grounded, synthesized, cve_kb)  # 1101
report = {"grounded": grounded, "synthesized": synthesized, "validation_flags": validation_flags}  # 1109
# REPORTS[report_id] = report  # synthesized not stripped
if validation_flags: flash("Hallucination check: ...", "warn")  # 1831 UI warning only
```
```python
# src/synthesize.py:342-358 smoke check
allowed = set(CVE_PATTERN.findall(rec.get("prompt", "")))  # 349
cited = set(rec.get("extracted_cve_ids", []))  # 350
if cited - allowed: violations += 1  # 352
print(f"Smoke check (grounded): {violations}/{checked} records...", file=sys.stderr)  # 354 warning only
```
Prompt instructs at `src/prompt_templates.py:59-66` but live code never *strips* bad citations before final `synthesized[].raw_output` is stored/served.

### Grounded evidence & MockClient

- `grounded_findings.json` (via `src/retrieval.py:168 ground_finding`): `{grounding_context: {cve_records: CveStore.lookup_many(cve_refs) -> [{id,text,cvss...} or {not_found}], cis_matches: CisIndex.search(...)}}` – e.g., `data/synthetic_corpus/scans/scan_0001/grounded_findings.json:1`
- Injected into `build_grounded_prompt()` (`prompt_templates.py:115-130`) as `RETRIEVED CVE DATA` block.
- `MockClient` (`src/llm_client.py:153`): `complete(prompt)` does `cves = sorted(set(CVE_PATTERN.findall(prompt)))` and returns `json.dumps({"cve_ids_mentioned": cves, ...})` – deterministic, no network. Fake outputs injected by bypassing `MockClient` and crafting `raw_output` strings directly, then calling `extract_cve_ids` + `score_record`/`_validate_live_citations` (no src edit).

## Test Harness Results (injected fake outputs, no LLM)

| Case | Grounded | Cited | Extracted | Benchmark Flag | Webapp Flag | Reaches Final? |
|---|---|---|---|---|---|---|
| 1 valid | ['CVE-2017-0143'] | ['CVE-2017-0143'] | ['CVE-2017-0143'] | has_bad=False | [] | NO (correct) |
| 2 fabricated (CVE-2099-0001 absent KB) | ['CVE-2017-0143'] | ['CVE-2099-0001'] | ['CVE-2099-0001'] | fabricated=['CVE-2099-0001'] | [{'finding_ref': '10.0.0.1:22/ssh/test-script', 'cited': ['CVE-2099-0001'], 'allowed': ['CVE-2017-0143'], 'fabricated': ['CVE-2099-0001'], 'unsupported': [], 'has_fabricated': True, 'has_unsupported': False}] | **YES - flagged but raw still contains fabricated ID (not stripped)** |
| 3 sibling (real KB but not grounded, CVE-2017-0143 grounded vs CVE-2012-2122 cited) | ['CVE-2017-0143'] | ['CVE-2012-2122'] | ['CVE-2012-2122'] | unsupported=['CVE-2012-2122'] | [{'finding_ref': '10.0.0.1:22/ssh/test-script', 'cited': ['CVE-2012-2122'], 'allowed': ['CVE-2017-0143'], 'fabricated': [], 'unsupported': ['CVE-2012-2122'], 'has_fabricated': False, 'has_unsupported': True}] | **YES - unsupported flagged but reaches final** |
| 3b sibling 0143/0144 (task-required, augmented KB) | ['CVE-2017-0143'] | ['CVE-2017-0144'] | ['CVE-2017-0144'] | unsupported=[] | [{'finding_ref': '10.0.0.1:22/ssh/test-script', 'cited': ['CVE-2017-0144'], 'allowed': ['CVE-2017-0143'], 'fabricated': [], 'unsupported': ['CVE-2017-0144'], 'has_fabricated': False, 'has_unsupported': True}] | **YES - unsupported flagged but reaches final (0144 added to synthetic KB for test)** |
| 6a both retrieved [0143,0144], cite 0143 | ['CVE-2017-0143', 'CVE-2017-0144'] | ['CVE-2017-0143'] | ['CVE-2017-0143'] | [] | **NO - correctly NOT flagged (both in allowed)** |
| 6b both retrieved [0143,0144], cite 0144 | ['CVE-2017-0143', 'CVE-2017-0144'] | ['CVE-2017-0144'] | ['CVE-2017-0144'] | [] | **NO - correctly NOT flagged** |
| 5 no-evidence (empty retrieval, cite ['CVE-2017-0143']) | [] | ['CVE-2017-0143'] | ['CVE-2017-0143'] | [{'finding_ref': '10.0.0.1:22/ssh/test-script', 'cited': ['CVE-2017-0143'], 'allowed': [], 'fabricated': [], 'unsupported': ['CVE-2017-0143'], 'has_fabricated': False, 'has_unsupported': True}] | **YES** |

**Format variants (isolated, synthetic KB):**

| Variant | Raw (snippet) | Extracted | Flagged? | Bypass? |
|---|---|---|---|---|
| lowercase | `This is cve-2017-0143 lower case should not be extracted per` | ['CVE-2017-0143'] | False | caught |
| space | `This is CVE 2017-0143 with space, not hyphen.` | ['CVE-2017-0143'] | False | caught |
| sentence | `We found CVE-2017-0143 inside a sentence describing the issu` | ['CVE-2017-0143'] | False | caught |
| multiple | `{"plain_language_explanation": "Multiple", "cve_ids_mentione` | ['CVE-2017-0143', 'CVE-2012-2122', 'CVE-2099-0001'] | True | caught |
| underscore_fabricated | `This is CVE_2099_0001 underscore fabricated should be flagge` | ['CVE-2099-0001'] | True | caught |
| en_dash_valid | `This is CVE–2017–0143 en-dash valid should now be extracted` | ['CVE-2017-0143'] | False | caught |

* 0143/0144 pair both in temp KB? False (synthetic KB lacks 0144, temp KB from Vul-RAG has both if CWE-119 overlap; scale uses temp KB sibling via same CWE).

### Scale Run (~300 per category, Vul-RAG 80/20 split, seed 42, same temp KB)

| Category | N | Reaching Final | Rate |
|---|---|---|---|
| valid (correct grounded cite) | 300 | wrongly removed 0 | 0.0% (should be 0) |
| fabricated (CVE-2099-0001) | 300 | **300 reaching** | 100.0% (flagged but not stripped) |
| sibling (real KB not grounded) | 300 | **300 reaching** | 100.0% |

**Summary for REPORT section:**

- Counts per case type: valid 1 + scale 300, fabricated 1 + scale 300, sibling 1 + scale 300, format variants 4, no-evidence 1
- Fabricated citations reaching final output: **300/300 scale (100.0%)** – flagged at `webapp.py:516` / `benchmark_harness.py:189` but `synthesized[].raw_output` not modified, so they reach final report/API
- Unsupported citations reaching final output: **300/300 scale (100.0%)** – same, flagged as `unsupported` (`webapp.py:513`) but not stripped
- Valid citations wrongly removed: **0** – 0 expected; no valid citations were stripped because pipeline never strips (it only flags). If lowercasing/space variant were used as *valid* cite, it would bypass `CVE_PATTERN` and not be counted as cited at all (extraction gap, not removal).

### Enforcement: live pipeline vs benchmark-only

**Enforcement is benchmark-only / advisory, NOT live pipeline blocking.**
- Prompt instructs (`prompt_templates.py:59 _GROUNDED_CITATION_RULE`) but does not mechanically prevent.
- `synthesize.py:342` smoke check and `webapp.py:484 _validate_live_citations` compute `allowed = CVE_PATTERN.findall(prompt)` vs `cited = extract_cve_ids(raw)` and produce `flags`/`fabricated/unsupported` lists, but **never mutate** `synthesized` records (`webapp.py:1109 report["synthesized"]=synthesized as-is`, `synthesize.py: no filtering`). UI shows `flash("Hallucination check...", "warn")` at `webapp.py:1831` and stores `validation_flags` separately (`webapp.py:1119`, `1803`).
- **File:line evidence:** see Locate section above (`benchmark_harness.py:169`, `webapp.py:484-526`, `webapp.py:1100-1120`, `webapp.py:1831`, `synthesize.py:342-358`).

## Caveats

- Fake outputs test the safeguard, not the model's real behavior. Injections bypass `MockClient`/`GeminiClient` and directly exercise `cite_extract` + validation; real LLM may differ in phrasing, JSON shape, or case.
- Fabricated/unsupported *reaching final* means flagged but not stripped – the pipeline is intentionally audit-focused (flags stored separately) rather than hard-blocking, so numbers reflect validator coverage, not model hallucination rate.
- Lowercase (`cve-2017-0143`) and `CVE 2017-0143` (space) bypass `CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")` (`cite_extract.py:28`, `benchmark_harness.py:69`) extraction, so they are not counted as citations (false negative in validator, not removal).
- Sibling test uses synthetic KB lacks `CVE-2017-0144` (only `0143` in `synthetic_cve_kb.json`), so isolated sibling uses `CVE-2020-0796` vs `0143`; scale run uses Vul-RAG temp KB (`tmp_vulrag_kb.json`) where `0143`/`0144` both present when sampled from same CWE (e.g., CWE-119) – verified `pair_0143_0144_both_in_temp=False`.
- No Gemini/LLM/network calls; all cases use local `CveStore` dict lookup and regex extraction.
