# Vul-RAG Retrieval-Only Evaluation

**Repo:** `D:\Downloads\KnowledgeRAG4LLMVulD`  | **Seed:** `42` | **Total unique CVE:** `1325` | **Indexed (80%):** `1059` | **Unseen (20%):** `266` | **Temp KB:** `D:\Downloads\op\eval\results\tmp_vulrag_kb.json`

## Summary Table

| Query Set | Mode | N | Top-1 Acc | Top-5 Acc | MRR | CWE-match (wrong CVE, right CWE) | Sibling Confusions |
|---|---|---|---|---|---|---|---|
| In-KB (indexed) | truncated (first 50% desc) | 1059 | 0.936 (93.6%) | 0.970 (97.0%) | 0.951 (95.1%) | 36 (0.034 (3.4%)) | 36 |
| In-KB (indexed) | knowledge (extracted) | 921 | 0.516 (51.6%) | 0.724 (72.4%) | 0.612 (61.2%) | 182 (0.198 (19.8%)) | 182 |

### Per-Threshold In-KB Coverage / Precision / Correct Lost

| Threshold | Mode | Coverage (answered/N) | Precision@Coverage (correct/answered) | Correct Lost (lost/correct_at_0) | Correct Retained |
|---|---|---|---|---|---|
| 0.0 | truncated | 1059/1059 (100.0%) | 991/1059 (93.6%) | 0/991 (0.0%) | 991 |
| 0.1 | truncated | 1059/1059 (100.0%) | 991/1059 (93.6%) | 0/991 (0.0%) | 991 |
| 0.2 | truncated | 1054/1059 (99.5%) | 991/1054 (94.0%) | 0/991 (0.0%) | 991 |
| 0.3 | truncated | 1053/1059 (99.4%) | 991/1053 (94.1%) | 0/991 (0.0%) | 991 |
| 0.4 | truncated | 1007/1059 (95.1%) | 979/1007 (97.2%) | 12/991 (1.2%) | 979 |
| 0.5 | truncated | 973/1059 (91.9%) | 956/973 (98.3%) | 35/991 (3.5%) | 956 |
| 0.0 | knowledge | 921/921 (100.0%) | 475/921 (51.6%) | 0/475 (0.0%) | 475 |
| 0.1 | knowledge | 921/921 (100.0%) | 475/921 (51.6%) | 0/475 (0.0%) | 475 |
| 0.2 | knowledge | 859/921 (93.3%) | 467/859 (54.4%) | 8/475 (1.7%) | 467 |
| 0.3 | knowledge | 451/921 (49.0%) | 334/451 (74.1%) | 141/475 (29.7%) | 334 |
| 0.4 | knowledge | 166/921 (18.0%) | 152/166 (91.6%) | 323/475 (68.0%) | 152 |
| 0.5 | knowledge | 43/921 (4.7%) | 43/43 (100.0%) | 432/475 (90.9%) | 43 |

### Unseen Queries (20% held out, truncated) - Abstention

| Threshold (cosine) | Correct Abstention | False Citation | N |
|---|---|---|---|
| 0.0 | 0/266 (0.0%) | 266/266 (100.0%) | 266 |
| 0.1 | 0/266 (0.0%) | 266/266 (100.0%) | 266 |
| 0.2 | 6/266 (2.3%) | 260/266 (97.7%) | 266 |
| 0.3 | 64/266 (24.1%) | 202/266 (75.9%) | 266 |
| 0.4 | 152/266 (57.1%) | 114/266 (42.9%) | 266 |
| 0.5 | 206/266 (77.4%) | 60/266 (22.6%) | 266 |

**Existing threshold in `retrieval.py`:** *NONE* - `CveStore` uses exact key lookup (no similarity), `CisIndex.search` returns top-k filtered by `applies_to` with no score threshold (only abstains when no candidate tags or empty vocab). For this eval, default is treated as `0.0` (never abstain); sweep shows trade-off above.

### Combined Table per Threshold (truncated mode primary)

| Threshold | In-KB Coverage | In-KB Precision | In-KB Correct Lost | Unseen Correct Abstention | Unseen False Citation | Score (retained+abstain) |
|---|---|---|---|---|---|---|
| 0.0 | 100.0% (1059/1059) | 93.6% | 0/991 (0.0%) | 0.0% (0/266) | 100.0% | 991 |
| 0.1 | 100.0% (1059/1059) | 93.6% | 0/991 (0.0%) | 0.0% (0/266) | 100.0% | 991 |
| 0.2 | 99.5% (1054/1059) | 94.0% | 0/991 (0.0%) | 2.3% (6/266) | 97.7% | 997 |
| 0.3 | 99.4% (1053/1059) | 94.1% | 0/991 (0.0%) | 24.1% (64/266) | 75.9% | 1055 |
| 0.4 | 95.1% (1007/1059) | 97.2% | 12/991 (1.2%) | 57.1% (152/266) | 42.9% | 1131 |
| 0.5 | 91.9% (973/1059) | 98.3% | 35/991 (3.5%) | 77.4% (206/266) | 22.6% | 1162 |

### Combined Table per Threshold (knowledge mode)

| Threshold | In-KB Coverage | In-KB Precision | In-KB Correct Lost | Unseen Correct Abstention | Unseen False Citation | Score |
|---|---|---|---|---|---|---|
| 0.0 | 100.0% (921/921) | 51.6% | 0/475 (0.0%) | 0.0% | 100.0% | 475 |
| 0.1 | 100.0% (921/921) | 51.6% | 0/475 (0.0%) | 0.0% | 100.0% | 475 |
| 0.2 | 93.3% (859/921) | 54.4% | 8/475 (1.7%) | 2.3% | 97.7% | 473 |
| 0.3 | 49.0% (451/921) | 74.1% | 141/475 (29.7%) | 24.1% | 75.9% | 398 |
| 0.4 | 18.0% (166/921) | 91.6% | 323/475 (68.0%) | 57.1% | 42.9% | 304 |
| 0.5 | 4.7% (43/921) | 100.0% | 432/475 (90.9%) | 77.4% | 22.6% | 249 |

**Suggestion (maximizing retained + abstention, truncated mode):** threshold **0.5** (score 1162 = retained 956 + abstain 206) - *suggestion only, not tuned* . Knowledge mode best: **0.0** (score 475).

## Caveats

- **Dataset:** Linux kernel CVEs from `Linux_kernel_clean_data_top10_CWEs.json` (top-10 CWEs, 2740 entries -> 1325 unique CVE). Covers kernel-specific weakness classes (CWE-416, CWE-476, etc.), not general vulns.
- **Function-level code was not used:** Evaluation uses only `cve_id`, `cwe`, `cve_description` and `vulnerability knowledge` text; `code_before_change`, `code_after_change`, `patch`, `function_modified_lines` were ignored per task, so this does NOT measure code-level vulnerability detection.
- **Retrieval vs detection:** This measures retrieval and abstention accuracy (can we retrieve the right CVE entry from its description/knowledge), not vulnerability-detection accuracy. It is **NOT comparable to Vul-RAG's reported numbers** (which evaluate LLM-based vulnerable vs patched code classification).
- **Demo CVEs not in dataset:** The demo CVEs used elsewhere (`CVE-2017-0143` EternalBlue/SMBv3, `CVE-2011-2523` vsftpd backdoor, `CVE-2014-0160` Heartbleed, etc.) are **not in this Linux kernel dataset** (verified: overlap check shows kernel CVEs are `CVE-2006-3635` etc.; demo synthetic KB at `data/knowledge_base/synthetic_cve_kb.json` contains only 20 synthetic entries). Results here do not reflect performance on those demo vulns.
- **CveStore is exact-ID lookup with no threshold; this evaluates a TF-IDF retriever mirroring CisIndex.** `CveStore` in `src/retrieval.py:46` is `dict` key lookup (`lookup(cve_id)`) with no vectorization, no `similarity_score`, no `top_k`, no abstention threshold. This eval builds a *new* TF-IDF index (`TfidfVectorizer(stop_words='english') + cosine_similarity`) over the temp KB text to mirror `CisIndex.search` logic for retrieval simulation.
- **Assumptions:** `cve_id` is the join key (`CVE_id` in knowledge == `cve_id` in dataset); `cwe` primary is first `CWE-xxx` in list; truncated = first 50% words; knowledge query = concatenated `purpose`+`function`+`analysis`+`solution`+`vulnerability_behavior` fields; TF-IDF retrieval mirrors `CisIndex` logic but without `service_tags` filtering (CVE text only); thresholds sweep is around implicit `0.0` (no abstention) in `retrieval.py`.
- **No LLM/network calls:** All retrieval is local TF-IDF (`sklearn`) over temp KB at `eval/results/tmp_vulrag_kb.json` in `CveStore` schema; real KB `data/knowledge_base/synthetic_cve_kb.json` unchanged.
