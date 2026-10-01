# RAG Retrieval Schema — CVE & CIS Benchmark Grounding

This defines what gets stored, how it's chunked/embedded, and how a finding
from the Nmap/OpenVAS parser turns into a retrieval query and a grounded
LLM prompt.

---

## 1. Two separate knowledge bases

Keep CVE and CIS data as **separate collections**, not one merged index.
They answer different questions ("what is this vulnerability and how bad
is it" vs "what's the hardening standard for this service"), and merging
them causes retrieval to pull the wrong type of document for a query.

| Collection | Source | Answers |
|---|---|---|
| `cve_kb` | NVD API / NVD JSON feeds | "What is CVE-X, how severe, how exploitable" |
| `cis_kb` | CIS Benchmarks (PDF/XCCDF) | "How should this service/OS be configured" |

---

## 2. `cve_kb` document schema

Each CVE becomes one record. Don't chunk a CVE description across multiple
vectors — they're short enough to embed whole, and splitting them makes
retrieval return half a finding.

```json
{
  "id": "CVE-2017-0143",
  "text": "Full NVD description, used for embedding",
  "cvss_v3_score": 8.1,
  "cvss_v3_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cvss_severity": "HIGH",
  "cwe_ids": ["CWE-94"],
  "affected_products": ["microsoft:windows_server_2012_r2", "..."],
  "published_date": "2017-03-16",
  "last_modified_date": "2018-10-12",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0143"],
  "exploit_known": true,
  "kev_listed": true,
  "kev_date_added": "2021-11-03"
}
```

Notes:
- `kev_listed` (CISA Known Exploited Vulnerabilities catalog) is worth
  pulling in separately — it's a strong, deterministic priority signal
  your rule engine can use *without* the LLM, and it's a great thing to
  cite in the executive summary ("actively exploited in the wild").
- Embed on `text` (description) only. Store the structured fields as
  metadata for filtering, not for embedding — CVSS vectors embed poorly.

## 3. `cis_kb` document schema

CIS Benchmarks are long PDFs per platform (Windows Server, Apache, MySQL,
etc.). Chunk **per control/recommendation**, not per page — page-based
chunking splits a single control's rationale from its remediation steps.

```json
{
  "id": "CIS-MSFT-WS2012R2-2.3.10.1",
  "benchmark": "CIS Microsoft Windows Server 2012 R2 Benchmark v3.0.0",
  "section": "2.3.10 Network Security",
  "control_title": "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'",
  "text": "Full control text: rationale + remediation steps, used for embedding",
  "applies_to": ["windows_server_2012_r2", "smb", "netbios"],
  "level": 1,
  "remediation_type": "registry"
}
```

`applies_to` is the key filter field — tag it with the same service/OS
vocabulary your Nmap parser produces (`smb`, `rdp`, `mysql`, `apache_httpd`,
`openssh`, `windows_server_2012_r2`, etc.) so retrieval can be filtered
before the vector search, not after.

---

## 4. Turning a parsed finding into a retrieval query

This is the part that actually connects your rule engine to the RAG layer.
For each finding object coming out of the Nmap parser:

```json
{
  "host": "192.168.1.10",
  "port": 445,
  "service": "microsoft-ds",
  "product": "Windows Server 2012 R2 microsoft-ds",
  "nse_script": "smb-vuln-ms17-010",
  "cve_refs": ["CVE-2017-0143"],
  "raw_output": "VULNERABLE: Remote Code Execution vulnerability..."
}
```

Retrieval steps:

1. **CVE lookup is a direct key match, not a semantic search**, when
   `cve_refs` is non-empty — fetch `cve_kb["CVE-2017-0143"]` directly by ID.
   Only fall back to embedding-similarity search over `cve_kb.text` when
   there's no CVE ID (e.g. a cert-expiry or misconfig finding with just a
   text description).
2. **CIS lookup is a filtered semantic search**: filter `cis_kb` by
   `applies_to` containing the service/OS tags (`smb`, `windows_server_2012_r2`),
   then rank by embedding similarity between the finding's `raw_output`
   text and each control's `text`. Return top-k (start with k=3).
3. Both results get attached to the finding as `grounding_context` before
   it ever reaches the LLM.

This two-track approach (exact ID match for CVE, filtered vector search
for CIS) matters for your hallucination benchmark — it's the mechanism
that makes "grounded" mean something concrete and reproducible rather
than "we also gave the LLM a vector database."

---

## 5. Grounded prompt construction

The LLM never sees raw scan output alone — it sees the finding *plus*
retrieved evidence, and is constrained to only cite what's provided:

```
FINDING:
Host 192.168.1.10, port 445 (microsoft-ds)
Nmap NSE flagged: smb-vuln-ms17-010

RETRIEVED CVE DATA:
CVE-2017-0143 | CVSS 8.1 HIGH | CISA KEV: Yes (added 2021-11-03)
Description: [NVD text]

RETRIEVED CIS CONTROL:
CIS-MSFT-WS2012R2-2.3.10.1 — [control title]
[control text]

INSTRUCTIONS:
Summarize this finding for a non-technical stakeholder. Only reference
the CVE ID, CVSS score, and CIS control shown above. Do not introduce
any CVE, CVSS score, or benchmark ID not present in the retrieved data
above. If retrieved data is insufficient to assess severity, say so
explicitly rather than estimating.
```

That last instruction is what you'll toggle off for the **ungrounded
baseline** in your benchmark — same finding, no retrieved context, same
instruction to name CVE/CVSS if known. Comparing the two outputs on the
same findings set is your hallucination-rate measurement.

---

## 6. Vector DB / stack suggestion

For a project of this scope, don't over-engineer the infra:

- **Embeddings**: any sentence-transformer (e.g. `all-MiniLM-L6-v2`) is
  enough — you're not doing open-domain search, your corpus is narrow
  (CVE descriptions + CIS controls).
- **Store**: a local vector store (Chroma or FAISS) is sufficient for
  thesis/demo scale. No need for a managed vector DB unless you want to
  showcase production-readiness.
- **CVE data refresh**: pull from the NVD API on a schedule (daily/weekly)
  rather than embedding the entire NVD — scope it to CVEs relevant to the
  products/services your parser recognizes (Windows, Apache, MySQL,
  OpenSSH, etc.) to keep the index small and retrieval precise.
- **CIS data**: CIS Benchmarks require a (free) account to download:
  ingest once, chunk by control, re-embed only when a new benchmark
  version is released.

---

## 7. Why this design matters for your evaluation section

Your project's differentiator is measuring hallucination reduction, so
the schema needs to make grounding **falsifiable** — i.e. you can check,
per finding, whether the LLM's output CVE IDs and CVSS scores are a
strict subset of what was actually retrieved. That check itself becomes
your automated scoring function for the benchmark: no manual review
needed, just a set-membership comparison between
`LLM_output.cited_cves` and `grounding_context.cve_refs`.

---

## 8. Benchmark scoring methodology (formal decisions)

Section 7 established the general idea — a subset check. This section
documents the four concrete scoring decisions made when the benchmark
harness (`benchmark_harness.py`) was actually built, so the thesis
methodology write-up matches the code exactly rather than the looser
description above.

### 8.1 Two distinct failure modes, scored separately

A cited CVE ID that isn't in the grounding context can fail in two
different ways, and conflating them loses information:

- **`fabricated_cve`** — the cited ID does not exist in NVD at all (the
  model invented it outright).
- **`unsupported_cve`** — the cited ID is a real, existing CVE, but it
  was not present in the retrieved/injected context for that specific
  finding (the model cited something true but irrelevant/unverified
  here).

Existence is checked against `cve_kb` (offline mode) or a live NVD
lookup (`--nvd` flag) — see `ingest_nvd.py`'s `fetch_cve()` for the same
lookup logic reused by the harness. Grounded-variant output should be
structurally incapable of `fabricated_cve` (it was never shown a CVE ID
that doesn't exist), so seeing one there would indicate a template or
extraction bug, not a genuine grounding failure — worth flagging in
write-up if it ever occurs, rather than reported as a normal result.

Both counts are reported as separate columns in the scored JSONL and the
summary report — never merged into one "hallucination rate" number.

### 8.2 Two denominators reported for every rate, with raw counts

Every rate is reported two ways, each with numerator/denominator visible
(e.g. `2/2 (100.0%)`, not just `100%`):

- **Per-finding rate**: % of findings with at least one bad citation.
- **Per-citation rate**: % of all individual CVE citations, across the
  whole corpus, that were bad.

These diverge whenever a single finding's output cites multiple CVEs, so
reporting only one hides real information. Raw counts are shown
alongside every percentage because the corpus is small (starting at
20-40 findings) — "100%" reads very differently as 2/2 versus 40/40, and
the summary report should never let that ambiguity stand.

### 8.3 CVE-ID leakage fix in the ungrounded prompt

Discovered during implementation, not anticipated in the original
design (sections 4-5 above): the ungrounded prompt's FINDING block was
rendering NSE `raw_output` verbatim, which meant the actual CVE ID
(e.g. `CVE-2017-0143`, present in Nmap's own script output) leaked into
the "ungrounded" prompt even with the retrieved-evidence block removed.
The model could simply copy that ID rather than recall or hallucinate
it — which would have measured copy-paste fidelity, not hallucination.

Fix, in `prompt_templates.py`: the FINDING block now redacts CVE ID
patterns from `raw_output` (replaced with `[CVE ID redacted]`) before
it's included in either prompt variant, while preserving the rest of
the scan evidence (script name, service, port). This is a prompt-
template fix, not a harness fix — the harness can only score what it's
given, so a leaky prompt would have silently invalidated the whole
comparison upstream of any scoring logic.

A related fix in the same file: the ungrounded citation instruction was
rewritten to actively invite citation ("name the CVE ID(s) if you know
them; an accurate, specific citation is expected") with an explicit
no-invention guard, rather than passively allowing it. Without this, a
low ungrounded citation rate could mean "the model doesn't hallucinate
much" or could just as easily mean "the prompt discouraged citing
anything" — two very different findings that look identical in the
output unless the prompt actively invites the behavior being measured.

### 8.4 Live validation result

A live run against Gemini (grounded + ungrounded, `--nvd` live-existence
checking) on the two CVE-bearing findings in the sample corpus produced
a concrete, useful result for the write-up: the **ungrounded** SMB
finding (nse_script `smb-vuln-ms17-010`, actual CVE `CVE-2017-0143`)
cited **`CVE-2017-0144`** — a real, existing CVE (confirmed via live NVD
lookup), but a *different, never-injected sibling CVE* from the same
March 2017 SMB disclosure batch. The harness correctly classified this
as `unsupported_cve` (existence check: true) rather than `fabricated_cve`.

This is a genuinely illustrative failure mode for the thesis: it shows
an LLM pattern-matching on a well-known vulnerability cluster ("SMB RCE,
March 2017, EternalBlue-adjacent") and producing a plausible but
incorrect specific citation — exactly the class of error that sounds
authoritative to a non-expert reader and is hardest to catch without
grounding. Grounded output on the same two findings produced 0 bad
citations of either type. Small-n (2 findings) — reported here as a
concrete illustrative case for methodology validation, not as the
corpus-scale result; the full benchmark run against the target 20-40+
finding corpus is what the thesis result section should report.
