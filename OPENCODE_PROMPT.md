# Project Handoff Prompt — AI-Powered Cybersecurity Health Assessment Platform

Paste this whole file as your first message to opencode, in the root of
this project folder (`cyber-health-platform/`). It contains full context
so opencode doesn't have to guess at design decisions already made.

---

## Project summary

I'm building an AI-powered Cybersecurity Health Assessment Platform for
my [thesis/capstone — edit as applicable]. It ingests security scan
output (Nmap XML/TXT, eventually OpenVAS/Nessus), extracts assets/ports/
services/vulnerabilities, scores them with a deterministic rule-based
engine, grounds each finding in retrieved CVE (NVD) and CIS Benchmark
data via RAG, and only then uses an LLM to generate executive summaries,
plain-language explanations, and CIS-mapped remediation guidance —
plus a conversational interface for querying scan results.

The core research contribution is a **measurable comparison of grounded
vs. ungrounded LLM output on the same findings**, quantifying how much
RAG grounding reduces hallucinated/unsupported CVE references. This is
not just "add RAG because it's trendy" — the eval methodology is a
deliverable in itself.

## What's already built (do not rebuild — extend/integrate these)

All files are in this project folder already. Read them before writing
any new code so you don't duplicate or contradict existing design
decisions.

```
cyber-health-platform/
├── src/
│   ├── nmap_parser.py      # Nmap XML → structured findings JSON
│   ├── rule_engine.py      # Deterministic severity scoring + prioritization
│   ├── ingest_nvd.py       # NVD API 2.0 ingestion → cve_kb.json (NOT runnable in
│   │                       #   sandboxed envs without network — needs live NVD access)
│   └── retrieval.py        # RAG retrieval: direct CVE lookup + TF-IDF filtered
│                           #   semantic search over CIS controls
├── data/
│   ├── sample_scans/
│   │   ├── sample_scan.xml    # 3-host Nmap scan, mixed severity, real CVEs
│   │   └── sample_scan.txt    # same scan, plain-text Nmap format
│   ├── knowledge_base/
│   │   ├── sample_cve_kb.json # 2 real NVD-format CVE records (CVE-2017-0143, CVE-2012-2122)
│   │   └── sample_cis_kb.json # 9 illustrative CIS-style controls (NOT verbatim CIS
│   │                          #   Benchmark text — CIS docs are copyrighted and require
│   │                          #   a free account; these are written from scratch to match
│   │                          #   the structure/schema for dev/testing purposes only)
│   ├── findings_output.json   # nmap_parser.py output on sample_scan.xml
│   ├── scored_findings.json   # rule_engine.py output on findings_output.json
│   └── grounded_findings.json # retrieval.py output — fully grounded findings, ready
│                              #   for the LLM synthesis layer
└── docs/
    └── rag_retrieval_schema.md # Full design doc: cve_kb/cis_kb schemas, retrieval
                                 #   logic, grounded prompt template, why direct-match
                                 #   vs filtered-search, hallucination-check methodology
```

**Pipeline already verified end-to-end on sample data:**
`sample_scan.xml` → `nmap_parser.py` → `rule_engine.py` → `retrieval.py`
→ `grounded_findings.json`. Run it yourself to confirm before changing
anything:

```bash
cd src
python3 nmap_parser.py ../data/sample_scans/sample_scan.xml -o ../data/findings_output.json
python3 rule_engine.py ../data/findings_output.json -o ../data/scored_findings.json
python3 retrieval.py ../data/scored_findings.json \
  --cve-kb ../data/knowledge_base/sample_cve_kb.json \
  --cis-kb ../data/knowledge_base/sample_cis_kb.json \
  -o ../data/grounded_findings.json
```

## Key design decisions already made (respect these unless you have a strong reason not to)

1. **Rule engine runs before the LLM, not the LLM as the decision-maker.**
   Severity/priority is deterministic and auditable — every score has a
   `scoring_rationale` string. The LLM's job downstream is to explain and
   cite, never to invent a severity rating.

2. **CVE retrieval is a direct key lookup, not a semantic search** — NSE
   scripts already give exact CVE IDs, so there's no ambiguity to resolve
   with embeddings. **CIS retrieval is filtered-then-ranked**: filter
   `cis_kb` by `applies_to` tag overlap with the finding's service/OS
   first, then rank the filtered subset by text similarity. Filtering
   before ranking is deliberate — see `retrieval.py` docstring and
   `docs/rag_retrieval_schema.md` section 4 for why.

3. **CIS retrieval currently uses TF-IDF + cosine similarity** (scikit-learn),
   not neural embeddings — a deliberate scope choice since CIS control
   text is short and keyword-dense. If you upgrade to
   `sentence-transformers`, only `CisIndex._vectorize()`/`.search()` in
   `retrieval.py` should change; keep the filter-then-rank structure and
   the calling code (`ground_finding`, `ground_all`) untouched.

4. **`ingest_nvd.py` cannot be tested in network-sandboxed environments** —
   it was validated against a mocked NVD API 2.0 response, not live, since
   the dev sandbox couldn't reach `nvd.nist.gov`. Test it live in your
   environment before trusting it fully. It also pulls CISA's KEV catalog
   to tag actively-exploited CVEs — treat `kev_listed: null` as "unknown,"
   never coerce it to `false`.

5. **`sample_cis_kb.json` is placeholder content, not real CIS Benchmark
   text.** Before any real evaluation/demo, either get real CIS Benchmark
   content (free account required at cisecurity.org) and re-chunk it
   per-control matching this schema, or clearly label all CIS-sourced
   output as illustrative in any report/demo.

6. **The core benchmark methodology** (see schema doc section 7): the
   hallucination check is a set-membership comparison — does the LLM's
   set of cited CVE IDs stay a strict subset of what was actually
   retrieved and injected into its prompt? This should be automatable,
   not manually graded. Build the ungrounded-baseline prompt as the same
   template minus the retrieved-context block, run both on the same
   `grounded_findings.json` findings, and diff the cited-CVE sets.

## What's NOT built yet — this is your job

In rough dependency order:

1. **LLM synthesis layer**
   - Grounded prompt template (see schema doc section 5 for a draft) that
     takes a `grounded_findings.json` entry and produces: a per-finding
     plain-language explanation, and contributes to an executive summary
     across all findings for a host/scan.
   - CIS-mapped remediation priority list generation.
   - Ungrounded baseline variant of the same prompt (context block
     removed) — needed for the benchmark, not for production use.
   - Pick an LLM API (Claude, OpenAI, local model — confirm with me
     which one before hardcoding a client).

2. **Conversational interface**
   - Lets a user ask free-form questions about scan results.
   - Needs to route a question to the relevant subset of
     `grounded_findings.json` (or re-run retrieval per-query) rather than
     stuffing the entire scan into context every time.

3. **Hallucination benchmark harness**
   - Automated extraction of cited CVE IDs from LLM output text.
   - Set-membership check against `grounding_context.cve_records` per
     finding.
   - Run across a test corpus (decide size — needs to be big enough for
     a defensible result; discuss with me before committing to a number).
   - Output: a reproducible metric (e.g. hallucination rate % grounded
     vs. ungrounded) with enough logging to regenerate the result.

4. **OpenVAS/Nessus parsers**
   - Same normalized finding schema as `nmap_parser.py` output, different
     XML/format on the input side. Check their schema docs — don't
     assume they match Nmap's structure.

5. **Front end / report delivery**
   - Not yet decided — web dashboard vs. generated PDF/HTML report vs.
     just the chat interface. Ask me before building UI.

## How I want you to work

- Read all existing files before writing new code. Match the existing
  code style (docstrings explaining *why*, not just *what*; type hints;
  deterministic logic kept separate from anything LLM-driven).
- Don't silently change the finding/grounding_context schema — if you
  need to extend it, tell me what and why first, since the rule engine,
  retrieval layer, and any future eval harness all depend on it staying
  stable.
- Flag any place where you're making a judgment call I should weigh in
  on (e.g. LLM provider choice, benchmark corpus size, front-end
  framework) rather than just picking one.
- I'm also using Claude (claude.ai) for parts of this project, so keep
  file/module boundaries clean — I may bring code back and forth between
  tools, so avoid tightly coupling new work to opencode-specific state.

Start by running the existing pipeline yourself to confirm it works in
your environment, then propose a plan for the LLM synthesis layer before
writing code.
