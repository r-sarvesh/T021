"""
cite_extract.py

Deterministic extraction of CVE IDs (and, for completeness, CIS control
IDs) from free-form LLM output text. This is the mechanical, non-LLM half
of the hallucination-check methodology described in rag_retrieval_schema.md
section 7: the benchmark compares the set of CVE IDs extracted from the
model's prose against the set that was actually retrieved and injected
into its prompt.

Why a dedicated module instead of inlining the regex in synthesize.py or
the harness: exactly one implementation of "what counts as a cited CVE"
must exist, and it must be shared by the synthesis layer (which stamps the
JSONL records) and the benchmark harness (which scores them). Duplicating
this logic is how subtle measurement drift creeps in.

Note: the harness check must run on the model's RAW text, not only on the
structured `cve_ids_mentioned` field, because a model can contradict its
own structured field inside the prose. Extracting from raw text catches
both directions of that drift.
"""

import re

# Accepts variants: lowercase, space, underscore, hyphen, en-dash (\u2013), em-dash (\u2014)
# Returns canonical uppercase hyphenated form via _canonicalize.
# Keeps canonical pattern as base but variant-aware for robustness.
CVE_PATTERN = re.compile(r"CVE[\s_\-\u2013\u2014]*\d{4}[\s_\-\u2013\u2014]*\d{4,7}", re.IGNORECASE)
# Variant regex with capture groups for canonicalization
CVE_VARIANT_RE = re.compile(r"CVE[\s_\-\u2013\u2014]*(\d{4})[\s_\-\u2013\u2014]*(\d{4,7})", re.IGNORECASE)

# CIS control IDs look like "CIS-SMB-001" or "CIS-MSFT-WS2012R2-2.3.10.1".
# Anchor on the "CIS-" prefix; capture uppercase groups, digits, dots.
CIS_PATTERN = re.compile(r"CIS-[A-Z0-9]+(?:[-.\d]+)*")

# Beware false positives from the above: "CIS-2017" could match prose like
# "CIS level 2017". Accept that risk only because our grounding context
# uses the CIS-<TAG>-<NNN> shape, and benchmark analysis will only compare
# against IDs that actually exist in grounding_context.


def _canonicalize_cve(raw: str) -> str:
    """Normalize a raw CVE match to canonical uppercase hyphenated form CVE-YYYY-NNNNN."""
    m = CVE_VARIANT_RE.search(raw)
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    # Fallback: uppercase and replace separators with hyphen
    # This handles already-canonical strings passed via parsed field
    s = raw.strip().upper()
    # Replace any sequence of space/underscore/en/em dash with single hyphen
    s = re.sub(r"[\s_\-\u2013\u2014]+", "-", s)
    # Ensure CVE- prefix
    if not s.startswith("CVE-"):
        # Try to extract CVE part
        mm = re.search(r"CVE-\d{4}-\d{4,7}", s, re.IGNORECASE)
        if mm:
            return mm.group(0).upper()
    return s


def normalize_cve_id(cve_id: str) -> str:
    """Public helper: normalize a single CVE ID variant to canonical form."""
    if not cve_id:
        return cve_id
    return _canonicalize_cve(cve_id)


def extract_cve_ids(text: str) -> list[str]:
    """All unique CVE IDs in a string, in first-appearance order, normalized to canonical form."""
    if not text:
        return []
    # Find all variant matches
    matches = CVE_VARIANT_RE.findall(text)
    # findall returns list of tuples (year, seq) when pattern has groups
    canonical = []
    for year, seq in matches:
        canonical.append(f"CVE-{year}-{seq}")
    # Deduplicate preserving order, already canonical uppercase
    return list(dict.fromkeys(canonical))


def extract_cis_ids(text: str) -> list[str]:
    """All unique CIS control IDs in a string, in first-appearance order."""
    return list(dict.fromkeys(CIS_PATTERN.findall(text)))
