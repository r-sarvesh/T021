"""
benchmark_harness.py

Hallucination benchmark harness for the LLM synthesis layer. Consumes the
JSONL produced by synthesize.py (WITHOUT re-running the LLM) and scores
each finding's citations against the grounding context that was actually
injected into its prompt.

Scoring model (four refinements agreed at plan time — each changes what
the numbers mean, so they are baked into the data model, not bolted on):

1. TWO failure modes, reported separately, never merged into one number:
     - fabricated_cve  : cited CVE ID does not exist at all (checked
                         against cve_kb, or live NVD if --nvd is given).
     - unsupported_cve : cited CVE ID is real but was NOT in the
                         retrieved/injected context for that finding.
   Grounded variants should structurally only ever produce unsupported_cve
   (the model only saw retrieved context); ungrounded variants can produce
   both. Splitting them is what lets the grounded-vs-ungrounded comparison
   distinguish "stopped inventing CVEs" from "stopped citing without
   evidence."

2. TWO denominators, both computed and reported:
     - per-finding rate : % of findings with >=1 bad citation.
     - per-citation rate: % of bad citations / total individual citations.
   The summary picks a headline number but keeps both visible.

3. The ungrounded prompt (prompt_templates._UNGROUNDED_CITATION_RULE) was
   verified to still EXPLICITLY INVITE the model to name CVEs it knows,
   and the FINDING block redacts CVE IDs so the ungrounded baseline cannot
   copy them from NSE raw output. With those in place, "allowed set is
   empty for ungrounded" is a valid measurement of memory-based citation,
   not instruction compliance. See prompt_templates.py docstring.

4. Every rate is printed as raw numerator/denominator ("3/20 (15.0%)"),
   never as a bare percentage — with a 20-40 finding corpus, 12% could be
   1/8 or 12/100.

Existence checking:
  - Default: a CVE "exists" if present in the cve_kb JSON passed with
    --cve-kb. This is the offline, reproducible default (a real CVE not
    yet ingested will be marked fabricated — a known, documented limitation).
  - --nvd: live NVD API 2.0 lookup per cited ID (best-effort; nvd.nist.gov
    must be reachable). Reuses ingest_nvd's rate limiting and URL handling.
  - If existence is UNKNOWN (network failure), the citation is recorded as
    unverifiable and NOT counted as fabricated (we won't accuse the model
    of inventing an ID we failed to look up), and is folded into the
    unsupported bucket with a footnote in the per-record log.

Usage:
    python3 benchmark_harness.py llm_output.jsonl \
        --cve-kb ../data/knowledge_base/sample_cve_kb.json \
        -o scored_benchmark.jsonl --report hallucination_summary.txt

    python3 benchmark_harness.py llm_output.jsonl --nvd \
        -o scored_benchmark.jsonl --report hallucination_summary.txt
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Optional

# Same pattern the synthesis layer stamps records with — must stay in sync
# with cite_extract.CVE_PATTERN.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

SCORABLE_VARIANTS = ("grounded", "ungrounded")


# ---------------------------------------------------------------------------
# Existence checkers
# ---------------------------------------------------------------------------

class CveExistenceChecker:
    """Returns True/False/None (None = existence could not be verified)."""

    def exists(self, cve_id: str) -> Optional[bool]:
        raise NotImplementedError


class KbExistenceChecker(CveExistenceChecker):
    """Offline: a CVE exists iff it is present in the local cve_kb."""

    def __init__(self, cve_kb_path: str):
        self._kb = json.loads(Path(cve_kb_path).read_text())

    def exists(self, cve_id: str) -> Optional[bool]:
        return cve_id in self._kb


class NvdExistenceChecker(CveExistenceChecker):
    """
    Live NVD API 2.0 lookup. Existence is exact-ID only (no semantic
    search — an invented-looking ID either resolves or it doesn't).
    Caches results so repeated IDs cost one request each.
    """

    def __init__(self, api_key: Optional[str] = None):
        import requests
        from ingest_nvd import NVD_BASE_URL, NvdRateLimiter

        self._requests = requests
        self._base_url = NVD_BASE_URL
        self._api_key = api_key
        self._limiter = NvdRateLimiter(has_api_key=bool(api_key))
        self._cache: dict[str, Optional[bool]] = {}
        if not api_key:
            print(
                "No NVD API key (set NVD_API_KEY env var) — rate-limited to "
                "5 req/30s; expect slow runs on large citation sets.",
                file=sys.stderr,
            )

    def exists(self, cve_id: str) -> Optional[bool]:
        if cve_id in self._cache:
            return self._cache[cve_id]
        headers = {"apiKey": self._api_key} if self._api_key else {}
        try:
            resp = self._requests.get(
                self._base_url,
                params={"cveId": cve_id},
                headers=headers,
                timeout=30,
            )
        except Exception as e:  # noqa: BLE001 — network failure must not crash the run
            print(f"  ~ {cve_id}: NVD lookup failed ({e}); existence unknown", file=sys.stderr)
            self._cache[cve_id] = None
            return None
        finally:
            self._limiter.wait()

        if resp.status_code == 200:
            exists = bool((resp.json() or {}).get("vulnerabilities"))
        elif resp.status_code == 404:
            exists = False
        else:
            print(
                f"  ~ {cve_id}: NVD HTTP {resp.status_code}; existence unknown",
                file=sys.stderr,
            )
            exists = None
        self._cache[cve_id] = exists
        return exists


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _allowed_cve_set(record: dict) -> set[str]:
    """
    The set of CVE IDs the model was permitted to cite.

    Grounded: every CVE ID present in the injected prompt text — including
    sibling CVEs mentioned inside an NVD description, because those ARE in
    the retrieved context the model saw (schema doc §7: "retrieved AND
    injected"). Ungrounded: always empty — no context was injected, so any
    citation is by definition unsupported.
    """
    if record.get("prompt_variant") != "grounded":
        return set()
    return set(CVE_PATTERN.findall(record.get("prompt") or ""))


def score_record(record: dict, checker: CveExistenceChecker) -> dict:
    """
    Score one finding record from llm_output.jsonl.

    Returns a copy-of-inspection dict (does not mutate the input) with
    every classification field the aggregate metrics need, plus the raw
    sets so the numbers are fully auditable.
    """
    cited = set(record.get("extracted_cve_ids") or [])
    allowed = _allowed_cve_set(record)

    unsupported = set()
    fabricated = set()
    unverifiable = set()
    lookup_log = []

    for cve_id in cited - allowed:
        exists = checker.exists(cve_id)
        lookup_log.append({"cve_id": cve_id, "existence": exists})
        if exists is True:
            unsupported.add(cve_id)
        elif exists is False:
            fabricated.add(cve_id)
        else:
            # Can't prove non-existence, so refusing to call it fabricated.
            # It's still outside the allowed set, so it lands in unsupported
            # for the aggregate count, with the unknown flag preserved.
            unverifiable.add(cve_id)
            unsupported.add(cve_id)

    return {
        "finding_ref": record.get("finding_ref"),
        "host": record.get("host"),
        "port": record.get("port"),
        "service": record.get("service"),
        "nse_script": record.get("nse_script"),
        "severity_band": record.get("severity_band"),
        "prompt_variant": record.get("prompt_variant"),
        "cited_cve_ids": sorted(cited),
        "allowed_cve_ids": sorted(allowed),
        "fabricated_cve_ids": sorted(fabricated),
        "unsupported_cve_ids": sorted(unsupported),
        "unverifiable_cve_ids": sorted(unverifiable),
        "has_fabricated": bool(fabricated),
        "has_unsupported": bool(unsupported),
        "has_bad_citation": bool(fabricated or unsupported),
        "citation_count": len(cited),
        "bad_citation_count": len(fabricated) + len(unsupported),
        "existence_lookup_log": lookup_log,
    }


def aggregate_per_variant(scored: list[dict]) -> dict:
    """
    Compute per-variant metrics for BOTH denominators, with raw
    numerators/denominators attached to every rate.
    """
    variant = scored[0]["prompt_variant"]
    n_findings = len(scored)

    findings_bad = [s for s in scored if s["has_bad_citation"]]
    findings_fab = [s for s in scored if s["has_fabricated"]]
    findings_unsup = [s for s in scored if s["has_unsupported"]]

    total_citations = sum(s["citation_count"] for s in scored)
    bad_citations = sum(s["bad_citation_count"] for s in scored)
    fab_citations = sum(len(s["fabricated_cve_ids"]) for s in scored)
    unsup_citations = sum(len(s["unsupported_cve_ids"]) for s in scored)

    def rate(num: int, denom: int) -> dict:
        return {"n": num, "denominator": denom,
                "rate": round(num / denom, 4) if denom else 0.0}

    zero_citation_findings = sum(1 for s in scored if s["citation_count"] == 0)

    return {
        "variant": variant,
        "findings_scored": n_findings,
        "findings_with_any_bad_citation": rate(len(findings_bad), n_findings),
        "findings_with_fabricated_cve": rate(len(findings_fab), n_findings),
        "findings_with_unsupported_cve": rate(len(findings_unsup), n_findings),
        "findings_with_zero_citations": zero_citation_findings,
        "total_citations": total_citations,
        "bad_citations": rate(bad_citations, total_citations),
        "fabricated_citations": rate(fab_citations, total_citations),
        "unsupported_citations": rate(unsup_citations, total_citations),
        # Headline numbers with their raw counts attached.
        "headline_per_finding_rate": rate(len(findings_bad), n_findings),
        "headline_per_citation_rate": rate(bad_citations, total_citations),
        "bad_finding_refs": [s["finding_ref"] for s in findings_bad],
    }


def _render_rate_label(r: dict) -> str:
    return f"{r['n']}/{r['denominator']} ({r['rate'] * 100:.1f}%)"


def render_summary(aggregates: dict, existence_mode: str, input_files: list[str]) -> str:
    """Human-readable report. Every percentage is a raw n/d in parentheses."""
    grounded = aggregates.get("grounded")
    ungrounded = aggregates.get("ungrounded")

    lines = []
    w = lines.append
    w("=" * 72)
    w("HALLUCINATION BENCHMARK SUMMARY")
    w("=" * 72)
    w(f"Existence mode : {existence_mode}")
    w(f"Input files    : {', '.join(input_files)}")
    w("")

    for agg in (grounded, ungrounded):
        if agg is None:
            continue
        w(f"--- VARIANT: {agg['variant'].upper()} "
          f"({agg['findings_scored']} scored findings) ---")
        w(f"  per-finding  , any bad citation : {_render_rate_label(agg['findings_with_any_bad_citation'])}")
        w(f"  per-finding  , fabricated CVE   : {_render_rate_label(agg['findings_with_fabricated_cve'])}")
        w(f"  per-finding  , unsupported CVE  : {_render_rate_label(agg['findings_with_unsupported_cve'])}")
        w(f"  findings with zero citations    : {agg['findings_with_zero_citations']} "
          f"({agg['findings_with_zero_citations']}/{agg['findings_scored']})")
        w(f"  per-citation , bad citations    : {_render_rate_label(agg['bad_citations'])} "
          f"(of {agg['total_citations']} total citations)")
        w(f"  per-citation , fabricated CVE   : {_render_rate_label(agg['fabricated_citations'])}")
        w(f"  per-citation , unsupported CVE  : {_render_rate_label(agg['unsupported_citations'])}")
        if agg["bad_finding_refs"]:
            w("  findings with >=1 bad citation:")
            for ref in agg["bad_finding_refs"]:
                w(f"    - {ref}")
        w("")

    if grounded and ungrounded:
        w("--- GROUNDED vs UNGROUNDED (headline) ---")
        g_per_find = grounded["headline_per_finding_rate"]
        u_per_find = ungrounded["headline_per_finding_rate"]
        g_per_cit = grounded["headline_per_citation_rate"]
        u_per_cit = ungrounded["headline_per_citation_rate"]
        w(f"  per-finding bad-citation rate :"
          f" grounded {_render_rate_label(g_per_find)}  vs  "
          f"ungrounded {_render_rate_label(u_per_find)}")
        w(f"  per-citation bad-citation rate :"
          f" grounded {_render_rate_label(g_per_cit)}  vs  "
          f"ungrounded {_render_rate_label(u_per_cit)}")
        w("")
        w("Interpretation:")
        w("  - fabricated_cve (grounded) should be ~0: the model only saw")
        w("    retrieved context, so inventing IDs is structurally blocked.")
        w("  - unsupported_cve (ungrounded) is the interesting delta: real")
        w("    CVEs cited from memory without retrieval evidence.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Score LLM citation outputs for hallucination.")
    parser.add_argument("llm_output", help="Path to synthesize.py output JSONL")
    parser.add_argument("-o", "--output", default="scored_benchmark.jsonl", help="Scored JSONL output")
    parser.add_argument("--report", default="hallucination_summary.txt", help="Human-readable summary report")

    existence_group = parser.add_mutually_exclusive_group()
    existence_group.add_argument(
        "--cve-kb", help="Path to cve_kb JSON — existence = present in KB (offline, default mode)"
    )
    existence_group.add_argument(
        "--nvd", action="store_true", help="Use live NVD API 2.0 lookups for existence"
    )
    parser.add_argument("--nvd-api-key", default=None, help="NVD API key (or set NVD_API_KEY env var)")
    parser.add_argument("--max-findings", type=int, default=None,
                        help="Cap the number of findings scored per variant (for quick dev runs)")
    args = parser.parse_args()

    if not (args.cve_kb or args.nvd):
        parser.error("Provide --cve-kb <path> (offline) or --nvd (live lookup)")

    if args.nvd:
        import os
        api_key = args.nvd_api_key or os.environ.get("NVD_API_KEY")
        checker = NvdExistenceChecker(api_key=api_key)
        existence_mode = "live NVD API 2.0"
    else:
        checker = KbExistenceChecker(args.cve_kb)
        existence_mode = f"local cve_kb ({args.cve_kb})"

    records = [json.loads(line) for line in Path(args.llm_output).read_text(encoding="utf-8").splitlines() if line.strip()]

    scored = []
    skipped_failed = 0
    for rec in records:
        # Only finding-level grounded/ungrounded records are scorable;
        # executive summaries and remediation plans are out of scope for
        # the per-finding hallucination check.
        if rec.get("prompt_variant") not in SCORABLE_VARIANTS:
            continue
        if not rec.get("ok"):
            skipped_failed += 1
            continue
        scored.append(score_record(rec, checker))

    # Split by variant.
    per_variant = {}
    for variant in SCORABLE_VARIANTS:
        subset = [s for s in scored if s["prompt_variant"] == variant]
        if args.max_findings and len(subset) > args.max_findings:
            subset = subset[: args.max_findings]
        if subset:
            per_variant[variant] = aggregate_per_variant(subset)

    # Re-write a flattened scored JSONL (all variants) for downstream use.
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for s in scored:
            fh.write(json.dumps(s, ensure_ascii=False) + "\n")

    summary_text = render_summary(per_variant, existence_mode, [args.llm_output])
    Path(args.report).write_text(summary_text)

    print(summary_text, file=sys.stderr)
    if skipped_failed:
        print(f"\n(Note: {skipped_failed} failed/empty LLM record(s) skipped)", file=sys.stderr)
    print(f"\nWrote {len(scored)} scored record(s) to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()