"""
retrieval.py

Implements the two-track retrieval design from rag_retrieval_schema.md:

  1. CVE retrieval — a DIRECT KEY LOOKUP against cve_kb, not a semantic
     search. Nmap/OpenVAS NSE scripts already give us the CVE ID, so
     there's no ambiguity to resolve with embeddings.

  2. CIS retrieval — a FILTERED SEMANTIC SEARCH. First filter cis_kb to
     controls whose `applies_to` tags match the finding's service/OS,
     then rank by text similarity between the finding and each control.

Both results are attached to the finding as `grounding_context`, which is
exactly what gets injected into the LLM prompt (see section 5 of the
schema doc). Nothing here calls an LLM — this module's only job is
retrieval, so it can be unit-tested and audited independently of any
generation step.

Embedding note: this implementation uses TF-IDF + cosine similarity
(scikit-learn) rather than a neural embedding model. That's a deliberate
scope choice — CIS control text is short, domain-specific, and keyword-
heavy, so TF-IDF performs adequately and avoids a heavy model download /
GPU dependency for a project this size. Swapping in sentence-transformers
embeddings later only requires replacing `CisIndex._vectorize()` and
`CisIndex.search()` — the filtering and calling code don't change. This
tradeoff is worth a sentence in your report if asked "why not real
embeddings."

Usage:
    python3 retrieval.py scored_findings.json \
        --cve-kb samples/sample_cve_kb.json \
        --cis-kb samples/sample_cis_kb.json \
        -o grounded_findings.json
"""

import argparse
import json
import sys
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class CveStore:
    """Direct-lookup CVE knowledge base."""

    def __init__(self, cve_kb: dict):
        self.kb = cve_kb

    def lookup(self, cve_id: str) -> dict | None:
        return self.kb.get(cve_id)

    def lookup_many(self, cve_ids: list[str]) -> list[dict]:
        results = []
        for cve_id in cve_ids:
            record = self.lookup(cve_id)
            if record is not None:
                results.append(record)
            else:
                # Explicitly surface misses rather than silently dropping
                # them — a finding referencing an unresolvable CVE ID
                # should be visible, not invisible.
                results.append({"id": cve_id, "text": None, "not_found": True})
        return results


class CisIndex:
    """Filtered semantic search over CIS control text."""

    def __init__(self, cis_kb: list[dict]):
        self.controls = cis_kb or []
        # Gracefully handle empty KB (e.g. edge tests, missing file) — no crash, just no matches
        if not self.controls:
            self._vectorizer = None
            self._matrix = None
            return
        try:
            self._vectorizer = TfidfVectorizer(stop_words="english")
            self._matrix = self._vectorizer.fit_transform(
                c.get("text", "") for c in self.controls
            )
            # If all documents were empty/stop-words, fit_transform yields empty vocab — treat as empty index
            if self._matrix.shape[1] == 0:
                self._vectorizer = None
                self._matrix = None
        except ValueError as e:
            # e.g. "empty vocabulary; perhaps the documents only contain stop words"
            print(f"Warning: CIS index empty vocabulary ({e}) — no CIS matches will be returned", file=sys.stderr)
            self._vectorizer = None
            self._matrix = None

    def search(self, query_text: str, service_tags: list[str], top_k: int = 3) -> list[dict]:
        """
        Filter controls by applies_to overlap with service_tags, then rank
        the filtered subset by cosine similarity to query_text. Filtering
        BEFORE ranking (not after) means a highly-similar-but-wrong-service
        control can never crowd out a correctly-tagged one.
        """
        # Degrade gracefully if KB was empty or failed to vectorize
        if self._vectorizer is None or self._matrix is None:
            return []
        if not query_text or not query_text.strip():
            return []
        service_tags_lower = {t.lower() for t in service_tags if t}

        candidate_idxs = [
            i for i, c in enumerate(self.controls)
            if service_tags_lower & {t.lower() for t in c.get("applies_to", [])}
        ]

        if not candidate_idxs:
            return []

        query_vec = self._vectorizer.transform([query_text])
        candidate_matrix = self._matrix[candidate_idxs]
        sims = cosine_similarity(query_vec, candidate_matrix)[0]

        ranked = sorted(zip(candidate_idxs, sims), key=lambda pair: pair[1], reverse=True)

        results = []
        for idx, score in ranked[:top_k]:
            control = dict(self.controls[idx])
            control["similarity_score"] = round(float(score), 3)
            results.append(control)
        return results


def build_service_tags(finding: dict) -> list[str]:
    """
    Derive the tag vocabulary used to filter cis_kb, from a finding's
    service/product/os fields. Kept as a standalone function so the tag
    vocabulary can be extended in one place as more services are added.
    """
    tags = set()
    if finding.get("service"):
        tags.add(finding["service"])
    if finding.get("product"):
        product_lower = finding["product"].lower()
        # Map common product strings to the tag vocabulary used in cis_kb.
        if "apache" in product_lower:
            tags.add("apache_httpd")
        if "openssh" in product_lower:
            tags.add("openssh")
        if "windows server" in product_lower:
            tags.add("windows_server")
        elif "windows" in product_lower:
            tags.add("windows")
        if "mysql" in product_lower or "mariadb" in product_lower:
            tags.add("mysql")
    if finding.get("service") == "https":
        tags.update({"ssl", "tls"})
    return list(tags)


def build_query_text(finding: dict) -> str:
    """The text used to drive CIS semantic search for a given finding."""
    parts = [
        finding.get("service") or "",
        finding.get("product") or "",
        finding.get("raw_output") or "",
        finding.get("scoring_rationale") or "",
    ]
    return " ".join(p for p in parts if p)


def ground_finding(finding: dict, cve_store: CveStore, cis_index: CisIndex, top_k_cis: int = 3) -> dict:
    """
    Attach grounding_context to a single finding. This is the object that
    gets injected into the LLM prompt template (see schema section 5).
    """
    grounded = dict(finding)

    cve_records = cve_store.lookup_many(finding.get("cve_refs", []))

    service_tags = build_service_tags(finding)
    query_text = build_query_text(finding)
    cis_matches = cis_index.search(query_text, service_tags, top_k=top_k_cis) if query_text else []

    grounded["grounding_context"] = {
        "cve_records": cve_records,
        "cis_matches": cis_matches,
        "service_tags_used": service_tags,
    }
    return grounded


def ground_all(findings: list[dict], cve_store: CveStore, cis_index: CisIndex) -> list[dict]:
    return [ground_finding(f, cve_store, cis_index) for f in findings]


def main():
    parser = argparse.ArgumentParser(description="Ground scored findings in CVE + CIS retrieval context.")
    parser.add_argument("findings_file", help="Path to scored_findings.json (rule_engine.py output)")
    parser.add_argument("--cve-kb", required=True, help="Path to cve_kb JSON (dict keyed by CVE ID)")
    parser.add_argument("--cis-kb", required=True, help="Path to cis_kb JSON (list of control records)")
    parser.add_argument("-o", "--output", help="Write JSON result to this file instead of stdout")
    args = parser.parse_args()

    findings_data = json.loads(Path(args.findings_file).read_text())
    # Accept either the full rule_engine output dict or a flat findings list.
    findings = (
        findings_data.get("all_scored_findings")
        if isinstance(findings_data, dict) else findings_data
    )
    # Only vuln-type findings carry CVE refs / need CIS grounding in a
    # meaningful way, but asset findings still benefit from CIS hardening
    # matches (e.g. "SMB is open" -> CIS-SMB-001 even with no CVE yet).
    vuln_and_asset_findings = [f for f in findings if f.get("type") in ("vuln", "asset")]

    cve_kb = json.loads(Path(args.cve_kb).read_text())
    cis_kb = json.loads(Path(args.cis_kb).read_text())

    cve_store = CveStore(cve_kb)
    cis_index = CisIndex(cis_kb)

    grounded = ground_all(vuln_and_asset_findings, cve_store, cis_index)

    output = json.dumps(grounded, indent=2)
    if args.output:
        Path(args.output).write_text(output)
        print(f"Wrote {len(grounded)} grounded findings to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Quick sanity summary.
    cve_hits = sum(
        1 for f in grounded
        for r in f["grounding_context"]["cve_records"]
        if not r.get("not_found")
    )
    cve_misses = sum(
        1 for f in grounded
        for r in f["grounding_context"]["cve_records"]
        if r.get("not_found")
    )
    cis_hits = sum(1 for f in grounded if f["grounding_context"]["cis_matches"])
    print(
        f"Grounding summary: {cve_hits} CVE(s) resolved, {cve_misses} CVE(s) not in local KB, "
        f"{cis_hits}/{len(grounded)} findings matched >=1 CIS control",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
