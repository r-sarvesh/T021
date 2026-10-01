"""
ingest_nvd.py

Pulls CVE records from the NVD REST API 2.0 and builds a local cve_kb.json
file matching the schema defined in rag_retrieval_schema.md. This is what
rule_engine.lookup_cvss() and the RAG retrieval layer should query against
once this replaces the CVE_CVSS_TABLE stub.

IMPORTANT — network note for this environment:
This sandbox's outbound network allowlist does not include
services.nvd.nist.gov, so this script cannot be executed live here. It is
written to run correctly in your own environment (local machine, VM, or
CI runner) where NVD is reachable. Install dependencies with:
    pip install requests

NVD API 2.0 basics this script relies on (see nvd.nist.gov/developers):
  - Base URL: https://services.nvd.nist.gov/rest/json/cves/2.0
  - Rate limit: 5 requests / 30s without an API key, 50 requests / 30s
    with one. Get a free key at https://nvd.nist.gov/developers/request-an-api-key
    (recommended — 10x the throughput, and this project will make many
    requests if you resolve CVEs one at a time).
  - Two supported lookup modes here:
      1. By exact CVE ID  -> single CVE, used for on-demand enrichment
         when the Nmap/OpenVAS parser already found a CVE reference.
      2. By keyword + CPE  -> bulk pull for a specific product ("Apache
         httpd", "OpenSSH", etc.) to pre-populate the knowledge base for
         products commonly seen in scans, independent of any one scan.

Usage:
    # Enrich specific CVE IDs found by the parser/rule engine:
    python3 ingest_nvd.py --cve-ids CVE-2017-0143 CVE-2012-2122

    # Enrich every CVE referenced in a scored_findings.json file:
    python3 ingest_nvd.py --from-findings scored_findings.json

    # Bulk pull recent HIGH+ CVEs for a product to pre-populate cve_kb:
    python3 ingest_nvd.py --keyword "OpenSSH" --severity HIGH

    # With an API key (recommended):
    python3 ingest_nvd.py --cve-ids CVE-2017-0143 --api-key YOUR_KEY
    # or set env var NVD_API_KEY
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("This script requires the 'requests' package: pip install requests", file=sys.stderr)
    sys.exit(1)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_KB_PATH = "cve_kb.json"

# CISA Known Exploited Vulnerabilities catalog — small JSON file, useful
# for tagging kev_listed without a second API integration. Also not
# reachable from this sandbox; same caveat as above applies.
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class NvdRateLimiter:
    """Sleeps between requests to respect NVD's published rate limits."""

    def __init__(self, has_api_key: bool):
        # Public: 5 req / 30s -> 6.0s/req is NVD's own recommended pace.
        # Keyed:  50 req / 30s -> 0.6s/req is safe with margin.
        self.delay = 0.6 if has_api_key else 6.0

    def wait(self):
        time.sleep(self.delay)


def fetch_cve(cve_id: str, api_key: Optional[str], rate_limiter: NvdRateLimiter) -> Optional[dict]:
    """Fetch a single CVE record by ID."""
    headers = {"apiKey": api_key} if api_key else {}
    params = {"cveId": cve_id}

    resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
    rate_limiter.wait()

    if resp.status_code != 200:
        print(f"  ! {cve_id}: HTTP {resp.status_code} — {resp.text[:200]}", file=sys.stderr)
        return None

    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print(f"  ! {cve_id}: not found in NVD", file=sys.stderr)
        return None

    return normalize_cve_record(vulns[0]["cve"])


def fetch_by_keyword(keyword: str, severity: Optional[str], api_key: Optional[str],
                      rate_limiter: NvdRateLimiter, max_results: int = 50) -> list[dict]:
    """Bulk pull CVEs matching a keyword (product name), optionally filtered by CVSS v3 severity."""
    headers = {"apiKey": api_key} if api_key else {}
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results, 2000),
    }
    if severity:
        params["cvssV3Severity"] = severity.upper()

    resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
    rate_limiter.wait()

    if resp.status_code != 200:
        print(f"  ! keyword '{keyword}': HTTP {resp.status_code} — {resp.text[:200]}", file=sys.stderr)
        return []

    data = resp.json()
    return [normalize_cve_record(v["cve"]) for v in data.get("vulnerabilities", [])]


def normalize_cve_record(cve: dict) -> dict:
    """
    Convert a raw NVD API 2.0 CVE object into the flat cve_kb schema
    defined in rag_retrieval_schema.md.
    """
    cve_id = cve.get("id")

    # English description — NVD returns descriptions in multiple languages.
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # Prefer CVSS v3.1, then v3.0, then fall back to v2 if that's all
    # that exists (common for very old CVEs).
    metrics = cve.get("metrics", {})
    cvss_score, cvss_vector, cvss_severity = None, None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            cvss_severity = (
                cvss_data.get("baseSeverity")
                or metrics[key][0].get("baseSeverity")
            )
            break

    cwe_ids = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                cwe_ids.append(desc["value"])

    references = [r.get("url") for r in cve.get("references", []) if r.get("url")]

    return {
        "id": cve_id,
        "text": description,
        "cvss_v3_score": cvss_score,
        "cvss_v3_vector": cvss_vector,
        "cvss_severity": cvss_severity,
        "cwe_ids": cwe_ids,
        "published_date": cve.get("published"),
        "last_modified_date": cve.get("lastModified"),
        "references": references[:5],  # cap for storage size
        "kev_listed": None,  # populated separately via fetch_kev_catalog()
        "kev_date_added": None,
    }


def fetch_kev_catalog() -> dict[str, str]:
    """
    Returns {cve_id: date_added} from CISA's KEV catalog. Best-effort —
    if unreachable, callers should treat kev_listed as unknown, not False.
    """
    resp = requests.get(CISA_KEV_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        entry["cveID"]: entry["dateAdded"]
        for entry in data.get("vulnerabilities", [])
    }


def load_kb(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_kb(path: Path, kb: dict):
    path.write_text(json.dumps(kb, indent=2))


def collect_cve_ids_from_findings(findings_path: Path) -> list[str]:
    """Extract every unique CVE ID referenced in a scored_findings.json file."""
    data = json.loads(findings_path.read_text())
    findings = data.get("all_scored_findings", data if isinstance(data, list) else [])
    cve_ids = set()
    for f in findings:
        for cve in f.get("cve_refs", []):
            cve_ids.add(cve)
    return sorted(cve_ids)


def main():
    parser = argparse.ArgumentParser(description="Ingest CVE data from NVD API 2.0 into a local cve_kb.")
    parser.add_argument("--cve-ids", nargs="+", help="Specific CVE IDs to fetch")
    parser.add_argument("--from-findings", help="Path to scored_findings.json — extracts CVE IDs automatically")
    parser.add_argument("--keyword", help="Bulk keyword search (e.g. product name) to pre-populate the KB")
    parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Filter keyword search by CVSS v3 severity")
    parser.add_argument("--max-results", type=int, default=50, help="Max results for keyword search")
    parser.add_argument("--kb-path", default=DEFAULT_KB_PATH, help="Path to local cve_kb JSON file")
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"), help="NVD API key (or set NVD_API_KEY env var)")
    parser.add_argument("--skip-kev", action="store_true", help="Skip CISA KEV enrichment")
    args = parser.parse_args()

    if not any([args.cve_ids, args.from_findings, args.keyword]):
        parser.error("Provide one of --cve-ids, --from-findings, or --keyword")

    kb_path = Path(args.kb_path)
    kb = load_kb(kb_path)
    rate_limiter = NvdRateLimiter(has_api_key=bool(args.api_key))

    if not args.api_key:
        print(
            "No API key provided — rate-limited to 5 req/30s. "
            "Get a free key: https://nvd.nist.gov/developers/request-an-api-key",
            file=sys.stderr,
        )

    cve_ids_to_fetch = list(args.cve_ids or [])
    if args.from_findings:
        found = collect_cve_ids_from_findings(Path(args.from_findings))
        print(f"Found {len(found)} unique CVE(s) in {args.from_findings}: {found}", file=sys.stderr)
        cve_ids_to_fetch.extend(found)

    cve_ids_to_fetch = sorted(set(cve_ids_to_fetch) - set(kb.keys()))  # skip already-cached

    print(f"Fetching {len(cve_ids_to_fetch)} CVE(s) individually...", file=sys.stderr)
    for cve_id in cve_ids_to_fetch:
        print(f"  -> {cve_id}", file=sys.stderr)
        record = fetch_cve(cve_id, args.api_key, rate_limiter)
        if record:
            kb[record["id"]] = record

    if args.keyword:
        print(f"Bulk fetching CVEs for keyword '{args.keyword}'...", file=sys.stderr)
        records = fetch_by_keyword(args.keyword, args.severity, args.api_key, rate_limiter, args.max_results)
        for record in records:
            kb[record["id"]] = record
        print(f"  -> retrieved {len(records)} record(s)", file=sys.stderr)

    if not args.skip_kev:
        try:
            print("Fetching CISA KEV catalog for exploited-in-the-wild tagging...", file=sys.stderr)
            kev_map = fetch_kev_catalog()
            matched = 0
            for cve_id, record in kb.items():
                if cve_id in kev_map:
                    record["kev_listed"] = True
                    record["kev_date_added"] = kev_map[cve_id]
                    matched += 1
                elif record.get("kev_listed") is None:
                    record["kev_listed"] = False
            print(f"  -> {matched} CVE(s) in this KB are CISA KEV-listed", file=sys.stderr)
        except Exception as e:
            print(f"  ! KEV fetch failed (non-fatal): {e}", file=sys.stderr)

    save_kb(kb_path, kb)
    print(f"\nSaved {len(kb)} total CVE record(s) to {kb_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
