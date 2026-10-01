"""
rule_engine.py

Deterministic, rule-based analysis engine. Takes the flat findings list
produced by nmap_parser.py and produces:
  1. A severity score + rating for each individual finding.
  2. An aggregated risk score per host.
  3. A prioritized findings list (highest risk first).

This layer runs BEFORE the RAG/LLM layer. Its job is to establish
severity and priority using transparent, auditable rules — not the LLM's
judgment. The RAG layer later attaches CVE/CIS evidence to these already-
scored findings, and the LLM only explains/summarizes what this engine
has already decided. This keeps severity ratings deterministic and
reproducible, which matters for your hallucination-benchmark story: the
LLM's job is narrowly "explain and cite," never "decide how bad this is."

Design notes:
- CVSS scores are the primary severity driver when a CVE is known. In
  this stub, CVSS is pulled from a small local lookup table
  (`CVE_CVSS_TABLE`) standing in for the real `cve_kb` NVD lookup that
  the RAG layer will eventually own. Swap `lookup_cvss()` for a real
  `cve_kb` query once that's built — the rest of the engine doesn't care
  where the number comes from.
- Non-CVE findings (expired certs, anonymous auth, etc.) get severity
  from a rule table keyed on NSE script id / keyword, since there's no
  CVSS to anchor to.
- Asset criticality is a multiplier, not a separate score — a medium
  finding on a domain controller should outrank a high finding on a
  disposable test box, and multiplying (rather than just tie-breaking)
  is what makes that happen.

Usage:
    python3 rule_engine.py findings_output.json
    python3 rule_engine.py findings_output.json -o scored_findings.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Rule tables — the deterministic, auditable heart of the engine.
# Every number here should be defensible/explainable to a reviewer; that's
# the whole point of a rule-based layer vs. an LLM guessing severity.
# ---------------------------------------------------------------------------

# Stand-in for a real NVD/cve_kb lookup. Maps CVE ID -> CVSS v3 base score.
CVE_CVSS_TABLE = {
    "CVE-2017-0143": 8.1,   # EternalBlue-family SMB RCE
    "CVE-2012-2122": 9.8,   # MySQL auth bypass
}

# Severity band from a numeric score (0-10 scale, CVSS-aligned).
def severity_band(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


# Fallback severity rules for findings with no CVE (keyed on nse_script id
# or a keyword substring in raw_output). Score is on the same 0-10 scale
# as CVSS so it can be compared/sorted alongside CVE-backed findings.
NON_CVE_SEVERITY_RULES = [
    # (match_fn, score, reason)
    (lambda f: f["nse_script"] == "ftp-anon", 5.5,
        "Anonymous FTP access allows unauthenticated file listing/upload"),
    (lambda f: f["nse_script"] == "ssl-known-key" and "expired" in (f["raw_output"] or "").lower(), 4.0,
        "Expired TLS certificate undermines transport trust and may trigger client warnings"),
    (lambda f: f["nse_script"] == "ssl-cert" and "not valid after" in (f["raw_output"] or "").lower(), 3.5,
        "TLS certificate has expired — encrypted channel cannot be authenticated"),
    (lambda f: f["nse_script"] == "ssl-cert" and "not valid after" not in (f["raw_output"] or "").lower(), 1.5,
        "TLS certificate metadata present; review validity and trust chain"),
    (lambda f: f["nse_script"] == "rdp-vuln-ms12-020", 7.5,
        "Unauthenticated remote denial-of-service against RDP service"),
    (lambda f: f["nse_script"] == "redis-info"
        and "no password" in (f["raw_output"] or "").lower(), 7.0,
        "Redis server reachable with no authentication — remote data theft/overwrite without credentials"),
    (lambda f: f["nse_script"] == "mongodb-info"
        and "no authentication" in (f["raw_output"] or "").lower(), 7.0,
        "MongoDB exposed with authentication disabled — unauthenticated access to all collections"),
    (lambda f: f["nse_script"] == "ssh-hostkey" and "weak" in (f["raw_output"] or "").lower(), 4.5,
        "Weak SSH host key algorithm lowers session-integrity guarantees and enables offline cracking"),
]

# Baseline exposure risk added when a sensitive service is open at all,
# independent of any specific vuln finding. This captures "attack surface"
# risk, not just "known vulnerability" risk.
EXPOSED_SERVICE_BASELINE = {
    "ftp": 1.0,
    "microsoft-ds": 1.5,   # SMB — historically high-value target
    "ms-wbt-server": 1.5,  # RDP — common ransomware entry vector
    "mysql": 1.0,
    "redis": 2.0,          # unauthenticated DB by default = data exposure
    "mongodb": 2.0,        # same reasoning as redis
    "telnet": 3.0,         # unencrypted mgmt protocol, if ever seen
}

# Asset criticality multipliers, matched against hostname/OS patterns.
# This is intentionally simple pattern matching for the thesis scope —
# a production system would pull this from a CMDB / asset inventory.
ASSET_CRITICALITY_RULES = [
    (lambda h: "dc" in (h["hostname"] or "").lower()
        or "domain controller" in (h["os_guess"] or "").lower()
        or "active directory" in "".join(h.get("services", [])).lower(),
        1.5, "Domain controller / identity infrastructure"),
    (lambda h: "fin" in (h["hostname"] or "").lower(), 1.3, "Finance-tagged workstation"),
    (lambda h: "web" in (h["hostname"] or "").lower(), 1.2, "Externally-facing application server"),
]
DEFAULT_CRITICALITY_MULTIPLIER = 1.0


def lookup_cvss(cve_id: str, cve_kb: Optional[dict] = None) -> float | None:
    """
    Resolve a CVE's CVSS v3 base score for severity scoring.

    Prefers the real `cve_kb` (NVD-derived, see ingest_nvd.py) when a KB
    is supplied — that's the authoritative source once retrieved data
    exists. `CVE_CVSS_TABLE` remains as a small built-in fallback so the
    engine still produces deterministic scores even when run standalone
    without a KB (e.g. on the sample corpus before grounding).
    """
    if cve_kb:
        record = cve_kb.get(cve_id)
        score = record.get("cvss_v3_score") if record else None
        if score is not None:
            return float(score)
    return CVE_CVSS_TABLE.get(cve_id)


def score_finding(finding: dict, cve_kb: Optional[dict] = None) -> dict:
    """Attach a severity score, band, and rationale to a single finding."""
    scored = dict(finding)

    if finding["type"] == "asset":
        base_score = EXPOSED_SERVICE_BASELINE.get(finding["service"], 0.0)
        scored["severity_score"] = round(base_score, 1)
        scored["severity_band"] = severity_band(base_score) if base_score > 0 else "INFO"
        scored["scoring_rationale"] = (
            f"Baseline exposure risk for open '{finding['service']}' service"
            if base_score > 0 else "Standard open service, no elevated exposure risk assigned"
        )
        return scored

    # type == "vuln"
    cve_scores = [
        s for s in (lookup_cvss(c, cve_kb) for c in finding["cve_refs"]) if s is not None
    ]
    if cve_scores:
        top_score = max(cve_scores)
        scored["severity_score"] = top_score
        scored["severity_band"] = severity_band(top_score)
        scored["scoring_rationale"] = (
            f"CVSS v3 base score {top_score} from {finding['cve_refs']}"
        )
        return scored

    # No CVE — check the non-CVE rule table.
    for match_fn, score, reason in NON_CVE_SEVERITY_RULES:
        if match_fn(finding):
            scored["severity_score"] = score
            scored["severity_band"] = severity_band(score)
            scored["scoring_rationale"] = reason
            return scored

    # Unmatched vuln finding — flag for manual/LLM triage rather than
    # silently dropping it. This is a deliberate "unknown" state, not a
    # zero score, so it doesn't get lost in prioritization.
    scored["severity_score"] = None
    scored["severity_band"] = "UNSCORED"
    scored["scoring_rationale"] = (
        "No CVE reference and no matching rule; requires manual/LLM review"
    )
    return scored


def compute_asset_criticality(host_findings: list[dict]) -> tuple[float, str]:
    """Determine a criticality multiplier for a host from its findings."""
    host_ctx = {
        "hostname": host_findings[0].get("hostname"),
        "os_guess": host_findings[0].get("os_guess"),
        "services": [f["service"] for f in host_findings],
    }
    for match_fn, multiplier, reason in ASSET_CRITICALITY_RULES:
        if match_fn(host_ctx):
            return multiplier, reason
    return DEFAULT_CRITICALITY_MULTIPLIER, "Standard asset, no elevated criticality tag matched"


def analyze(findings: list[dict], cve_kb: Optional[dict] = None) -> dict:
    """
    Score every finding, compute per-host aggregate risk, and return a
    structured, prioritized result.
    """
    scored_findings = [score_finding(f, cve_kb) for f in findings]

    # Group by host for aggregate scoring.
    hosts: dict[str, list[dict]] = {}
    for f in scored_findings:
        hosts.setdefault(f["host"], []).append(f)

    host_summaries = []
    for host_ip, host_findings in hosts.items():
        multiplier, criticality_reason = compute_asset_criticality(host_findings)

        vuln_scores = [
            f["severity_score"] for f in host_findings
            if f["type"] == "vuln" and f["severity_score"] is not None
        ]
        max_vuln_score = max(vuln_scores) if vuln_scores else 0.0
        adjusted_score = round(min(max_vuln_score * multiplier, 10.0), 1)

        unscored_count = sum(
            1 for f in host_findings if f.get("severity_band") == "UNSCORED"
        )

        host_summaries.append({
            "host": host_ip,
            "hostname": host_findings[0].get("hostname"),
            "os_guess": host_findings[0].get("os_guess"),
            "open_service_count": sum(1 for f in host_findings if f["type"] == "asset"),
            "vuln_finding_count": sum(1 for f in host_findings if f["type"] == "vuln"),
            "unscored_finding_count": unscored_count,
            "max_raw_vuln_score": max_vuln_score,
            "criticality_multiplier": multiplier,
            "criticality_reason": criticality_reason,
            "adjusted_risk_score": adjusted_score,
            "risk_band": severity_band(adjusted_score),
        })

    # Prioritize hosts by adjusted risk score, descending.
    host_summaries.sort(key=lambda h: h["adjusted_risk_score"], reverse=True)

    # Prioritize individual vuln findings the same way, for a flat
    # "top issues" list independent of host grouping.
    prioritized_vulns = sorted(
        [f for f in scored_findings if f["type"] == "vuln"],
        key=lambda f: (f["severity_score"] is not None, f["severity_score"] or 0),
        reverse=True,
    )

    return {
        "host_risk_summary": host_summaries,
        "prioritized_findings": prioritized_vulns,
        "all_scored_findings": scored_findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Rule-based severity scoring and prioritization engine.")
    parser.add_argument("findings_file", help="Path to findings JSON from nmap_parser.py")
    parser.add_argument("-o", "--output", help="Write JSON result to this file instead of stdout")
    parser.add_argument(
        "--cve-kb",
        help="Path to cve_kb JSON (dict keyed by CVE ID). When given, CVSS "
             "scores come from it instead of the built-in fallback table.",
    )
    parser.add_argument("--pretty", action="store_true", default=True, help="Pretty-print JSON (default on)")
    args = parser.parse_args()

    path = Path(args.findings_file)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    findings = json.loads(path.read_text())

    cve_kb = None
    if args.cve_kb:
        kb_path = Path(args.cve_kb)
        if not kb_path.exists():
            print(f"Error: cve_kb not found: {kb_path}", file=sys.stderr)
            sys.exit(1)
        cve_kb = json.loads(kb_path.read_text())

    result = analyze(findings, cve_kb)

    json_output = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(json_output)
        print(f"Wrote analysis to {args.output}")
    else:
        print(json_output)

    print("\n--- Host Risk Summary ---", file=sys.stderr)
    for h in result["host_risk_summary"]:
        print(
            f"{h['host']:16} {h['hostname'] or '':28} "
            f"risk={h['adjusted_risk_score']:>4} ({h['risk_band']:<8}) "
            f"vulns={h['vuln_finding_count']} unscored={h['unscored_finding_count']}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
