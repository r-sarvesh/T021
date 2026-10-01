"""
run_corpus_pipeline.py

Drives the full benchmark pipeline over a generated synthetic corpus:

    nmap_parser.py  ->  rule_engine.py  ->  retrieval.py  ->  synthesize.py

for every scan in data/synthetic_corpus/scans/scan_*/ and emits:
  - per-scan intermediate artifacts (findings/scored/grounded JSON)
  - a consolidated corpus report (corpus_report.json) with grounding
    coverage checks (0 CVE "not found" everywhere) and severity diversity
    so the thesis appendix can assert corpus quality with numbers.

Usage:
    python src/run_corpus_pipeline.py [--corpus data/synthetic_corpus] [--offline]
"""

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
DEFAULT_CORPUS = ROOT / "data" / "synthetic_corpus"


def run_stage(cmd: list[str]) -> None:
    """Run one pipeline stage as a subprocess, inheriting stdout/stderr."""
    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        sys.exit(f"Stage failed ({result.returncode}): {' '.join(cmd)}")


def process_scan(scan_dir: Path, offline: bool) -> dict:
    xml = scan_dir / "scan.xml"
    findings = scan_dir / "findings.json"
    scored = scan_dir / "scored_findings.json"
    grounded = scan_dir / "grounded_findings.json"
    cve_kb = scan_dir / "cve_kb.json"
    cis_kb = scan_dir / "cis_kb.json"

    run_stage([sys.executable, str(SRC / "nmap_parser.py"), str(xml),
               "-o", str(findings), "--pretty"])
    run_stage([sys.executable, str(SRC / "rule_engine.py"), str(findings),
               "--cve-kb", str(cve_kb), "-o", str(scored)])
    run_stage([sys.executable, str(SRC / "retrieval.py"), str(scored),
               "--cve-kb", str(cve_kb), "--cis-kb", str(cis_kb),
               "-o", str(grounded)])
    run_stage([sys.executable, str(SRC / "synthesize.py"), str(grounded),
               "-o", str(scan_dir / "llm_output.jsonl"),
               "--offline", "--delay", "0" if offline else "6"])

    # ---- corpus-quality checks -------------------------------------------
    grounded_data = json.loads(grounded.read_text(encoding="utf-8"))
    findings_data = json.loads(findings.read_text(encoding="utf-8"))

    not_found = []
    resolved = 0
    for f in grounded_data:
        for rec in f.get("grounding_context", {}).get("cve_records", []):
            if rec.get("status") == "not_found":
                not_found.append((f.get("cve_refs"), f.get("nse_script")))
            else:
                resolved += 1

    cve_refs_total = sum(len(f.get("cve_refs", [])) for f in findings_data)
    decoy_vulns = sum(
        1 for f in findings_data
        if f["type"] == "vuln" and not f.get("cve_refs")
    )

    return {
        "scan_id": scan_dir.name,
        "hosts": len({f["host"] for f in grounded_data}),
        "findings": len(grounded_data),
        "vuln_findings": sum(1 for f in grounded_data if f["type"] == "vuln"),
        "decoy_vuln_findings": decoy_vulns,
        "cve_refs_total": cve_refs_total,
        "cve_resolved": resolved,
        "cve_not_found": len(not_found),
        "cve_not_found_details": not_found,
    }


def main():
    parser = argparse.ArgumentParser(description="Run full pipeline over the synthetic corpus.")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--offline", action="store_true",
                        help="Use deterministic MockClient instead of live Gemini")
    args = parser.parse_args()

    corpus = Path(args.corpus)
    scans_root = corpus / "scans"
    if not scans_root.exists():
        sys.exit(f"No scans directory: {scans_root}")

    scan_dirs = sorted(p for p in scans_root.iterdir() if p.is_dir())
    if not scan_dirs:
        sys.exit(f"No scan directories under {scans_root}")

    report = {"scan_results": [], "totals": {}, "coverage_ok": True}
    for scan_dir in scan_dirs:
        print(f"\n===== {scan_dir.name} =====")
        row = process_scan(scan_dir, args.offline)
        report["scan_results"].append(row)
        if row["cve_not_found"]:
            report["coverage_ok"] = False
            print(f"  !! {row['cve_not_found']} CVE not_found in {scan_dir.name}")

    sev_bands = Counter()
    for row in report["scan_results"]:
        pass
    for row in report["scan_results"]:
        row["severity_bands"] = _severity_bands(corpus / "scans" / row["scan_id"] / "scored_findings.json")

    report["totals"] = {
        "scans": len(scan_dirs),
        "findings": sum(r["findings"] for r in report["scan_results"]),
        "vuln_findings": sum(r["vuln_findings"] for r in report["scan_results"]),
        "decoy_vuln_findings": sum(r["decoy_vuln_findings"] for r in report["scan_results"]),
        "cve_refs_total": sum(r["cve_refs_total"] for r in report["scan_results"]),
        "cve_resolved": sum(r["cve_resolved"] for r in report["scan_results"]),
        "cve_not_found": sum(r["cve_not_found"] for r in report["scan_results"]),
    }
    # Severity diversity across the whole corpus (unique bands seen).
    all_bands = set()
    for row in report["scan_results"]:
        all_bands.update(row["severity_bands"])
    report["totals"]["severity_bands_seen"] = sorted(all_bands)
    report["coverage_ok"] = report["coverage_ok"] and (
        report["totals"]["cve_not_found"] == 0
        and report["totals"]["cve_refs_total"] == report["totals"]["cve_resolved"]
    )

    report_path = corpus / "corpus_report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n===== CORPUS REPORT: {report_path} =====")
    print(json.dumps(report["totals"], indent=2, ensure_ascii=False))
    if report["coverage_ok"]:
        print("\nCOVERAGE OK: every CVE referenced resolved in its scan's KB.")
    else:
        print("\nCOVERAGE FAILED: see corpus_report.json for not_found details.")


def _severity_bands(scored_path: Path) -> list[str]:
    try:
        data = json.loads(scored_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    findings = data.get("all_scored_findings", data) if isinstance(data, dict) else data
    return sorted({f.get("severity_band") for f in findings if f.get("severity_band")})


if __name__ == "__main__":
    main()
