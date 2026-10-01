"""
select_benchmark_subset.py

Builds the live-benchmark subset: EXACTLY ONE representative finding per
template, drawn from the already-generated 12-scan corpus. It does NOT
regenerate the corpus — it only filters the grounded_findings.json files
already sitting on disk.

Why one-per-template (see thesis notes): the hallucination benchmark only
needs grounded + ungrounded calls per finding (2 calls/finding). One
finding from each of the 15 HOST_TEMPLATES preserves full diversity —
all CVSS bands, every service type, and both no-CVE decoys — while
cutting the live cost from 58 findings (~116 calls) to 15 findings
(~30 calls), which fits the ~20 req/day free-tier quota in 1-2 days.

Executive summaries and remediation are NOT benchmark calls and are
deliberately excluded here (feature demo, not measurement).

Selection rule (deterministic):
  - A finding belongs to a template iff its hostname starts with that
    template's hostname-prefix (derived from HOST_TEMPLATES' format
    string, e.g. "dc{scan:02d}..." -> prefix "dc").
  - Representative = highest (type=vuln preferred, severity_score
    descending, then nse_script, port) finding of that template.
  - Pure-decoy templates emit an asset finding instead (they still carry
    an INFO/LOW band and CIS grounding, so they exercise the benchmark's
    "nothing to hallucinate" case).

Output: reports/benchmark_subset_grounded.json (flat findings list ready
for synthesize.py --scan-id benchmark-subset).

Usage:
    python src/select_benchmark_subset.py [--scan-root data/synthetic_corpus/scans]
"""

import argparse
import json
import glob
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCAN_ROOT = ROOT / "data" / "synthetic_corpus" / "scans"
DEFAULT_OUT = ROOT / "reports" / "benchmark_subset_grounded.json"


def _template_prefix(hostname_fmt: str) -> str:
    """Extract the literal prefix before the {scan} variable.

    "dc{scan:02d}.corp.local" -> "dc"; "decoy-ftp-{scan:02d}..." -> "decoy-ftp-"
    """
    return hostname_fmt.split("{scan", 1)[0]


def template_map() -> dict[str, dict]:
    """Map template name -> {prefix, template} from HOST_TEMPLATES."""
    sys.path.insert(0, str(ROOT / "src"))
    from corpus_generator import HOST_TEMPLATES

    by_prefix: dict[str, dict] = {}
    for t in HOST_TEMPLATES:
        prefix = _template_prefix(t["hostname"])
        by_prefix[prefix] = {"template": t, "name": t["name"]}
    return by_prefix


def assign_template(finding: dict, by_prefix: dict[str, dict]) -> str | None:
    """Return the template name for a finding, or None if unmatched."""
    hostname = finding.get("hostname") or ""
    for prefix, meta in by_prefix.items():
        if hostname.startswith(prefix):
            return meta["name"]
    return None


def sort_key(finding: dict) -> tuple:
    """Deterministic tie-break: prefer vuln, then higher severity, then script/port."""
    is_vuln = 1 if finding.get("type") == "vuln" else 0
    score = finding.get("severity_score") or 0.0
    return (is_vuln, score,
            finding.get("nse_script") or "",
            finding.get("port") or 0,
            finding.get("host") or "")


def load_all_findings(scan_root: Path) -> list[dict]:
    findings = []
    for gf in sorted(glob.glob(str(scan_root / "scan_*" / "grounded_findings.json"))):
        data = json.loads(Path(gf).read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data = data.get("all_scored_findings", [])
        findings.extend(data)
    return findings


def main():
    parser = argparse.ArgumentParser(description="Select one representative finding per template.")
    parser.add_argument("--scan-root", default=str(DEFAULT_SCAN_ROOT))
    parser.add_argument("-o", "--output", default=str(DEFAULT_OUT))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    scan_root = Path(args.scan_root)
    findings = load_all_findings(scan_root)
    by_prefix = template_map()

    # Group findings under their template.
    by_template: dict[str, list[dict]] = {}
    for f in findings:
        tpl = assign_template(f, by_prefix)
        if tpl is None:
            continue  # shouldn't happen with generated hosts; ignore defensively
        by_template.setdefault(tpl, []).append(f)

    selected = []
    missing = []
    for name, meta in by_prefix.items():
        tpl = meta["name"]
        candidates = by_template.get(tpl, [])
        if not candidates:
            missing.append(tpl)
            continue
        best = max(candidates, key=sort_key)
        selected.append(best)

    if missing:
        print(f"WARNING: no findings for templates: {sorted(missing)}", file=sys.stderr)

    # Deterministic output order (by template name) so the file is stable.
    selected.sort(key=lambda f: (assign_template(f, by_prefix) or "", f.get("host") or ""))

    # Uniqueness guard: resume keys are (scan_id, finding_ref, variant), so a
    # duplicated finding_ref inside the subset would break checkpointing.
    refs = [f"{f.get('host')}:{f.get('port')}/{f.get('protocol')}/{f.get('service')}/{(f.get('nse_script') or 'asset')}" for f in selected]
    if len(refs) != len(set(refs)):
        dup = sorted({r for r in refs if refs.count(r) > 1})
        print(f"ERROR: duplicate finding_ref in subset: {dup}", file=sys.stderr)
        sys.exit(1)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(selected, indent=2, ensure_ascii=False), encoding="utf-8")

    bands = sorted({f.get("severity_band") for f in selected})
    services = sorted({f.get("service") for f in selected})
    decoys = [f for f in selected if not f.get("cve_refs")]
    cve_total = sum(len(f.get("cve_refs", [])) for f in selected)
    print(f"Selected {len(selected)} findings (one per template, from {len(by_prefix)} templates)")
    print(f"  severity bands: {bands}")
    print(f"  services      : {services}")
    print(f"  decoy (no-CVE): {len(decoys)}")
    print(f"  CVE refs total: {cve_total}")
    print(f"  benchmark calls (x2 variants) : {len(selected) * 2}")
    if args.verbose:
        for f in selected:
            print(f"    {assign_template(f, by_prefix):26s} {f.get('type'):5s} "
                  f"{f.get('severity_band'):8s} {f.get('service')}:{f.get('port')} "
                  f"{(f.get('nse_script') or 'asset'):32s} {f.get('cve_refs')}")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()