"""
run_corpus_benchmark.py

Runs benchmark_harness.py over every scan's LLM output and folds the
per-scan scored records into a single corpus-wide hallucination benchmark
report.

Each scan scores with ITS OWN cve_kb.json as the existence source (the KB
subset injected into that scan's grounded prompt), so the grounded
comparison stays fair — a real CVE that was never in the scan's context is
still correctly classified as unsupported_cve (existence=True) rather than
fabricated_cve.

Usage:
    python src/run_corpus_benchmark.py [--corpus data/synthetic_corpus]
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
DEFAULT_CORPUS = ROOT / "data" / "synthetic_corpus"

sys.path.insert(0, str(SRC))
from benchmark_harness import (  # noqa: E402
    SCORABLE_VARIANTS,
    aggregate_per_variant,
    render_summary,
)


def main():
    parser = argparse.ArgumentParser(description="Corpus-wide hallucination benchmark.")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    args = parser.parse_args()

    corpus = Path(args.corpus)
    scans_root = corpus / "scans"
    scan_dirs = sorted(p for p in scans_root.iterdir() if p.is_dir())
    if not scan_dirs:
        sys.exit(f"No scan directories under {scans_root}")

    all_scored = []
    input_files = []
    total_skipped = 0

    for scan_dir in scan_dirs:
        llm_out = scan_dir / "llm_output.jsonl"
        if not llm_out.exists():
            continue
        cve_kb = scan_dir / "cve_kb.json"
        scored_path = scan_dir / "scored_benchmark.jsonl"
        report_path = scan_dir / "hallucination_summary.txt"

        args_list = [
            sys.executable, str(SRC / "benchmark_harness.py"), str(llm_out),
            "--cve-kb", str(cve_kb),
            "-o", str(scored_path), "--report", str(report_path),
        ]
        result = subprocess.run(args_list, cwd=str(ROOT), capture_output=True, text=True)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            sys.exit(f"harness failed for {scan_dir.name}")

        records = [json.loads(line) for line in scored_path.read_text().splitlines() if line.strip()]
        all_scored.extend(records)
        input_files.append(str(llm_out))

    if not all_scored:
        sys.exit("No scored records found — run run_corpus_pipeline.py first.")

    per_variant = {}
    for variant in SCORABLE_VARIANTS:
        subset = [s for s in all_scored if s["prompt_variant"] == variant]
        if subset:
            per_variant[variant] = aggregate_per_variant(subset)

    summary_text = render_summary(per_variant, "per-scan local cve_kb", input_files)
    out_report = corpus / "hallucination_summary.txt"
    out_report.write_text(summary_text, encoding="utf-8")

    merged = corpus / "scored_corpus.jsonl"
    with merged.open("w", encoding="utf-8") as fh:
        for s in all_scored:
            fh.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(summary_text)
    print(f"\nWrote merged scored corpus to {merged}")
    print(f"Wrote aggregate report to {out_report}")


if __name__ == "__main__":
    main()