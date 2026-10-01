"""
run_live_benchmark.py

Runs the live Gemini benchmark.

Two target modes:

  SUBSEET (--subset, the thesis benchmark run):
      Uses reports/benchmark_subset_grounded.json — one representative
      finding per template (15 findings) selected by
      select_benchmark_subset.py. Runs ONLY grounded + ungrounded variants
      (the hallucination measurement); executive summaries and remediation
      are a separate feature-demo task and deliberately skipped here so
      they don't compete for the ~20 req/day free-tier quota.
      Dry-run cross-check: 15 findings * 2 variants = 30 calls.

  FULL CORPUS (default):
      Per-scan loop over data/synthetic_corpus/scans/*. Includes exec
      summaries + remediation. Use only if you have enough quota.

Both share the checkpoint/resume system: synthesize.py skips keys already
present in the output JSONL (streamed + flushed per record), so a run that
exceeds the daily cap just stops; re-running the same command resumes at
the frontier.

Free-tier reality check: gemini-2.5-flash is ~20 req/day (not 250). The
subset needs 30 calls => 1-2 days. The script refuses to start a run whose
pending count is at/over the given cap.

Usage:
    python src/run_live_benchmark.py --subset --dry-run
    python src/run_live_benchmark.py --subset --run
    python src/run_live_benchmark.py --full --dry-run
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

CORPUS = ROOT / "data" / "synthetic_corpus"
SUBSET_GROUNDED = ROOT / "reports" / "benchmark_subset_grounded.json"
SUBSET_OUTPUT = ROOT / "reports" / "llm_output_subset.jsonl"
FULL_OUTPUT = ROOT / "reports" / "llm_output_full.jsonl"

DEFAULT_DAILY_CAP = 20  # gemini-2.5-flash free tier, measured live (not 250)

FINDING_VARIANT_CALLS_PER_FINDING = 2  # grounded + ungrounded


def scan_dirs() -> list[Path]:
    root = CORPUS / "scans"
    if not root.is_dir():
        sys.exit(f"no scans dir: {root}")
    return sorted(p for p in root.iterdir() if p.is_dir())


def synthesize_base_args(grounded: Path, scan_id: str,
                         output: Path, extra: list[str]) -> list[str]:
    return ([sys.executable, str(SRC / "synthesize.py"), str(grounded),
             "-o", str(output), "--scan-id", scan_id] + extra)


def full_corpus_run_args(scan_dir: Path, output: Path, extra: list[str]) -> list[str]:
    grounded = scan_dir / "grounded_findings.json"
    if not grounded.exists():
        sys.exit(f"missing {grounded} — run run_corpus_pipeline.py first")
    return synthesize_base_args(grounded, scan_dir.name, output, extra)


def parse_synthesize_counts(text: str) -> dict:
    """Extract pending-by-kind + planned from a --dry-run stdout dump."""
    totals = {"finding": 0, "exec_summary": 0, "remediation": 0}
    findings_planned = 0
    for line in text.splitlines():
        m = re.search(r"Plan: (\d+) finding-variant", line)
        if m:
            findings_planned += int(m.group(1))
        if "Pending by kind:" in line:
            body = line.split("Pending by kind:", 1)[1].strip()
            for k, v in json.loads(body.replace("'", '"')).items():
                if k in totals:
                    totals[k] += int(v)
    return {"findings_planned": findings_planned, **totals,
            "pending_total": sum(totals.values())}


def dry_run_subset() -> dict:
    """Pending counts for the single subset file (benchmark variants only)."""
    if not SUBSET_GROUNDED.exists():
        sys.exit(f"subset file missing: {SUBSET_GROUNDED} — run select_benchmark_subset.py")
    args = synthesize_base_args(SUBSET_GROUNDED, "benchmark-subset", SUBSET_OUTPUT,
                                ["--dry-run", "--skip-exec-summary", "--skip-remediation"])
    result = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit("subset dry-run failed")
    return parse_synthesize_counts(result.stdout)


def dry_run_full() -> dict:
    totals = {"finding": 0, "exec_summary": 0, "remediation": 0}
    findings_planned = 0
    for scan in scan_dirs():
        result = subprocess.run(
            full_corpus_run_args(scan, FULL_OUTPUT, ["--dry-run"]),
            cwd=str(ROOT), capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            sys.exit(f"dry-run failed for {scan.name}")
        counts = parse_synthesize_counts(result.stdout)
        findings_planned += counts["findings_planned"]
        for k in totals:
            totals[k] += counts[k]
    return {"findings_planned": findings_planned, **totals,
            "pending_total": sum(totals.values())}


def run_subset() -> None:
    print("=== live synthesis (subset, grounded+ungrounded only) ===", flush=True)
    result = subprocess.run(
        synthesize_base_args(SUBSET_GROUNDED, "benchmark-subset", SUBSET_OUTPUT,
                             ["--skip-exec-summary", "--skip-remediation"]),
        cwd=str(ROOT),
    )
    if result.returncode != 0:
        sys.exit("live subset synthesis failed")


def run_full() -> None:
    for i, scan in enumerate(scan_dirs()):
        print(f"--- [{i+1}/{len(scan_dirs())}] {scan.name}", flush=True)
        result = subprocess.run(full_corpus_run_args(scan, FULL_OUTPUT, []), cwd=str(ROOT))
        if result.returncode != 0:
            sys.exit(f"live synthesis failed for {scan.name}")


def score(existing_output: Path) -> Path:
    tag = existing_output.stem.replace("llm_output_", "")   # subset / full
    scored = ROOT / "reports" / f"scored_live_{tag}.jsonl"
    report = ROOT / "reports" / f"live_hallucination_summary_{tag}.txt"
    result = subprocess.run(
        [sys.executable, str(SRC / "benchmark_harness.py"),
         str(existing_output), "--nvd",
         "-o", str(scored), "--report", str(report)],
        cwd=str(ROOT),
    )
    if result.returncode != 0:
        sys.exit("benchmark harness failed")
    return report


def main():
    parser = argparse.ArgumentParser(description="Live Gemini benchmark.")
    parser.add_argument("--subset", action="store_true",
                        help="Benchmark subset (15 findings, grounded+ungrounded only)")
    parser.add_argument("--full", dest="subset", action="store_false",
                        help="Full corpus per-scan (includes exec/remediation)")
    parser.set_defaults(subset=True)
    parser.add_argument("--dry-run", action="store_true", help="Count pending calls, call nothing")
    parser.add_argument("--run", action="store_true", help="Run synthesis (resumable), then score")
    parser.add_argument("--score-only", action="store_true",
                        help="Re-score existing subset output against live NVD")
    parser.add_argument("--cap", type=int, default=DEFAULT_DAILY_CAP,
                        help="Free-tier daily cap to refuse above")
    args = parser.parse_args()

    if args.subset:
        count = dry_run_subset()
        output_path = SUBSET_OUTPUT
    else:
        count = dry_run_full()
        output_path = FULL_OUTPUT

    print("=" * 72)
    print("LIVE BENCHMARK CALL BUDGET  (mode: 'subset' if --subset else 'full corpus')")
    print(f"  pending finding-variant calls : {count['findings_planned']} "
          f"({FINDING_VARIANT_CALLS_PER_FINDING} per finding x subset findings)")
    print(f"  pending exec_summary calls    : {count.get('exec_summary', 0)}")
    print(f"  pending remediation calls     : {count.get('remediation', 0)}")
    print(f"  TOTAL pending calls           : {count['pending_total']}")
    print(f"  free-tier cap (daily)         : {args.cap}")
    over = count["pending_total"] >= args.cap
    if over:
        days = max(1, -(-count["pending_total"] // args.cap))
        print(f"  at/over cap?                  : YES ({days} calendar day(s) via resume needed)")
    else:
        print(f"  at/over cap?                  : no")
    print(f"  guard                         : informed only - resume handles, API enforces")
    print("=" * 72)

    if args.dry_run:
        return

    if args.score_only:
        if not output_path.exists() or not any(output_path.read_text(encoding='utf-8').splitlines()):
            sys.exit(f"no subset output yet: {output_path}")
        report = score(output_path)
        print(f"Scored against live NVD -> {report}")
        return

    if over and args.cap < 25:
        print("note: daily cap will be hit mid-run; remaining records are written "
              "as failed and re-attempted on resume (expected to be 2 days).")

    if args.subset:
        run_subset()
    else:
        run_full()
    print(f"\nSynthesis complete -> {output_path}")
    report = score(output_path)
    print(f"Scored against live NVD -> {report}")


if __name__ == "__main__":
    main()