"""
synthesize.py

LLM synthesis layer. Consumes grounded_findings.json (retrieval.py output)
and produces:

  1. Per-finding plain-language explanations — for both the grounded and
     ungrounded prompt variants (ungrounded exists only for the benchmark).
  2. Per-host executive summaries.
  3. A scan-wide prioritized remediation list, in rule-engine priority order.

Design invariants (see project handoff):
  - The rule engine ALREADY decided severity/priority deterministically.
    This layer explains and cites; it never re-rates. The only module that
    talks to the network is llm_client.py — everything here that can be
    tested offline is tested offline.
  - Output records are appended to a JSONL file. Each record keeps the
    raw model text plus the prompt variant and the extraction result, so
    the benchmark harness can score them later WITHOUT re-running the LLM.
  - Rate limiting: Gemini free tier allows 10 req/min (gemini-2.5-flash).
    A default delay between calls keeps a full run inside quota; override
    with --delay 0 only if you have billing enabled or are running offline.

Usage:
    python3 synthesize.py ../data/grounded_findings.json \
        -o ../reports/llm_output.jsonl

    # offline/deterministic (MockClient) — no API key needed:
    python3 synthesize.py ../data/grounded_findings.json --offline \
        -o ../reports/llm_output.jsonl

    # skip the ungrounded variant (production report run):
    python3 synthesize.py ../data/grounded_findings.json --grounded-only

    # preview how many API calls a run will make, without calling:
    python3 synthesize.py ../data/grounded_findings.json --dry-run

    # live run that resumes from an existing output file (skips pairs whose
    # (scan_id, finding_ref, prompt_variant) key is already present):
    python3 synthesize.py ../data/grounded_findings.json -o out.jsonl \
        --scan-id scan_0001

Resume / checkpointing:
  - If the output file already exists, records already present (matched by
    the triple key (scan_id, finding_ref, prompt_variant)) are skipped, so
    a run that dies halfway can be re-invoked with the same command and
    only the missing IDs will be generated.
  - Each completed record is flushed to the output file immediately, so a
    crash can never lose the tail of the run — in the worst case the last
    in-flight call is redone on resume.
  - Use --scan-id to tag which scan a finding came from; this keeps the
    key unique even when different scans reuse the same host/port/service
    (the corpus generator reuses the 10.20.30.x range across scans).
  - --dry-run counts pending calls and stops without calling the API
    (handy for checking the total against the free-tier daily cap).

Rate limiting: retries with exponential backoff are handled in
llm_client.GeminiClient (429/quota-safe). The --delay flag still spaces
successive calls; it defaults to 6s for Gemini free tier (10 req/min).
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Optional

from cite_extract import extract_cve_ids
from llm_client import make_client
from prompt_templates import (
    build_executive_summary_prompt,
    build_grounded_prompt,
    build_remediation_prompt,
    build_ungrounded_prompt,
)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


def finding_ref(finding: dict) -> str:
    """Stable, human-readable identifier for a finding across pipeline stages."""
    nse = finding.get("nse_script") or "asset"
    return f"{finding.get('host')}:{finding.get('port')}/{finding.get('protocol')}/{finding.get('service')}/{nse}"


def _safe_json_parse(raw_text: str) -> Optional[dict]:
    """
    The model is asked for strict JSON, but models sometimes wrap it in
    markdown fences or add prose. Extract the first balanced {...} block
    and parse it; return None if nothing parseable survives.
    """
    start = raw_text.find("{")
    end = raw_text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(raw_text[start : end + 1])
    except json.JSONDecodeError:
        return None


def synthesize_finding(
    finding: dict,
    client,
    variants: tuple[str, ...],
    delay_s: float = 6.0,
) -> list[dict]:
    """
    Run the grounded and/or ungrounded prompt for a single finding.
    Returns one record per variant. Never raises on model/parse failure —
    a failed variant is recorded with its error so the benchmark can count
    it as a non-answer instead of silently dropping data.

    Note: the streaming main() uses plan_work()/_build_finding_record()/
    _append_record() for checkpointing; this buffered variant is kept for
    callers that want a one-shot in-memory batch (e.g. tests).
    """
    build_map = {
        "grounded": build_grounded_prompt,
        "ungrounded": build_ungrounded_prompt,
    }
    ref = finding_ref(finding)
    records = []
    for variant in variants:
        prompt = build_map[variant](finding)
        record = {
            "finding_ref": ref,
            "host": finding.get("host"),
            "port": finding.get("port"),
            "service": finding.get("service"),
            "nse_script": finding.get("nse_script"),
            "severity_band": finding.get("severity_band"),
            "prompt_variant": variant,
            "prompt": prompt,
            "retrieved_cve_ids": [
                r.get("id")
                for r in (finding.get("grounding_context") or {}).get("cve_records", [])
                if r.get("id")
            ],
        }
        try:
            raw = client.complete(prompt)
            record["raw_output"] = raw
            record["parsed"] = _safe_json_parse(raw) or {}
            # Independent extraction from raw prose — the authoritative
            # citation set for the benchmark (see cite_extract docstring).
            record["extracted_cve_ids"] = extract_cve_ids(raw)
            record["ok"] = True
        except Exception as e:  # noqa: BLE001 — record & continue is correct here
            record["ok"] = False
            record["error"] = f"{type(e).__name__}: {e}"
            record["raw_output"] = ""
            record["parsed"] = {}
            record["extracted_cve_ids"] = []
        records.append(record)
        if delay_s > 0:
            time.sleep(delay_s)
    return records


# ---------------------------------------------------------------------------
# Checkpointing / resume
# ---------------------------------------------------------------------------

def record_key(record: dict, scan_id: Optional[str]) -> tuple[str, str, str]:
    """The unique key used to skip already-done records on resume.

    Non-finding records (executive_summary, remediation) are keyed by their
    own variant plus a discriminator (the host for exec summaries) so they
    are generated exactly once per scan; finding records are keyed by
    (scan_id, finding_ref, prompt_variant).
    """
    variant = record.get("prompt_variant") or ""
    if variant == "executive_summary":
        return (scan_id or "", variant, record.get("host") or "")
    if variant == "remediation":
        return (scan_id or "", variant, variant)
    return (scan_id or "", record.get("finding_ref") or "", variant)


def load_existing_keys(path: Path) -> set[tuple[str, str, str]]:
    """Return the set of COMPLETED record keys already in a JSONL output.

    Only `ok: true` records count as done. A failed record (ok: false) is
    re-attempted on the next run — treating it as present would silently
    drop it from the benchmark.
    """
    if not path.exists():
        return set()
    keys: set[tuple[str, str, str]] = set()
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not rec.get("ok"):
                continue
            keys.add(record_key(rec, rec.get("scan_id")))
    return keys


def _append_record(record: dict, path: Path):
    """Append one record and flush immediately (crash-safe checkpointing)."""
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh.flush()


# ---------------------------------------------------------------------------
# Work scheduling (unit-testable, no side effects)
# ---------------------------------------------------------------------------

def plan_work(findings: list[dict], variants: tuple[str, ...],
              include_exec_summary: bool, include_remediation: bool) -> list[dict]:
    """Plan the ordered list of LLM calls for a run.

    Returns a list of ("type", finding) records describing each pending
    call. This is what --dry-run counts and what the run loop executes.
    """
    plan = []
    for f in findings:
        for v in variants:
            plan.append({"kind": "finding", "finding": f, "variant": v})
    if include_exec_summary:
        hosts = list(dict.fromkeys(f.get("host") for f in findings))
        for h in hosts:
            plan.append({"kind": "exec_summary", "host": h})
    if include_remediation:
        plan.append({"kind": "remediation"})
    return plan


def main():
    parser = argparse.ArgumentParser(description="LLM synthesis over grounded findings.")
    parser.add_argument("grounded_file", help="Path to grounded_findings.json (retrieval.py output)")
    parser.add_argument("-o", "--output", default="llm_output.jsonl", help="Output JSONL path")
    parser.add_argument(
        "--variants",
        nargs="+",
        choices=["grounded", "ungrounded"],
        default=["grounded", "ungrounded"],
        help="Which prompt variants to run (default: both)",
    )
    parser.add_argument("--grounded-only", action="store_true", help="Shorthand for --variants grounded")
    parser.add_argument("--scan-id", default=None,
                        help="Tag for this scan (keeps resume keys unique across scans)")
    parser.add_argument("--model", help="Override LLM model (default: GEMINI_MODEL env or gemini-2.5-flash)")
    parser.add_argument("--offline", action="store_true", help="Use deterministic MockClient (no API key/network)")
    parser.add_argument("--delay", type=float, default=6.0, help="Seconds between API calls (Gemini free tier: ~10/min)")
    parser.add_argument("--skip-exec-summary", action="store_true", help="Skip per-host executive summaries")
    parser.add_argument("--skip-remediation", action="store_true", help="Skip the remediation list")
    parser.add_argument("--dry-run", action="store_true",
                        help="Count pending calls and exit without calling the API")
    args = parser.parse_args()

    if args.grounded_only:
        variants = ("grounded",)
    else:
        variants = tuple(args.variants)

    findings = json.loads(Path(args.grounded_file).read_text(encoding="utf-8"))
    # Confirm the input is a flat findings list (retrieval output).
    if isinstance(findings, dict):
        findings = findings.get("all_scored_findings", [])

    plan = plan_work(findings, variants,
                     include_exec_summary=not args.skip_exec_summary,
                     include_remediation=not args.skip_remediation)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    existing = load_existing_keys(out_path)

    # ---- dry-run ----------------------------------------------------------
    if args.dry_run:
        done = 0
        pending_by_kind: dict[str, int] = {}
        for item in plan:
            if item["kind"] == "finding":
                rec = {"prompt_variant": item["variant"],
                       "finding_ref": finding_ref(item["finding"])}
                key = record_key(rec, args.scan_id)
            else:
                variant = "executive_summary" if item["kind"] == "exec_summary" else "remediation"
                rec = {"prompt_variant": variant}
                key = record_key(rec, args.scan_id)
            if key in existing:
                done += 1
            else:
                pending_by_kind[item["kind"]] = pending_by_kind.get(item["kind"], 0) + 1
        n_finding_plan = sum(1 for i in plan if i["kind"] == "finding")
        print(f"Plan: {n_finding_plan} finding-variant call(s), "
              f"{pending_by_kind.get('exec_summary', 0)} pending exec_summary, "
              f"{pending_by_kind.get('remediation', 0)} pending remediation")
        print(f"Total planned calls: {len(plan)} (already done: {done}, "
              f"pending: {sum(pending_by_kind.values())})")
        print("Pending by kind:", pending_by_kind)
        return

    client = make_client(model=args.model, offline=args.offline)

    n_ok = 0
    n_fail = 0
    n_skipped = 0
    produced: list[dict] = []
    for item in plan:
        if item["kind"] == "finding":
            record = _build_finding_record(item["finding"], item["variant"], args.scan_id)
        elif item["kind"] == "exec_summary":
            record = _build_exec_record(findings, item["host"], args.scan_id)
        else:  # remediation
            record = _build_remediation_record(findings, args.scan_id)
        key = record_key(record, args.scan_id)
        if key in existing:
            n_skipped += 1
            continue
        _run_record(record, client)
        if record.get("ok"):
            n_ok += 1
        else:
            n_fail += 1
        _append_record(record, out_path)
        produced.append(record)
        if args.delay > 0:
            time.sleep(args.delay)

    print(f"Completed: {n_ok} ok, {n_fail} failed, {n_skipped} skipped (already present)", file=sys.stderr)
    print(f"Output: {out_path}", file=sys.stderr)

    # Report network behavior for the live provider, if exposed.
    retries = getattr(client, "rate_limit_retries", 0)
    net_err = getattr(client, "network_errors", 0)
    if retries or net_err:
        print(f"Live client: {retries} rate-limit retry(ies), {net_err} network error(s)", file=sys.stderr)

    # Quick citation sanity for the grounded variant (same logic as before).
    if "grounded" in variants and produced:
        violations = 0
        checked = 0
        for rec in produced:
            if rec.get("prompt_variant") != "grounded" or not rec.get("ok"):
                continue
            allowed = set(CVE_PATTERN.findall(rec.get("prompt", "")))
            cited = set(rec.get("extracted_cve_ids", []))
            checked += 1
            if cited - allowed:
                violations += 1
        print(
            f"Smoke check (grounded): {violations}/{checked} records cited a CVE outside "
            f"the injected prompt's CVE set",
            file=sys.stderr,
        )


def _build_finding_record(finding: dict, variant: str, scan_id: Optional[str]) -> dict:
    build_map = {
        "grounded": build_grounded_prompt,
        "ungrounded": build_ungrounded_prompt,
    }
    prompt = build_map[variant](finding)
    return {
        "scan_id": scan_id,
        "finding_ref": finding_ref(finding),
        "host": finding.get("host"),
        "port": finding.get("port"),
        "service": finding.get("service"),
        "nse_script": finding.get("nse_script"),
        "severity_band": finding.get("severity_band"),
        "prompt_variant": variant,
        "prompt": prompt,
        "retrieved_cve_ids": [
            r.get("id")
            for r in (finding.get("grounding_context") or {}).get("cve_records", [])
            if r.get("id")
        ],
    }


def _build_exec_record(findings: list[dict], host: str, scan_id: Optional[str]) -> dict:
    host_findings = [f for f in findings if f.get("host") == host]
    prompt = build_executive_summary_prompt(host_findings)
    return {
        "scan_id": scan_id,
        "host": host,
        "hostname": host_findings[0].get("hostname") if host_findings else None,
        "prompt_variant": "executive_summary",
        "prompt": prompt,
        "finding_count": len(host_findings),
    }


def _build_remediation_record(findings: list[dict], scan_id: Optional[str]) -> dict:
    vulns = [f for f in findings if f.get("type") == "vuln"]
    assets = [f for f in findings if f.get("type") == "asset"]

    def sort_key(f):
        s = f.get("severity_score")
        return (s is not None, s or 0)

    vulns.sort(key=sort_key, reverse=True)
    assets.sort(key=sort_key, reverse=True)
    prioritized = vulns + assets

    prompt = build_remediation_prompt(prioritized)
    return {
        "scan_id": scan_id,
        "prompt_variant": "remediation",
        "prompt": prompt,
        "prioritized_finding_refs": [finding_ref(f) for f in prioritized],
    }


def _run_record(record: dict, client) -> None:
    """Execute the LLM call for one pending record, populating result fields."""
    try:
        raw = client.complete(record["prompt"])
        record["raw_output"] = raw
        record["parsed"] = _safe_json_parse(raw) or {}
        record["extracted_cve_ids"] = extract_cve_ids(raw)
        record["ok"] = True
    except Exception as e:  # noqa: BLE001 — record & continue is correct here
        record["ok"] = False
        record["error"] = f"{type(e).__name__}: {e}"
        record["raw_output"] = ""
        record["parsed"] = {}
        record["extracted_cve_ids"] = []


if __name__ == "__main__":
    main()
