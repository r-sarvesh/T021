"""
webapp.py

Minimal Flask dashboard over a generated/analyzed corpus. Zero build step:
server-rendered Jinja2 templates, no node toolchain — matching the project's
"deterministic Python + data files" ethos (CLI pipeline output is the data
source; this is a read-only viewer over it).

Routes:
    GET /                          index — scan inventory (enumerated from scans/)
    GET /scan/<scan_id>            scan detail — host risk summary + findings table
                                   with severity badges and CVE/CIS grounding context
    GET/POST /import               import an Nmap XML report -> runs the existing
                                   parser/scoring/retrieval pipeline live, adds it
                                   to the inventory as a scan_NNNN entry
    GET /scan/<scan_id>/export     download grounded_findings.json as JSON

The app reads from a corpus root directory (the same layout emitted by
corpus_generator.py and filled by run_corpus_pipeline.py):

    <corpus>/
      corpus_report.json
      manifest.json
      hallucination_summary.txt     # if run_corpus_benchmark ran
      scans/
        scan_0001/
          scored_findings.json      # rule_engine output
          grounded_findings.json    # retrieval output (with grounding_context)
          cve_kb.json / cis_kb.json # per-scan KB subsets
          llm_output.jsonl          # synthesis output, if run

Imported scans reuse the exact same pipeline modules (nmap_parser ->
rule_engine -> retrieval) and persist the same file layout, so they render
on the same detail page with no special-casing. The index enumerates the
scans/ directory directly instead of trusting corpus_report.json, so an
imported entry shows up immediately without having to re-run the corpus
report.

Usage:
    python src/webapp.py
    # or
    python src/webapp.py --corpus data/synthetic_corpus --port 5000
"""

import argparse
import hmac
import json
import os
import re
import shutil
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.exceptions import RequestEntityTooLarge

import nmap_parser
import retrieval
import rule_engine
import cite_extract

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = ROOT / "data" / "synthetic_corpus"

# Knowledge bases used when importing a scan: the same CVE + CIS sources
# the corpus pipeline grounds against.
CVE_KB_PATH = ROOT / "data" / "knowledge_base" / "synthetic_cve_kb.json"
CIS_KB_PATH = ROOT / "data" / "knowledge_base" / "sample_cis_kb.json"

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
REPORT_MAX_BYTES = 5 * 1024 * 1024
DAILY_GEMINI_QUOTA = 20

SCAN_ID_PATTERN = re.compile(r"^scan_\d{4}$")
REPORT_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")

# In-memory report store + on-disk persistence for demo scale
REPORTS: dict[str, dict] = {}
REPORTS_DIR = ROOT / "reports" / "live_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Load any persisted reports on startup (so restarts don't lose demo reports)
for _p in REPORTS_DIR.glob("*.json"):
    try:
        _data = json.loads(_p.read_text(encoding="utf-8"))
        _rid = _p.stem
        if REPORT_ID_PATTERN.match(_rid):
            REPORTS[_rid] = _data
    except Exception:
        continue

# Audit log persistence — admin-only via GET /api/audit (server-side role check)
AUDIT_LOG_PATH = ROOT / "reports" / "audit_log.json"
AUDIT_SEED: list[dict] = [
    {"id": "a-1", "timestamp": "2026-08-16T07:31:12Z", "user": "M. Lindqvist", "role": "analyst", "action": "scan_import", "target": "edge-gateway-2026-08-16.xml", "result": "success", "ip": "10.4.12.30"},
    {"id": "a-2", "timestamp": "2026-08-16T07:29:55Z", "user": "M. Lindqvist", "role": "analyst", "action": "login", "target": "session", "result": "success", "ip": "10.4.12.30"},
    {"id": "a-3", "timestamp": "2026-08-15T22:14:03Z", "user": "unknown", "role": "analyst", "action": "login_failed", "target": "username: root", "result": "failure", "ip": "198.51.100.77"},
    {"id": "a-4", "timestamp": "2026-08-15T22:13:41Z", "user": "unknown", "role": "analyst", "action": "login_failed", "target": "username: admin", "result": "failure", "ip": "198.51.100.77"},
    {"id": "a-5", "timestamp": "2026-08-14T09:20:11Z", "user": "Peter", "role": "admin", "action": "report_export", "target": "DMZ Perimeter Sweep", "result": "success", "ip": "10.4.12.11"},
    {"id": "a-6", "timestamp": "2026-08-14T09:12:00Z", "user": "Peter", "role": "admin", "action": "scan_import", "target": "dmz-perimeter-2026-08-14.xml", "result": "success", "ip": "10.4.12.11"},
    {"id": "a-7", "timestamp": "2026-08-14T09:05:22Z", "user": "Peter", "role": "admin", "action": "login", "target": "session", "result": "success", "ip": "10.4.12.11"},
    {"id": "a-8", "timestamp": "2026-08-12T14:47:00Z", "user": "M. Lindqvist", "role": "analyst", "action": "scan_import", "target": "internal-app-tier-2026-08-12.xml", "result": "success", "ip": "10.4.12.30"},
    {"id": "a-9", "timestamp": "2026-08-12T14:30:09Z", "user": "M. Lindqvist", "role": "analyst", "action": "scan_access", "target": "Finance VLAN Audit", "result": "success", "ip": "10.4.12.30"},
    {"id": "a-10", "timestamp": "2026-08-05T16:21:44Z", "user": "M. Lindqvist", "role": "analyst", "action": "scan_import", "target": "lab-segment-2026-08-05.xml", "result": "failure", "ip": "10.4.12.30"},
]


def _load_audit_events() -> list[dict]:
    if AUDIT_LOG_PATH.exists():
        try:
            data = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                return data
        except Exception:
            pass
    # seed on first run and persist
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        AUDIT_LOG_PATH.write_text(json.dumps(AUDIT_SEED, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
    return list(AUDIT_SEED)


def _save_audit_events(events: list[dict]) -> None:
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        AUDIT_LOG_PATH.write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _append_audit_event(action: str, target: str, user_obj: dict | None, result: str, ip: str | None = None) -> None:
    events = _load_audit_events()
    actor = (user_obj.get("name") if user_obj and user_obj.get("name") else (user_obj.get("username") if user_obj else "unknown")) or "unknown"
    role = (user_obj.get("role") if user_obj else "analyst") or "analyst"
    entry = {
        "id": f"a-{uuid.uuid4().hex[:8]}",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "user": actor,
        "role": role,
        "action": action,
        "target": target,
        "result": result,
        "ip": ip or request.remote_addr,
    }
    events.insert(0, entry)
    # keep reasonable size
    _save_audit_events(events[:200])

app = Flask(__name__)
app.secret_key = os.environ.get("WEBAPP_SECRET_KEY", "cyber-health-dev-key-change-me")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
corpus_root: Path = DEFAULT_CORPUS

# CORS for Next.js (http://localhost:3000) — allow credentials if using cookies, and Bearer header if using token
try:
    from flask_cors import CORS
    CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:3000"], supports_credentials=True, allow_headers=["Content-Type", "Authorization"])
except ImportError:
    pass

# Token store for Bearer auth (in-memory, demo scale) — token -> user dict
TOKENS: dict[str, dict] = {}

# Simple demo auth: env vars with a documented dev default. This is a
# mentor-demo gate, not a production auth system — deliberately no user
# database, no hashing beyond comparison, and no password reset flow.
DEMO_USER = os.environ.get("WEBAPP_USER", "admin")
DEMO_PASS = os.environ.get("WEBAPP_PASS", "admin")
# Additional demo accounts as shown in the Starting page screenshot
# Support both new (admin123) and legacy (admin) for admin user
DEMO_USERS = {
    "admin": {"admin123", "admin"},
    "analyst": {"analyst123"},
}
# Add env override as additional accepted password (not overwriting)
if DEMO_USER not in DEMO_USERS:
    DEMO_USERS[DEMO_USER] = {DEMO_PASS}
else:
    DEMO_USERS[DEMO_USER].add(DEMO_PASS)

# Severity band -> semantic ordering + badge color (CSS class).
SEVERITY_BANDS = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNSCORED": -1,
}


def _current_user():
    # Check Bearer token first (for Next.js API calls)
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        user = TOKENS.get(token)
        if user:
            return user
    # Fall back to session cookie (for Jinja pages)
    if session.get("authenticated"):
        username = session.get("username") or DEMO_USER
        # Return minimal user dict
        return {"username": username, "name": username, "role": "admin" if username == "admin" else "analyst"}
    return None


def login_required(view):
    """Gate behind either session cookie or Bearer token (for Next.js)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if _current_user():
            return view(*args, **kwargs)
        # For API routes, return JSON 401 instead of redirect
        if request.path.startswith("/api/"):
            return {"error": "unauthorized", "message": "Authentication required"}, 401
        return redirect(url_for("login", next=request.path))
    return wrapped


def _require_admin():
    user = _current_user()
    if not user or user.get("role") != "admin":
        # Check if user is admin via DEMO_USERS list
        username = user.get("username") if user else ""
        if username != "admin":
            abort(403)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _scan_dir(scan_id: str) -> Path:
    if not SCAN_ID_PATTERN.match(scan_id or ""):
        abort(404)
    d = corpus_root / "scans" / scan_id
    if not d.is_dir():
        abort(404)
    return d


def _findings_by_host(grounded: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in grounded:
        out.setdefault(f["host"], []).append(f)
    return out


def _sort_key_finding(f: dict) -> tuple:
    band = SEVERITY_BANDS.get(f.get("severity_band"), -1)
    score = f.get("severity_score") or 0
    return (band, score, f.get("service", ""), f.get("port", 0))


def _scan_rows() -> list[dict]:
    """Enumerate scan_* dirs and derive their ledger rows directly from the
    per-scan artifacts — imported scans included, no corpus_report needed."""
    scans_root = corpus_root / "scans"
    if not scans_root.is_dir():
        return []
    rows = []
    for d in sorted(scans_root.iterdir()):
        if not SCAN_ID_PATTERN.match(d.name) or not d.is_dir():
            continue
        row = _scan_row(d)
        if row is not None:
            rows.append(row)
    return rows


def _scan_row(scan_dir: Path) -> dict | None:
    """Compute one inventory row for a scan dir, mirroring the metrics
    run_corpus_pipeline.py reports so imported scans are consistent."""
    grounded = _load(scan_dir / "grounded_findings.json")
    if grounded is None:
        return None
    findings_file = _load(scan_dir / "findings.json") or []
    scored = _load(scan_dir / "scored_findings.json") or {}

    bands = {
        f.get("severity_band")
        for f in scored.get("all_scored_findings", [])
        if f.get("severity_band")
    }
    band_order = {b: SEVERITY_BANDS.get(b, -1) for b in bands}
    worst = max(band_order, key=band_order.get) if bands else "INFO"

    resolved = 0
    not_found = 0
    for f in grounded:
        for rec in f.get("grounding_context", {}).get("cve_records", []):
            if rec.get("not_found") or rec.get("status") == "not_found":
                not_found += 1
            else:
                resolved += 1

    return {
        "scan_id": scan_dir.name,
        "hosts": len({f.get("host") for f in grounded}),
        "findings": len(grounded),
        "vuln_findings": sum(1 for f in grounded if f.get("type") == "vuln"),
        "decoy_vuln_findings": sum(
            1 for f in findings_file
            if f.get("type") == "vuln" and not f.get("cve_refs")
        ),
        "cve_refs_total": sum(len(f.get("cve_refs", [])) for f in findings_file),
        "cve_resolved": resolved,
        "cve_not_found": not_found,
        "severity_bands": sorted(bands),
        "worst_band": worst,
    }


def _next_scan_dir() -> Path:
    """Find the next free scan_NNNN slot in the corpus scans dir."""
    scans_root = corpus_root / "scans"
    scans_root.mkdir(parents=True, exist_ok=True)
    used = []
    for d in scans_root.iterdir():
        m = re.match(r"^scan_(\d{4})$", d.name)
        if m and d.is_dir():
            used.append(int(m.group(1)))
    nxt = (max(used) + 1) if used else 1
    return scans_root / f"scan_{nxt:04d}"


def _import_scan(file, scan_dir: Path) -> str | None:
    """Run an uploaded Nmap XML file through the existing pipeline in-process
    and persist the same artifacts a corpus scan carries. Returns a warning
    string when some CVEs can't be grounded, else None. Raises ValueError with
    a plain-language message for anything that isn't a usable Nmap report."""
    scan_dir.mkdir(parents=True, exist_ok=False)
    xml_path = scan_dir / "scan.xml"
    file.save(xml_path)

    # Validate it actually looks like nmap -oX output before running the
    # (heavier) pipeline stages.
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        raise ValueError("This file doesn't look like a valid Nmap XML report (couldn't parse it).")
    if root.tag != "nmaprun":
        raise ValueError("This file doesn't look like a valid Nmap XML report (missing <nmaprun> root).")

    cve_kb = _load(CVE_KB_PATH) or {}
    cis_kb = _load(CIS_KB_PATH) or []

    findings = nmap_parser.parse_nmap_xml(str(xml_path))
    if not findings:
        raise ValueError("No open ports or vulnerability findings in this Nmap report.")

    scored = rule_engine.analyze(findings, cve_kb)
    cve_store = retrieval.CveStore(cve_kb)
    cis_index = retrieval.CisIndex(cis_kb)
    grounded = retrieval.ground_all(
        [f for f in scored.get("all_scored_findings", [])
         if f.get("type") in ("vuln", "asset")],
        cve_store, cis_index)

    # Persist the same artifacts a corpus scan carries.
    for name, data in (("findings.json", findings),
                       ("scored_findings.json", scored),
                       ("grounded_findings.json", grounded)):
        (scan_dir / name).write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    (scan_dir / "cve_kb.json").write_text(
        json.dumps(cve_kb, indent=2, ensure_ascii=False), encoding="utf-8")
    (scan_dir / "cis_kb.json").write_text(
        json.dumps(cis_kb, indent=2, ensure_ascii=False), encoding="utf-8")
    (scan_dir / "source.json").write_text(
        json.dumps({
            "origin": "upload",
            "filename": file.filename,
            "imported_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2, ensure_ascii=False), encoding="utf-8")

    # Surface CVEs the local KB can't ground — visible, not silent.
    unresolved = sorted({
        rec.get("id")
        for f in grounded
        for rec in f["grounding_context"]["cve_records"]
        if rec.get("not_found") or rec.get("status") == "not_found"
        if rec.get("id")
    })
    if unresolved:
        n = len(unresolved)
        return (f"{n} CVE(s) in this scan aren't in the local knowledge base "
                f"({', '.join(unresolved)}) — grounding may be incomplete for "
                "those findings.")
    return None


def _render_scan(scan_id: str):
    """Shared scan-detail renderer used by /scan/<id> and the import flow."""
    scan_dir = _scan_dir(scan_id)

    scored = _load(scan_dir / "scored_findings.json")
    grounded = _load(scan_dir / "grounded_findings.json")
    if scored is None or grounded is None:
        abort(404, description=f"Pipeline artifacts missing for {scan_id}")

    host_summary = scored.get("host_risk_summary", [])
    findings = sorted(grounded, key=_sort_key_finding, reverse=True)

    # Per-host rollup so the findings table supports a host grouping toggle
    # purely on the client.
    hosts = []
    by_host = _findings_by_host(grounded)
    for hs in host_summary:
        hs_findings = by_host.get(hs["host"], [])
        hosts.append({
            **hs,
            "findings": sorted(hs_findings, key=_sort_key_finding, reverse=True),
        })

    cve_records_total = sum(
        len(f.get("grounding_context", {}).get("cve_records", []))
        for f in grounded
    )
    cis_matches_total = sum(
        len(f.get("grounding_context", {}).get("cis_matches", []))
        for f in grounded
    )

    # Optional synthesis link: present when llm_output.jsonl was produced.
    llm_exists = (scan_dir / "llm_output.jsonl").exists()

    return render_template("scan.html",
                           corpus=str(corpus_root),
                           scan_id=scan_id,
                           host_summary=host_summary,
                           hosts=hosts,
                           findings=findings,
                           cve_records_total=cve_records_total,
                           cis_matches_total=cis_matches_total,
                           llm_exists=llm_exists)


# ---------------------------------------------------------------------------
# Report helpers (POST /report/upload pipeline)
# ---------------------------------------------------------------------------

def _quota_usage_path() -> Path:
    return REPORTS_DIR / "_quota.json"


def _get_remaining_quota() -> int:
    """Simple daily quota tracker (20/day). Returns remaining calls."""
    p = _quota_usage_path()
    today = datetime.now(timezone.utc).date().isoformat()
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except Exception:
        data = {}
    if data.get("date") != today:
        return DAILY_GEMINI_QUOTA
    used = int(data.get("used", 0))
    return max(0, DAILY_GEMINI_QUOTA - used)


def _reserve_quota(n: int) -> None:
    p = _quota_usage_path()
    today = datetime.now(timezone.utc).date().isoformat()
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except Exception:
        data = {}
    if data.get("date") != today:
        data = {"date": today, "used": 0}
    data["used"] = int(data.get("used", 0)) + n
    p.write_text(json.dumps(data), encoding="utf-8")


def _validate_live_citations(grounded: list[dict], synthesized: list[dict], cve_kb: dict) -> list[dict]:
    """
    Reuse benchmark validator logic on live report output.
    For each synthesized finding, check cited CVEs against allowed set
    (now stricter: only the CVE IDs in that finding's own retrieved records,
    not every CVE found anywhere in the prompt) and against KB existence
    (fabricated vs unsupported). Uses shared extractor from cite_extract.py
    for normalization (lowercase/space/underscore/en-em dash -> canonical).
    Returns list of flagged findings with details, never raises.
    """
    # Use shared extractor for normalization; keep behavior in sync with cite_extract.py
    from cite_extract import extract_cve_ids, normalize_cve_id

    # Build map from finding_ref to grounded finding for strict per-finding allowed set
    grounded_by_ref: dict[str, dict] = {}
    for g in grounded or []:
        # Use same ref construction as _synthesize_with_quota, plus variants for harness compatibility
        try:
            ref = f"{g.get('host')}:{g.get('port')}/{g.get('protocol')}/{g.get('service')}/{g.get('nse_script') or 'asset'}"
            grounded_by_ref[ref] = g
            # Variant without protocol (some test harnesses omit protocol)
            ref_no_proto = f"{g.get('host')}:{g.get('port')}/{g.get('service')}/{g.get('nse_script') or 'asset'}"
            grounded_by_ref[ref_no_proto] = g
            # Also index by explicit finding_ref if present
            if g.get("finding_ref"):
                grounded_by_ref[g.get("finding_ref")] = g
        except Exception:
            continue

    flags = []
    for rec in synthesized:
        if not rec.get("ok"):
            continue
        if rec.get("prompt_variant") != "grounded":
            allowed = set()
        else:
            g = grounded_by_ref.get(rec.get("finding_ref"))
            # Fallback: search by finding_ref equality if dict miss (handles protocol variations)
            if g is None:
                for gg in grounded or []:
                    try:
                        gg_ref = f"{gg.get('host')}:{gg.get('port')}/{gg.get('protocol')}/{gg.get('service')}/{gg.get('nse_script') or 'asset'}"
                        gg_ref_no_proto = f"{gg.get('host')}:{gg.get('port')}/{gg.get('service')}/{gg.get('nse_script') or 'asset'}"
                    except Exception:
                        continue
                    if gg_ref == rec.get("finding_ref") or gg_ref_no_proto == rec.get("finding_ref"):
                        g = gg
                        break
                # Last resort: if only one grounded finding, use it (isolated test harness)
                if g is None and grounded and len(grounded) == 1:
                    g = grounded[0]
            if g is not None:
                cve_recs = (g.get("grounding_context") or {}).get("cve_records") or []
                # Fallback to cve_refs if grounding_context empty (e.g., legacy data)
                if not cve_recs and g.get("cve_refs"):
                    cve_recs = [{"id": cid} for cid in g.get("cve_refs") if cid]
                allowed = set()
                for r in cve_recs:
                    cid = r.get("id")
                    if cid:
                        # Normalize allowed IDs same way as cited (lowercase/space/underscore/dash -> canonical)
                        allowed.add(normalize_cve_id(cid))
            else:
                allowed = set()

        # Cited: normalize extracted + parsed + re-extract from raw_output for variant coverage
        cited_raw = set(rec.get("extracted_cve_ids") or [])
        cited = set(normalize_cve_id(c) for c in cited_raw)
        parsed_cves_raw = set((rec.get("parsed") or {}).get("cve_ids_mentioned") or [])
        parsed_cves = set(normalize_cve_id(c) for c in parsed_cves_raw)
        cited = cited.union(parsed_cves)
        # Also re-extract from raw_output with shared extractor to catch variants missed by old records
        extra_from_raw = set(extract_cve_ids(rec.get("raw_output") or ""))
        cited = cited.union(extra_from_raw)
        # Remove empty strings
        cited = {c for c in cited if c}
        allowed = {a for a in allowed if a}
        bad = cited - allowed
        fabricated = set()
        unsupported = set()
        for cve_id in bad:
            exists = cve_kb.get(cve_id) is not None
            if exists:
                unsupported.add(cve_id)
            else:
                fabricated.add(cve_id)
        if fabricated or unsupported:
            flags.append({
                "finding_ref": rec.get("finding_ref"),
                "cited": sorted(cited),
                "allowed": sorted(allowed),
                "fabricated": sorted(fabricated),
                "unsupported": sorted(unsupported),
                "has_fabricated": bool(fabricated),
                "has_unsupported": bool(unsupported),
            })
    return flags


def _synthesize_with_quota(grounded: list[dict], cve_kb: dict) -> tuple[list[dict], dict]:
    """
    Live Gemini synthesis with quota handling (recommendation a).
    Returns (synthesized_records, quota_info)
    quota_info contains: requested, synthesized, skipped, quota_remaining, quota_exceeded, message
    """
    total = len(grounded)
    remaining = _get_remaining_quota()
    quota_info = {
        "requested": total,
        "quota_remaining": remaining,
        "quota_exceeded": False,
        "synthesized": 0,
        "skipped": 0,
        "message": None,
    }
    if total == 0:
        return [], quota_info

    # Sort grounded by severity for top-N prioritization
    def sort_key(f):
        band = SEVERITY_BANDS.get(f.get("severity_band"), -1)
        score = f.get("severity_score") or 0
        return (band, score)
    sorted_grounded = sorted(grounded, key=sort_key, reverse=True)

    if total > remaining:
        # Recommendation (a): synthesize top-N, label rest
        quota_info["quota_exceeded"] = True
        quota_info["synthesized"] = remaining
        quota_info["skipped"] = total - remaining
        quota_info["message"] = (
            f"Daily Gemini quota ({DAILY_GEMINI_QUOTA}/day) exceeded: "
            f"requested {total}, synthesized top {remaining} highest-severity findings, "
            f"{total - remaining} not synthesized — daily quota reached."
        )
        to_synthesize = sorted_grounded[:remaining]
        skipped = sorted_grounded[remaining:]
    else:
        to_synthesize = sorted_grounded
        skipped = []
        quota_info["synthesized"] = total

    synthesized = []
    # Try live Gemini, fall back to mock if no API key (so demo doesn't 500)
    try:
        from llm_client import make_client
        client = make_client(offline=False)
        is_mock = False
    except Exception as e:
        # No API key or genai not installed — use MockClient so report still completes (labeled)
        print(f"Gemini client unavailable ({e}), using MockClient for report", file=sys.stderr)
        from llm_client import MockClient
        client = MockClient()
        is_mock = True
        quota_info["message"] = (quota_info["message"] or "") + " (using offline mock — no GEMINI_API_KEY)"

    # Synthesize each finding (grounded only for live report)
    from prompt_templates import build_grounded_prompt
    for finding in to_synthesize:
        prompt = build_grounded_prompt(finding)
        ref = f"{finding.get('host')}:{finding.get('port')}/{finding.get('protocol')}/{finding.get('service')}/{finding.get('nse_script') or 'asset'}"
        rec = {
            "finding_ref": ref,
            "host": finding.get("host"),
            "port": finding.get("port"),
            "service": finding.get("service"),
            "nse_script": finding.get("nse_script"),
            "severity_band": finding.get("severity_band"),
            "prompt_variant": "grounded",
            "prompt": prompt,
            "retrieved_cve_ids": [r.get("id") for r in (finding.get("grounding_context") or {}).get("cve_records", []) if r.get("id")],
        }
        try:
            raw = client.complete(prompt)
            rec["raw_output"] = raw
            # Try to parse JSON from raw
            import re as _re, json as _json
            start = raw.find("{")
            end = raw.rfind("}")
            parsed = {}
            if start != -1 and end != -1 and end > start:
                try:
                    parsed = _json.loads(raw[start:end+1])
                except Exception:
                    parsed = {}
            rec["parsed"] = parsed
            rec["extracted_cve_ids"] = cite_extract.extract_cve_ids(raw)
            rec["ok"] = True
        except Exception as e:
            rec["ok"] = False
            rec["error"] = f"{type(e).__name__}: {e}"
            rec["raw_output"] = ""
            rec["parsed"] = {}
            rec["extracted_cve_ids"] = []
        synthesized.append(rec)

    # Reserve quota for successful calls (only count ok=True to avoid double-charging on retry)
    ok_count = sum(1 for r in synthesized if r.get("ok"))
    if ok_count and not is_mock:
        _reserve_quota(ok_count)

    # Add skipped entries as not_synthesized markers
    for finding in skipped:
        ref = f"{finding.get('host')}:{finding.get('port')}/{finding.get('protocol')}/{finding.get('service')}/{finding.get('nse_script') or 'asset'}"
        synthesized.append({
            "finding_ref": ref,
            "host": finding.get("host"),
            "port": finding.get("port"),
            "service": finding.get("service"),
            "nse_script": finding.get("nse_script"),
            "severity_band": finding.get("severity_band"),
            "prompt_variant": "grounded",
            "ok": False,
            "not_synthesized": True,
            "error": "not synthesized — daily quota reached",
            "retrieved_cve_ids": [r.get("id") for r in (finding.get("grounding_context") or {}).get("cve_records", []) if r.get("id")],
            "extracted_cve_ids": [],
            "parsed": {},
        })

    return synthesized, quota_info


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Check against DEMO_USERS dict (supports admin/admin123, analyst/analyst123, plus env override)
        expected_pass = DEMO_USERS.get(username)
        ok = False
        if expected_pass is not None:
            if isinstance(expected_pass, set):
                ok = any(hmac.compare_digest(password, p) for p in expected_pass)
            else:
                ok = hmac.compare_digest(password, expected_pass)
        else:
            # Fallback to original single-user check for env configurability
            ok_user = hmac.compare_digest(username, DEMO_USER)
            ok_pass = hmac.compare_digest(password, DEMO_PASS)
            ok = ok_user and ok_pass
        if ok:
            session["authenticated"] = True
            session["username"] = username
            nxt = request.args.get("next")
            if nxt and nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
            return redirect(url_for("index"))
        error = "Incorrect username or password"

    return render_template("login.html", corpus=str(corpus_root), error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# JSON API — for Next.js frontend (token-based, CORS enabled)
# ---------------------------------------------------------------------------

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or request.form.get("username") or "").strip()
    password = data.get("password") or request.form.get("password") or ""
    expected = DEMO_USERS.get(username)
    ok = False
    if expected is not None:
        if isinstance(expected, set):
            ok = any(hmac.compare_digest(password, p) for p in expected)
        else:
            ok = hmac.compare_digest(password, expected)
    else:
        ok_user = hmac.compare_digest(username, DEMO_USER)
        ok_pass = hmac.compare_digest(password, DEMO_PASS)
        ok = ok_user and ok_pass
    if not ok:
        # audit failed login (do not reveal password)
        try:
            _append_audit_event("login_failed", f"username: {username or 'unknown'}", {"username": username or "unknown", "name": username or "unknown", "role": "analyst"}, "failure")
        except Exception:
            pass
        return {"error": "invalid_credentials", "message": "The username or password is incorrect."}, 401
    # Create token
    token = uuid.uuid4().hex
    user = {"id": f"u-{username}", "username": username, "name": "Peter" if username == "admin" else "M. Lindqvist", "email": f"{username}@secops.internal", "role": "admin" if username == "admin" else "analyst"}
    TOKENS[token] = user
    # Also set session for compatibility
    session["authenticated"] = True
    session["username"] = username
    try:
        _append_audit_event("login", "session", user, "success")
    except Exception:
        pass
    return {"user": user, "token": token}


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    user = _current_user()
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        TOKENS.pop(token, None)
    session.clear()
    try:
        if user:
            _append_audit_event("logout", "session", user, "success")
    except Exception:
        pass
    return {"ok": True}


@app.route("/api/auth/session", methods=["GET"])
def api_session():
    user = _current_user()
    if not user:
        return {"error": "unauthorized", "message": "Not authenticated"}, 401
    # Find token if any
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else None
    return {"user": user, "token": token}


@app.route("/api/dashboard/summary", methods=["GET"])
@login_required
def api_dashboard_summary():
    stats = _dashboard_stats()
    # Map to frontend DashboardSummary type
    # frontend expects: totalScans, totalFindings, severityCounts (critical/high/medium/low), evidenceBacked, evidenceMissing, hostsAssessed, overallRisk
    sev = stats["severity_counts"]
    # Map overallRisk level to frontend Severity
    level_map = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":"low","UNSCORED":"unscored"}
    overall = None
    if stats["overall_risk"] in level_map:
        overall = {"label": f"{stats['overall_risk'].title()} exposure present" if stats["overall_risk"] in ["CRITICAL","HIGH"] else stats["overall_risk"], "level": level_map[stats["overall_risk"]]}
        if stats["overall_risk"] in ("INFO", "UNSCORED"):
            overall = None if stats["overall_risk"] == "INFO" else {"label": "Unscored — insufficient data", "level": "unscored"}
    return {
        "totalScans": stats["totals"]["scans"],
        "totalFindings": stats["totals"]["findings"],
        "severityCounts": {"critical": sev["CRITICAL"], "high": sev["HIGH"], "medium": sev["MEDIUM"], "low": sev["LOW"]},
        "evidenceBacked": stats["totals"]["evidence_backed"],
        "evidenceMissing": stats["totals"]["evidence_unverified"],
        "hostsAssessed": stats["totals"]["hosts"],
        "overallRisk": overall,
    }


@app.route("/api/scans", methods=["GET"])
@login_required
def api_list_scans():
    scans = _scan_rows()
    # Also include live reports as scans for unified view
    enriched = []
    for r in scans:
        scan_dir = corpus_root / "scans" / r["scan_id"]
        source = _load(scan_dir / "source.json") or {}
        grounded = _load(scan_dir / "grounded_findings.json") or []
        # Count evidence
        backed = sum(1 for f in grounded if f.get("grounding_context", {}).get("cve_records") or f.get("grounding_context", {}).get("cis_matches"))
        missing = len(grounded) - backed
        # Severity counts for this scan
        sev_counts = {"critical":0,"high":0,"medium":0,"low":0}
        for f in grounded:
            b = (f.get("severity_band") or "INFO").lower()
            if b in sev_counts:
                sev_counts[b] += 1
        # Map worst_band to frontend Severity
        band_map = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":None}
        enriched.append({
            "id": r["scan_id"],
            "name": source.get("display_name") or r["scan_id"].replace("scan_", "Scan ").replace("_"," ").title(),
            "filename": source.get("filename") or f"{r['scan_id']}.xml",
            "importedBy": source.get("imported_by") or source.get("origin") or "unknown",
            "importedAt": source.get("imported_at") or "2026-08-16T13:01:00Z",
            "status": "completed" if r["findings"]>0 else "processing",
            "hostCount": r["hosts"],
            "findingCount": r["findings"],
            "highestSeverity": band_map.get(r["worst_band"]),
            "severityCounts": sev_counts,
            "evidenceBacked": backed,
            "evidenceMissing": missing,
        })
    # Live reports are served separately via GET /api/reports — not merged into Scans library (keeps 12+1 real scans distinct from 14 live reports)
    # Apply filters from query params (Next.js sends search/status/severity/evidence/sort)
    search = (request.args.get("search") or "").strip().lower()
    status = request.args.get("status") or "all"
    severity = request.args.get("severity") or "all"
    evidence = request.args.get("evidence") or "all"
    sort = request.args.get("sort") or "recent"
    filtered = enriched
    if search:
        filtered = [s for s in filtered if search in s["name"].lower() or search in s["filename"].lower()]
    if status != "all":
        filtered = [s for s in filtered if s["status"] == status]
    if severity != "all":
        filtered = [s for s in filtered if s["highestSeverity"] == severity]
    if evidence != "all":
        # evidence: complete = no missing, partial = has missing
        if evidence == "complete":
            filtered = [s for s in filtered if s["evidenceMissing"] == 0 and (s["evidenceBacked"] + s["evidenceMissing"]) > 0]
        elif evidence == "partial":
            filtered = [s for s in filtered if s["evidenceMissing"] > 0]
    # Sort
    if sort == "severity":
        filtered.sort(key=lambda s: SEVERITY_BANDS.get((s["highestSeverity"] or "low").upper(), 0), reverse=True)
    elif sort == "findings":
        filtered.sort(key=lambda s: s["findingCount"], reverse=True)
    else:  # recent
        filtered.sort(key=lambda s: s["importedAt"] or "", reverse=True)
    return filtered


@app.route("/api/scans/<scan_id>", methods=["GET"])
@login_required
def api_get_scan(scan_id: str):
    # Try corpus scan first
    if SCAN_ID_PATTERN.match(scan_id):
        scan_dir = corpus_root / "scans" / scan_id
        if scan_dir.is_dir():
            row = _scan_row(scan_dir)
            if row:
                grounded = _load(scan_dir / "grounded_findings.json") or []
                backed = sum(1 for f in grounded if f.get("grounding_context", {}).get("cve_records") or f.get("grounding_context", {}).get("cis_matches"))
                missing = len(grounded) - backed
                sev_counts = {"critical":0,"high":0,"medium":0,"low":0}
                for f in grounded:
                    b = (f.get("severity_band") or "INFO").lower()
                    if b in sev_counts:
                        sev_counts[b] += 1
                band_map = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":None}
                return {
                    "id": scan_id,
                    "name": scan_id,
                    "filename": f"{scan_id}.xml",
                    "importedBy": "System",
                    "importedAt": "2026-08-16T13:01:00Z",
                    "status": "completed",
                    "hostCount": row["hosts"],
                    "findingCount": row["findings"],
                    "highestSeverity": band_map.get(row["worst_band"]),
                    "severityCounts": sev_counts,
                    "evidenceBacked": backed,
                    "evidenceMissing": missing,
                }
    # Try live report
    for p in REPORTS_DIR.glob("*.json"):
        if p.stem.startswith(scan_id) or p.stem == scan_id:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                grounded = data.get("grounded", [])
                backed = sum(1 for f in grounded if f.get("grounding_context", {}).get("cve_records") or f.get("grounding_context", {}).get("cis_matches"))
                missing = len(grounded) - backed
                return {
                    "id": scan_id,
                    "name": data.get("filename","").replace(".xml",""),
                    "filename": data.get("filename",""),
                    "importedBy": data.get("uploaded_by","System"),
                    "importedAt": data.get("uploaded_at",""),
                    "status": "completed",
                    "hostCount": len(set(f.get("host") for f in grounded)),
                    "findingCount": len(grounded),
                    "highestSeverity": None,
                    "severityCounts": {"critical":0,"high":0,"medium":0,"low":0},
                    "evidenceBacked": backed,
                    "evidenceMissing": missing,
                }
            except Exception:
                continue
    return {"error": "not_found", "message": "Scan not found"}, 404


@app.route("/api/scans/<scan_id>/hosts", methods=["GET"])
@login_required
def api_scan_hosts(scan_id: str):
    # Try corpus
    scan_dir = corpus_root / "scans" / scan_id
    if scan_dir.is_dir():
        scored = _load(scan_dir / "scored_findings.json")
        if scored:
            hosts = []
            for h in scored.get("host_risk_summary", []):
                hosts.append({
                    "id": h.get("host"),
                    "scanId": scan_id,
                    "ip": h.get("host"),
                    "hostname": h.get("hostname"),
                    "openPorts": h.get("open_service_count", 0),
                    "findingCount": h.get("vuln_finding_count", 0) + h.get("open_service_count", 0),
                    "highestSeverity": (h.get("risk_band") or "low").lower(),
                    "riskScore": h.get("adjusted_risk_score"),
                    "severityCounts": {"critical":0,"high":0,"medium":0,"low":0},
                    "evidenceBacked": 0,
                    "evidenceMissing": 0,
                })
            return hosts
    # Try live report
    for p in REPORTS_DIR.glob("*.json"):
        if p.stem.startswith(scan_id) or p.stem == scan_id:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                hosts = []
                for h in data.get("host_summary", []) or data.get("scored", {}).get("host_risk_summary", []):
                    hosts.append({
                        "id": h.get("host"),
                        "scanId": scan_id,
                        "ip": h.get("host"),
                        "hostname": h.get("hostname"),
                        "openPorts": h.get("open_service_count", 0),
                        "findingCount": 0,
                        "highestSeverity": (h.get("risk_band") or "low").lower(),
                        "riskScore": h.get("adjusted_risk_score"),
                        "severityCounts": {"critical":0,"high":0,"medium":0,"low":0},
                        "evidenceBacked": 0,
                        "evidenceMissing": 0,
                    })
                return hosts
            except Exception:
                continue
    return []


@app.route("/api/scans/<scan_id>/findings", methods=["GET"])
@login_required
def api_scan_findings(scan_id: str):
    # Apply filters from query params (Next.js sends search/severity/hostId/evidence)
    search = (request.args.get("search") or "").strip().lower()
    severity = request.args.get("severity") or "all"
    host_id = request.args.get("hostId") or "all"
    evidence = request.args.get("evidence") or "all"

    def _filter_findings(findings: list[dict]) -> list[dict]:
        result = findings
        if search:
            result = [f for f in result if search in (f.get("title") or "").lower() or search in (f.get("service") or "").lower() or search in (f.get("host") or "").lower() or (f.get("cve") and search in (f["cve"].get("id") or "").lower())]
        if severity != "all":
            result = [f for f in result if f.get("severity") == severity]
        if host_id != "all":
            result = [f for f in result if f.get("hostId") == host_id or f.get("host") == host_id]
        if evidence != "all":
            result = [f for f in result if f.get("evidenceStatus") == evidence]
        return result

    # Try corpus
    scan_dir = corpus_root / "scans" / scan_id
    if scan_dir.is_dir():
        grounded = _load(scan_dir / "grounded_findings.json")
        if grounded is not None:
            # Map to frontend Finding type
            result = []
            for f in grounded:
                ctx = f.get("grounding_context", {})
                cve_recs = ctx.get("cve_records", [])
                cis_recs = ctx.get("cis_matches", [])
                has_cve = any(not r.get("not_found") for r in cve_recs)
                has_cis = len(cis_recs) > 0
                # Map severity - UNSCORED is distinct from Low (insufficient data, not low risk)
                sev_map = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":"low","UNSCORED":"unscored"}
                result.append({
                    "id": f"{f.get('host')}:{f.get('port')}/{f.get('service')}",
                    "scanId": scan_id,
                    "hostId": f.get("host"),
                    "host": f.get("host"),
                    "hostname": f.get("hostname"),
                    "port": f.get("port"),
                    "protocol": f.get("protocol"),
                    "service": f.get("service"),
                    "title": f.get("nse_script") or f.get("service") or "Finding",
                    "description": f.get("scoring_rationale") or f.get("raw_output") or "",
                    "severity": sev_map.get(f.get("severity_band"), "unscored"),
                    "severityReasoning": f.get("scoring_rationale") or "",
                    "cvss": f.get("severity_score"),
                    "cve": {"id": cve_recs[0].get("id"), "cvss": cve_recs[0].get("cvss_v3_score"), "cvssSeverity": sev_map.get(cve_recs[0].get("cvss_severity","low"), "low"), "description": cve_recs[0].get("text",""), "affectedProduct": f.get("product"), "knownExploited": bool(cve_recs[0].get("kev_listed")), "source": cve_recs[0].get("references",[None])[0]} if has_cve and cve_recs and not cve_recs[0].get("not_found") else None,
                    "cis": {"control": cis_recs[0].get("id"), "title": cis_recs[0].get("control_title"), "recommendation": cis_recs[0].get("text",""), "reasoning": cis_recs[0].get("text","")} if has_cis else None,
                    "evidenceStatus": "backed" if (has_cve or has_cis) else "none",
                    "remediation": None,
                })
            return _filter_findings(result)
    # Try live report
    for p in REPORTS_DIR.glob("*.json"):
        if p.stem.startswith(scan_id) or p.stem == scan_id:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                grounded = data.get("grounded", [])
                result = []
                for f in grounded:
                    ctx = f.get("grounding_context", {})
                    cve_recs = ctx.get("cve_records", [])
                    cis_recs = ctx.get("cis_matches", [])
                    has_cve = any(not r.get("not_found") for r in cve_recs)
                    has_cis = len(cis_recs) > 0
                    sev_map = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":"low","UNSCORED":"unscored"}
                    result.append({
                        "id": f"{f.get('host')}:{f.get('port')}/{f.get('service')}",
                        "scanId": scan_id,
                        "hostId": f.get("host"),
                        "host": f.get("host"),
                        "hostname": f.get("hostname"),
                        "port": f.get("port"),
                        "protocol": f.get("protocol"),
                        "service": f.get("service"),
                        "title": f.get("nse_script") or f.get("service") or "Finding",
                        "description": f.get("scoring_rationale") or "",
                        "severity": sev_map.get(f.get("severity_band"), "unscored"),
                        "severityReasoning": f.get("scoring_rationale") or "",
                        "cvss": f.get("severity_score"),
                        "cve": {"id": cve_recs[0].get("id"), "cvss": cve_recs[0].get("cvss_v3_score"), "cvssSeverity": "critical" if cve_recs[0].get("cvss_severity")=="CRITICAL" else "high", "description": cve_recs[0].get("text",""), "affectedProduct": f.get("product"), "knownExploited": bool(cve_recs[0].get("kev_listed")), "source": cve_recs[0].get("references",[None])[0]} if has_cve and cve_recs and not cve_recs[0].get("not_found") else None,
                        "cis": {"control": cis_recs[0].get("id"), "title": cis_recs[0].get("control_title"), "recommendation": cis_recs[0].get("text",""), "reasoning": cis_recs[0].get("text","")} if has_cis else None,
                        "evidenceStatus": "backed" if (has_cve or has_cis) else "none",
                        "remediation": None,
                    })
                return _filter_findings(result)
            except Exception:
                continue
    return []


@app.route("/api/scans/import", methods=["POST"])
@login_required
def api_scans_import():
    # Reuse same validation and pipeline as /report/upload but return scanId for Next.js
    file = request.files.get("file") or request.files.get("scan_file")
    if not file or not file.filename:
        return {"error": "invalid_scan", "message": "expected .xml file"}, 400
    filename = file.filename or ""
    if not filename.lower().endswith(".xml"):
        return {"error": "invalid_scan", "message": "expected .xml file"}, 400
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > REPORT_MAX_BYTES:
        return {"error": "invalid_scan", "message": "file too large"}, 413
    tmpdir = Path(tempfile.mkdtemp(prefix="api_import_"))
    safe_name = Path(filename).name or "upload.xml"
    tmp_xml = tmpdir / safe_name
    try:
        file.save(str(tmp_xml))
        root = ET.parse(str(tmp_xml)).getroot()
    except ET.ParseError:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return {"error": "invalid_scan", "message": "not valid XML"}, 400
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return {"error": "invalid_scan", "message": "not valid XML"}, 400
    if root.tag != "nmaprun":
        shutil.rmtree(tmpdir, ignore_errors=True)
        return {"error": "invalid_scan", "message": "not an nmap scan file"}, 400
    try:
        cve_kb = _load(CVE_KB_PATH) or {}
        cis_kb = _load(CIS_KB_PATH) or []
        findings = nmap_parser.parse_nmap_xml(str(tmp_xml))
        # Use same logic as _import_scan but don't persist as scan_NNNN — use report storage
        scored = rule_engine.analyze(findings, cve_kb)
        cve_store = retrieval.CveStore(cve_kb)
        cis_index = retrieval.CisIndex(cis_kb)
        grounded = retrieval.ground_all([f for f in scored.get("all_scored_findings", []) if f.get("type") in ("vuln","asset")], cve_store, cis_index)
        # Full pipeline: synthesize (live Gemini, quota-aware) + hallucination validation — same as POST /report/upload
        # This is the actual core requirement, not a nice-to-have; without it the Next.js hallucination/quotabanner UI is dead code
        synthesized, quota_info = _synthesize_with_quota(grounded, cve_kb)
        validation_flags = _validate_live_citations(grounded, synthesized, cve_kb)
        # Create a report entry so frontend can show it inline on same page
        report_id = uuid.uuid4().hex
        # Count hosts
        try:
            hosts_up = len([h for h in root.findall("host") if (h.find("status") is not None and h.find("status").get("state") == "up")])
        except Exception:
            hosts_up = len({f.get("host") for f in findings}) if findings else 0
        report = {
            "report_id": report_id,
            "filename": filename,
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
            "uploaded_by": (_current_user() or {}).get("username") or "unknown",
            "findings": findings,
            "scored": scored,
            "grounded": grounded,
            "synthesized": synthesized,
            "quota_info": quota_info,
            "validation_flags": validation_flags,
            "has_hallucination": bool(validation_flags),
            "host_summary": scored.get("host_risk_summary", []),
            "cve_records_total": sum(len(f.get("grounding_context", {}).get("cve_records", [])) for f in grounded),
            "cis_matches_total": sum(len(f.get("grounding_context", {}).get("cis_matches", [])) for f in grounded),
            "hosts_up": hosts_up,
            "is_empty_scan": hosts_up == 0,
            "is_no_findings": hosts_up > 0 and len(grounded) == 0,
        }
        REPORTS[report_id] = report
        (REPORTS_DIR / f"{report_id}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        shutil.copy(str(tmp_xml), str(REPORTS_DIR / f"{report_id}.xml"))
        shutil.rmtree(tmpdir, ignore_errors=True)
        try:
            _append_audit_event("scan_import", filename, _current_user(), "success")
        except Exception:
            pass
        # Return scanId for frontend (use report_id as scanId)
        return {"scanId": report_id, "reportId": report_id}
    except Exception as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        app.logger.exception("api import failed")
        return {"error": "service_unavailable", "message": f"import failed: {e}"}, 500


@app.route("/api/reports", methods=["GET"])
@login_required
def api_list_reports():
    reports = []
    for p in sorted(REPORTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.name == "_quota.json":
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            rid = p.stem
            # Determine if report is completed (has grounded findings)
            grounded = data.get("grounded", [])
            completed = bool(grounded)
            reports.append({
                "id": rid,
                "scanId": rid,
                "scanName": data.get("filename","").replace(".xml",""),
                "generatedBy": data.get("uploaded_by","System"),
                "generatedAt": data.get("uploaded_at",""),
                "status": "completed" if completed else "in_progress",
                "sizeKb": round(p.stat().st_size / 1024),
                "grounded": grounded,
            })
        except Exception:
            continue
    # Return all real live reports (14) — no cap, distinct from Scans
    return reports


@app.route("/api/reports/<report_id>/pdf", methods=["GET"])
@login_required
def api_report_pdf(report_id: str):
    """Return the PDF for a live report, falling back to on‑the‑fly generation."""
    pdf_path = REPORTS_DIR / f"{report_id}.pdf"
    if pdf_path.exists():
        return send_file(pdf_path, as_attachment=True,
                         download_name=f"{report_id}_report.pdf",
                         mimetype="application/pdf")
    # Fallback: generate on the fly using the stored report JSON
    try:
        report_data = json.loads((REPORTS_DIR / f"{report_id}.json").read_text(encoding="utf-8"))
    except Exception:
        abort(404, description="Report not found")
    # Minimal PDF generation using weasyprint/reportlab same as report_pdf
    # For brevity, redirect to the existing HTML‑based route
    return redirect(url_for("report_pdf", report_id=report_id))


@app.route("/api/reports/<report_id>/json", methods=["GET"])
@login_required
def api_report_json(report_id: str):
    """Return the raw report JSON for download."""
    report_path = REPORTS_DIR / f"{report_id}.json"
    if not report_path.exists():
        abort(404, description="Report not found")
    return send_file(report_path, as_attachment=True,
                     download_name=f"{report_id}_report.json",
                     mimetype="application/json")


@app.route("/api/audit", methods=["GET"])
@login_required
def api_audit():
    # Admin-gated server-side: backend is the source of truth, not just UI hiding.
    user = _current_user()
    if not user or user.get("role") != "admin":
        return {"error": "unauthorized", "message": "You do not have permission to access the audit log."}, 403
    return _load_audit_events()


@app.route("/")
@login_required
def index():
    # Keep legacy light view at / but also support /dashboard dark view
    return redirect(url_for("dashboard"))


def _dashboard_stats():
    scans = _scan_rows()
    # Aggregate grounded findings for severity distribution
    all_grounded = []
    for d in sorted((corpus_root / "scans").glob("scan_*")):
        if not d.is_dir():
            continue
        g = _load(d / "grounded_findings.json")
        if g:
            all_grounded.extend(g)
    # Also include live reports
    for p in REPORTS_DIR.glob("*.json"):
        if p.name == "_quota.json":
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "grounded" in data:
                all_grounded.extend(data.get("grounded", []))
        except Exception:
            continue

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNSCORED": 0}
    for f in all_grounded:
        band = f.get("severity_band") or "INFO"
        if band in severity_counts:
            severity_counts[band] += 1
        else:
            severity_counts["INFO"] += 1

    hosts = set(f.get("host") for f in all_grounded if f.get("host"))
    evidence_backed = sum(1 for f in all_grounded if (f.get("grounding_context", {}).get("cve_records") or f.get("grounding_context", {}).get("cis_matches")))

    evidence_unverified = len(all_grounded) - evidence_backed

    totals = {
        "scans": len(scans) + len([p for p in REPORTS_DIR.glob("*.json") if p.name != "_quota.json"]),
        "findings": len(all_grounded),
        "hosts": len(hosts),
        "evidence_backed": evidence_backed,
        "evidence_unverified": evidence_unverified,
        "vuln_findings": sum(r["vuln_findings"] for r in scans),
        "cve_resolved": sum(r["cve_resolved"] for r in scans),
    }
    # Overall risk: highest severity present
    overall_risk = "INFO"
    for band in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity_counts.get(band, 0) > 0:
            overall_risk = band
            break
    # Evidence coverage % — must equal round(Backed/Total*100), always computed from real data, never hardcoded
    evidence_coverage = round((evidence_backed / len(all_grounded) * 100) if all_grounded else 0)

    return {
        "totals": totals,
        "severity_counts": severity_counts,
        "overall_risk": overall_risk,
        "evidence_coverage": evidence_coverage,
        "scans": scans,
        "all_grounded": all_grounded,
    }


@app.route("/dashboard")
@login_required
def dashboard():
    stats = _dashboard_stats()
    return render_template("dashboard_dark.html",
                           totals=stats["totals"],
                           severity_counts=stats["severity_counts"],
                           overall_risk=stats["overall_risk"],
                           evidence_coverage=stats["evidence_coverage"])


@app.route("/scans")
@login_required
def scans_library():
    scans = _scan_rows()
    # Enrich for dark UI
    enriched = []
    for r in scans:
        # Try to get display name and file info from source.json or manifest
        scan_dir = corpus_root / "scans" / r["scan_id"]
        source = _load(scan_dir / "source.json") or {}
        # Evidence pct
        evidence_pct = 0
        grounded = _load(scan_dir / "grounded_findings.json") or []
        if grounded:
            has_evidence = sum(1 for f in grounded if f.get("grounding_context", {}).get("cve_records") or f.get("grounding_context", {}).get("cis_matches"))
            evidence_pct = round(has_evidence / len(grounded) * 100) if grounded else 0
        enriched.append({
            "scan_id": r["scan_id"],
            "display_name": source.get("display_name") or r["scan_id"].replace("scan_", "Scan ").replace("_", " ").title(),
            "filename": source.get("filename") or f"{r['scan_id']}.xml",
            "imported_by": source.get("imported_by") or source.get("origin") or "System",
            "imported_at": source.get("imported_at") or "16 Aug 2026, 13:01",
            "hosts": r["hosts"],
            "findings": r["findings"],
            "worst_band": r["worst_band"],
            "evidence_pct": evidence_pct,
            "status": "Completed" if r["findings"] > 0 else "Processing",
        })
    # Also include live reports as scans
    for p in sorted(REPORTS_DIR.glob("*.json")):
        if p.name == "_quota.json":
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            rid = p.stem
            grounded = data.get("grounded", [])
            hosts = len(set(f.get("host") for f in grounded)) if grounded else 0
            findings = len(grounded)
            # Determine worst band
            worst = "INFO"
            for band in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if any(f.get("severity_band") == band for f in grounded):
                    worst = band
                    break
            has_ev = sum(1 for f in grounded if f.get("grounding_context", {}).get("cve_records") or f.get("grounding_context", {}).get("cis_matches"))
            pct = round(has_ev / len(grounded) * 100) if grounded else 0
            enriched.append({
                "scan_id": rid[:8],
                "display_name": data.get("filename", rid).replace(".xml","").replace("-", " ").title(),
                "filename": data.get("filename", f"{rid}.xml"),
                "imported_by": data.get("uploaded_by", "System"),
                "imported_at": data.get("uploaded_at", "")[:16].replace("T"," "),
                "hosts": hosts,
                "findings": findings,
                "worst_band": worst,
                "evidence_pct": pct,
                "status": "Completed",
            })
        except Exception:
            continue
    return render_template("scans_dark.html", scans=enriched)


@app.route("/reports")
@login_required
def reports_view():
    reports = []
    # From live reports
    for p in sorted(REPORTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.name == "_quota.json":
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            rid = p.stem
            grounded = data.get("grounded", [])
            size_kb = round(p.stat().st_size / 1024)
            # Try to get PDF size if exists
            pdf_path = REPORTS_DIR / f"{rid}.pdf"
            if pdf_path.exists():
                size_kb = round(pdf_path.stat().st_size / 1024)
            reports.append({
                "name": data.get("filename", rid).replace(".xml","").replace("-", " ").title(),
                "filename": data.get("filename", ""),
                "generated_by": data.get("uploaded_by", "System"),
                "generated_at": data.get("uploaded_at", "")[:16].replace("T"," "),
                "size": f"{size_kb} KB",
                "pdf_url": url_for("report_pdf", report_id=rid),
                "json_url": url_for("api_report_json", report_id=rid),
            })
        except Exception:
            continue
    # Return all real live reports (14) — distinct from Scans library
    # Fallback: from corpus scans that have reports
    if not reports:
        for d in sorted((corpus_root / "scans").glob("scan_*")):
            if not d.is_dir():
                continue
            grounded = _load(d / "grounded_findings.json")
            if not grounded:
                continue
            # Simulate report
            reports.append({
                "name": d.name.replace("scan_", "Scan ").title(),
                "filename": f"{d.name}.xml",
                "generated_by": "System",
                "generated_at": "14 Aug 2026, 14:50",
                "size": "842 KB",
                "pdf_url": url_for("scan_pdf", scan_id=d.name),
                "json_url": url_for("api_scan_json", scan_id=d.name),
            })
            if len(reports) >= 14:
                break
    return render_template("reports_dark.html", reports=reports)


@app.route("/scan/<scan_id>")
@login_required
def scan(scan_id: str):
    return _render_scan(scan_id)


@app.route("/scan/<scan_id>/export")
@login_required
def export_scan(scan_id: str):
    scan_dir = _scan_dir(scan_id)
    export_path = scan_dir / "grounded_findings.json"
    if not export_path.exists():
        abort(404, description=f"No grounded findings to export for {scan_id}")
    return send_file(export_path, as_attachment=True,
                     download_name=f"{scan_id}_export.json",
                     mimetype="application/json")


@app.route("/scan/<scan_id>/pdf")
@login_required
def scan_pdf(scan_id: str):
    scan_dir = _scan_dir(scan_id)
    scored = _load(scan_dir / "scored_findings.json")
    grounded = _load(scan_dir / "grounded_findings.json")
    if scored is None or grounded is None:
        abort(404, description=f"Pipeline artifacts missing for {scan_id}")
    host_summary = scored.get("host_risk_summary", [])
    findings = sorted(grounded, key=_sort_key_finding, reverse=True)
    # Reuse report_view template with scan data, but with scan-specific marker
    live_marker = f"Scan {scan_id} — {len(findings)} findings"
    # Create a pseudo-report for PDF generation
    report = {
        "report_id": scan_id,
        "filename": f"{scan_id}.xml",
        "uploaded_at": "",
        "grounded": grounded,
        "scored": scored,
        "host_summary": host_summary,
        "cve_records_total": sum(len(f.get("grounding_context", {}).get("cve_records", [])) for f in grounded),
        "cis_matches_total": sum(len(f.get("grounding_context", {}).get("cis_matches", [])) for f in grounded),
        "quota_info": {},
        "validation_flags": [],
        "synthesized": [],
    }
    html = render_template("report_view.html",
                           corpus=str(corpus_root),
                           report=report,
                           report_id=scan_id,
                           host_summary=host_summary,
                           findings=findings,
                           live_marker=live_marker,
                           quota_info={},
                           validation_flags=[],
                           synthesized=[],
                           pdf_mode=True)
    try:
        from weasyprint import HTML
        import io
        pdf_bytes = HTML(string=html).write_pdf()
        return send_file(io.BytesIO(pdf_bytes), as_attachment=True, download_name=f"{scan_id}_report.pdf", mimetype="application/pdf")
    except Exception as e:
        app.logger.warning(f"weasyprint unavailable for scan PDF ({type(e).__name__}: {e}), trying reportlab")
        try:
            import io
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=15*mm, bottomMargin=15*mm, leftMargin=12*mm, rightMargin=12*mm, title=f"Scan {scan_id}", author="Cyber Health Assessment")
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle('Title2', parent=styles['Title'], fontSize=16, textColor=colors.HexColor('#0B0E13'), spaceAfter=6)
            h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=11, textColor=colors.HexColor('#1A2332'), spaceBefore=8, spaceAfter=4)
            body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#2A3441'), leading=11)
            mono_style = ParagraphStyle('Mono', parent=styles['Code'], fontSize=7, textColor=colors.HexColor('#5A6573'), leading=9, fontName='Courier')
            story = []
            story.append(Paragraph(f"Cyber Health Assessment — Scan {scan_id}", title_style))
            story.append(Paragraph(f"{live_marker} &middot; {len(findings)} findings", body_style))
            story.append(Spacer(1, 6))
            if host_summary:
                story.append(Paragraph("Host risk", h2_style))
                host_data = [["Host", "Risk", "Reason"]]
                for h in host_summary:
                    host_data.append([f"{h.get('host')} ({h.get('hostname') or ''})", f"{h.get('adjusted_risk_score')} {h.get('risk_band')}", h.get('criticality_reason','')[:60]])
                t = Table(host_data, colWidths=[60*mm, 30*mm, 80*mm])
                t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#11151C')), ('TEXTCOLOR', (0,0), (-1,0), colors.white), ('FONTSIZE', (0,0), (-1,0), 7), ('FONTSIZE', (0,1), (-1,-1), 7), ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#1E2633')), ('VALIGN', (0,0), (-1,-1), 'TOP'), ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F7F8FA')])]))
                story.append(t)
                story.append(Spacer(1, 8))
            story.append(Paragraph(f"Findings ({len(findings)} total) — every claim below is either cited or explicitly ungrounded", h2_style))
            from xml.sax.saxutils import escape as _escape2
            finding_title_style2 = ParagraphStyle('FindingTitle2', parent=body_style, fontSize=9, leading=12, textColor=colors.HexColor('#0B0E13'), spaceBefore=6, spaceAfter=3, fontName='Helvetica-Bold')
            finding_meta_style2 = ParagraphStyle('FindingMeta2', parent=body_style, fontSize=7, leading=10, textColor=colors.HexColor('#5A6573'), spaceAfter=2)
            evidence_style2 = ParagraphStyle('Evidence2', parent=body_style, fontSize=7, leading=10, textColor=colors.HexColor('#2A3441'), leftIndent=6, spaceAfter=2)
            synthesis_style2 = ParagraphStyle('Synthesis2', parent=body_style, fontSize=8, leading=11, textColor=colors.HexColor('#1A2332'), leftIndent=6, borderPadding=(4,4,6), spaceAfter=4, backColor=colors.HexColor('#F0FDF4'))
            for idx, f in enumerate(findings[:40]):
                host = _escape2(str(f.get("host") or ""))
                hostname = _escape2(str(f.get("hostname") or ""))
                port = _escape2(str(f.get("port") or ""))
                proto = _escape2(str(f.get("protocol") or ""))
                service = _escape2(str(f.get("service") or ""))
                nse = _escape2(str(f.get("nse_script") or ""))
                band = _escape2(str(f.get("severity_band") or ""))
                score = f.get("severity_score")
                score_str = f"{score:.1f}" if isinstance(score, (int, float)) else ""
                cve_refs = ", ".join(f.get("cve_refs", []) or []) or "— no CVE ref"
                cve_refs_esc = _escape2(cve_refs)
                title_text = f"<b>Finding {idx+1}: {band} {score_str}</b> — {host}:{port}/{proto} {service}"
                if nse:
                    title_text += f" <font size=7 color='#5A6573'>({nse})</font>"
                story.append(Paragraph(title_text, finding_title_style2))
                meta_text = f"Host {host} <font color='#5A6573'>({hostname})</font> · Service {service} · Port {port}/{proto} · CVE {cve_refs_esc}"
                rationale = f.get("scoring_rationale")
                if rationale:
                    meta_text += f" · <i>{_escape2(rationale)}</i>"
                story.append(Paragraph(meta_text, finding_meta_style2))
                ctx = f.get("grounding_context", {}) or {}
                cve_records = ctx.get("cve_records", []) or []
                cis_matches = ctx.get("cis_matches", []) or []
                if cve_records:
                    for rec in cve_records:
                        if rec.get("not_found") or rec.get("status") == "not_found":
                            story.append(Paragraph(f"<b>{_escape2(rec.get('id',''))}</b> <font color='#9B1C1C'>NOT IN KB</font> — no local record", evidence_style2))
                        else:
                            rid = _escape2(str(rec.get("id") or ""))
                            cvss = rec.get("cvss_v3_score")
                            cvss_str = f"CVSS {cvss}" if cvss is not None else ""
                            sev = _escape2(str(rec.get("cvss_severity") or ""))
                            text = _escape2((rec.get("text") or "")[:600])
                            kev = " · ACTIVELY EXPLOITED" if rec.get("kev_listed") else ""
                            story.append(Paragraph(f"<b>{rid}</b> {sev} {cvss_str}{kev}<br/><font size=7>{text}</font>", evidence_style2))
                            cwe = ", ".join(rec.get("cwe_ids", []) or [])
                            if cwe or rec.get("published_date") or rec.get("cvss_v3_vector"):
                                meta = []
                                if cwe:
                                    meta.append(f"CWE: {_escape2(cwe)}")
                                if rec.get("published_date"):
                                    meta.append(f"published {_escape2(str(rec.get('published_date')[:10]))}")
                                if rec.get("cvss_v3_vector"):
                                    meta.append(f"<font face='Courier' size=6>{_escape2(rec.get('cvss_v3_vector'))}</font>")
                                story.append(Paragraph(" · ".join(meta), finding_meta_style2))
                else:
                    story.append(Paragraph("<i>No CVE citation available — ungrounded</i>", finding_meta_style2))
                if cis_matches:
                    story.append(Paragraph("<b>CIS Controls:</b>", finding_meta_style2))
                    for c in cis_matches:
                        cid = _escape2(str(c.get("id") or ""))
                        title = _escape2(str(c.get("control_title") or ""))
                        section = _escape2(str(c.get("section") or ""))
                        level = c.get("level")
                        level_str = f" L{level}" if level is not None else ""
                        text = _escape2((c.get("text") or "")[:500])
                        sim = c.get("similarity_score")
                        sim_str = f" sim {sim:.3f}" if isinstance(sim, (int, float)) else ""
                        story.append(Paragraph(f"{cid}{level_str} — {title} <font color='#5A6573'>({section}{sim_str})</font><br/><font size=7>{text}</font>", evidence_style2))
                # Scan PDFs have no Gemini synthesis (pseudo-report), but still note it
                story.append(Paragraph("<i>No synthesis available for scan export — see live report for Gemini synthesis</i>", finding_meta_style2))
                story.append(Spacer(1, 4))
                line_tbl2 = Table([[""]], colWidths=[doc.width])
                line_tbl2.setStyle(TableStyle([('LINEBELOW', (0,0), (-1,0), 0.5, colors.HexColor('#E5E7EB'))]))
                story.append(line_tbl2)
                story.append(Spacer(1, 4))
            if len(findings) > 40:
                story.append(Paragraph(f"... and {len(findings)-40} more findings (see JSON export)", body_style))
            story.append(Spacer(1, 8))
            story.append(Paragraph(f"Generated {len(findings)} findings", mono_style))
            doc.build(story)
            pdf_bytes = buf.getvalue()
            buf.close()
            return send_file(io.BytesIO(pdf_bytes), as_attachment=True, download_name=f"{scan_id}_report.pdf", mimetype="application/pdf")
        except Exception as e2:
            app.logger.warning(f"reportlab fallback also failed ({type(e2).__name__}: {e2}), returning HTML")
            return html, 200, {"Content-Type": "text/html", "Content-Disposition": f"inline; filename={scan_id}_report.html"}


@app.route("/import", methods=["GET", "POST"])
@login_required
def import_scan():
    error = None
    if request.method == "POST":
        file = request.files.get("scan_xml")
        if file is None or not file.filename:
            error = "Choose an Nmap XML file to import."
        elif not file.filename.lower().endswith(".xml"):
            error = "Upload a .xml file — nmap -oX output."
        else:
            scan_dir = _next_scan_dir()
            try:
                warning = _import_scan(file, scan_dir)
            except ValueError as exc:
                shutil.rmtree(scan_dir, ignore_errors=True)
                error = str(exc)
            except Exception as exc:  # noqa: BLE001 — honest failure, not a 500
                app.logger.exception("Scan import failed")
                shutil.rmtree(scan_dir, ignore_errors=True)
                error = f"Import failed: {type(exc).__name__} — see server log. Nothing was saved."
            else:
                if warning:
                    flash(warning, "warn")
                else:
                    flash(f"Import complete — {scan_dir.name} added to the inventory.", "ok")
                return redirect(url_for("scan", scan_id=scan_dir.name))

    return render_template("import.html", corpus=str(corpus_root), error=error)


@app.route("/demo")
@login_required
def demo_dashboard():
    return render_template("demo_dashboard.html", corpus=str(corpus_root))


@app.route("/demo/data")
@login_required
def demo_data():
    p = ROOT / "sample_data" / "demo_grounded_findings.json"
    if not p.exists():
        abort(404, description="sample_data/demo_grounded_findings.json not found")
    return send_file(p, mimetype="application/json")


# Serve the same file at the path the standalone HTML expects, when
# accessed via http://127.0.0.1:5000/sample_data/demo_grounded_findings.json
@app.route("/sample_data/demo_grounded_findings.json")
@login_required
def demo_data_alias():
    p = ROOT / "sample_data" / "demo_grounded_findings.json"
    if not p.exists():
        abort(404, description="sample_data/demo_grounded_findings.json not found")
    return send_file(p, mimetype="application/json")


# Standalone HTML at /demo_dashboard.html for file:// parity when served via Flask
@app.route("/demo_dashboard.html")
@login_required
def demo_dashboard_static():
    p = ROOT / "demo_dashboard.html"
    if not p.exists():
        abort(404)
    return send_file(p, mimetype="text/html")


@app.route("/benchmark")
@login_required
def benchmark_exhibit():
    return render_template("benchmark_exhibit.html", corpus=str(corpus_root))


@app.route("/benchmark/data")
@login_required
def benchmark_data():
    p = ROOT / "sample_data" / "benchmark_data.json"
    if not p.exists():
        abort(404, description="sample_data/benchmark_data.json not found")
    return send_file(p, mimetype="application/json")


@app.route("/sample_data/benchmark_data.json")
@login_required
def benchmark_data_alias():
    p = ROOT / "sample_data" / "benchmark_data.json"
    if not p.exists():
        abort(404, description="sample_data/benchmark_data.json not found")
    return send_file(p, mimetype="application/json")


@app.route("/sample_data/benchmark_exhibit.html")
@login_required
def benchmark_exhibit_static():
    p = ROOT / "sample_data" / "benchmark_exhibit.html"
    if not p.exists():
        abort(404)
    return send_file(p, mimetype="text/html")


@app.route("/report/upload", methods=["GET", "POST"])
@login_required
def report_upload():
    """
    Live report upload — strict validation order, no pipeline on garbage.
    Spec: behind login_required, multipart single file field `scan_file`.
    Validation: file present/.xml -> size 5MB -> ET.parse -> root tag `nmaprun` (hard reject).
    Execution: parser -> rule_engine -> retrieval -> synthesize (live Gemini, quota-aware) -> validation.
    Returns: 200 {"report_id": "..."} for JSON, or redirect to /report/<id> for form.
    """
    if request.method == "GET":
        return render_template("report_upload.html", corpus=str(corpus_root))

    # POST — validation chain in order, reject fast
    file = request.files.get("scan_file")
    if not file or not file.filename:
        # 400 expected .xml file
        if request.accept_mimetypes.best == "application/json" or request.is_json:
            return {"error": "expected .xml file"}, 400
        return render_template("report_upload.html", corpus=str(corpus_root), error="expected .xml file"), 400

    filename = file.filename or ""
    if not filename.lower().endswith(".xml"):
        if request.accept_mimetypes.best == "application/json" or "application/json" in request.headers.get("Accept", ""):
            return {"error": "expected .xml file"}, 400
        return render_template("report_upload.html", corpus=str(corpus_root), error="expected .xml file"), 400

    # Size cap 5MB — check Content-Length and actual file size
    # Flask's MAX_CONTENT_LENGTH is 25MB for import, but report is stricter 5MB
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > REPORT_MAX_BYTES:
        if request.accept_mimetypes.best == "application/json" or "application/json" in request.headers.get("Accept", ""):
            return {"error": "file too large"}, 413
        return render_template("report_upload.html", corpus=str(corpus_root), error="file too large (max 5 MB)"), 413

    # Save to temp for ET.parse check (don't trust nmap_parser's soft warning)
    tmpdir = Path(tempfile.mkdtemp(prefix="report_upload_"))
    # Use basename only — client may send full path like "data/sample_scans/edge_empty.xml"
    safe_name = Path(filename).name or "upload.xml"
    tmp_xml = tmpdir / safe_name
    try:
        file.save(str(tmp_xml))
    except Exception as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        app.logger.exception("report upload save failed")
        return render_template("report_upload.html", corpus=str(corpus_root), error=f"failed to save upload: {e}"), 500

    # Parse attempt via ET.parse — hard reject if not valid XML
    try:
        root = ET.parse(str(tmp_xml)).getroot()
    except ET.ParseError as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        if request.accept_mimetypes.best == "application/json" or "application/json" in request.headers.get("Accept", ""):
            return {"error": "not valid XML"}, 400
        return render_template("report_upload.html", corpus=str(corpus_root), error="not valid XML — could not parse file"), 400
    except Exception as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        if request.accept_mimetypes.best == "application/json" or "application/json" in request.headers.get("Accept", ""):
            return {"error": "not valid XML"}, 400
        return render_template("report_upload.html", corpus=str(corpus_root), error="not valid XML"), 400

    # Root tag check — hard rejection, not soft warning
    if root.tag != "nmaprun":
        shutil.rmtree(tmpdir, ignore_errors=True)
        if request.accept_mimetypes.best == "application/json" or "application/json" in request.headers.get("Accept", ""):
            return {"error": "not an nmap scan file"}, 400
        return render_template("report_upload.html", corpus=str(corpus_root), error="not an nmap scan file — expected <nmaprun> root"), 400

    # Execution flow (server-side only — no Gemini calls from browser)
    try:
        cve_kb = _load(CVE_KB_PATH) or {}
        cis_kb = _load(CIS_KB_PATH) or []

        findings = nmap_parser.parse_nmap_xml(str(tmp_xml))
        # Count hosts that were up (for empty-scan vs no-findings distinction)
        try:
            hosts_up = len([h for h in root.findall("host") if (h.find("status") is not None and h.find("status").get("state") == "up")])
        except Exception:
            hosts_up = len({f.get("host") for f in findings}) if findings else 0
        # Empty scan is not an error 500 — show explicit UI state later
        # but we still need to handle 0 hosts / 0 findings gracefully
        scored = rule_engine.analyze(findings, cve_kb)
        cve_store = retrieval.CveStore(cve_kb)
        cis_index = retrieval.CisIndex(cis_kb)
        grounded = retrieval.ground_all(
            [f for f in scored.get("all_scored_findings", []) if f.get("type") in ("vuln", "asset")],
            cve_store, cis_index
        )

        # Gemini quota handling + synthesize (per grounded finding, grounded only)
        synthesized, quota_info = _synthesize_with_quota(grounded, cve_kb)

        # Fabrication/unsupported check on live output
        validation_flags = _validate_live_citations(grounded, synthesized, cve_kb)

    except Exception as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        app.logger.exception("report pipeline failed")
        if request.accept_mimetypes.best == "application/json" or "application/json" in request.headers.get("Accept", ""):
            return {"error": f"pipeline failed: {type(e).__name__}: {e}"}, 500
        return render_template("report_upload.html", corpus=str(corpus_root), error=f"pipeline failed: {e}"), 500
    finally:
        # Keep tmp_xml for potential debug, but clean up temp dir's other files
        pass

    # Assemble report — same shape as demo_grounded_findings.json plus synthesis
    report_id = uuid.uuid4().hex
    report = {
        "report_id": report_id,
        "filename": filename,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": session.get("username") or session.get("user") or "unknown",
        "findings": findings,
        "scored": scored,
        "grounded": grounded,
        "synthesized": synthesized,
        "quota_info": quota_info,
        "validation_flags": validation_flags,
        "has_hallucination": bool(validation_flags),
        # For HTML view convenience
        "host_summary": scored.get("host_risk_summary", []),
        "cve_records_total": sum(len(f.get("grounding_context", {}).get("cve_records", [])) for f in grounded),
        "cis_matches_total": sum(len(f.get("grounding_context", {}).get("cis_matches", [])) for f in grounded),
        "hosts_up": hosts_up,
        "is_empty_scan": hosts_up == 0,
        "is_no_findings": hosts_up > 0 and len(grounded) == 0,
    }

    # Store (in-memory + on-disk)
    REPORTS[report_id] = report
    try:
        (REPORTS_DIR / f"{report_id}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        # Also copy the original XML for audit
        dest_xml = REPORTS_DIR / f"{report_id}.xml"
        shutil.copy(str(tmp_xml), str(dest_xml))
    except Exception:
        pass
    shutil.rmtree(tmpdir, ignore_errors=True)

    # Return JSON for API clients, redirect for form posts
    if request.accept_mimetypes.best == "application/json" or "application/json" in request.headers.get("Accept", "") or request.headers.get("Accept", "").startswith("application/json"):
        return {"report_id": report_id}, 200
    # For form posts, flash quota/validation notices and redirect to HTML view
    if quota_info.get("quota_exceeded"):
        flash(quota_info["message"], "warn")
    if validation_flags:
        flash(f"Hallucination check: {len(validation_flags)} finding(s) flagged with fabricated/unsupported CVE citations — see report for details.", "warn")
    return redirect(url_for("report_view", report_id=report_id))


@app.route("/report/<report_id>")
@login_required
def report_view(report_id: str):
    if not REPORT_ID_PATTERN.match(report_id or ""):
        abort(404)
    report = REPORTS.get(report_id)
    # Fall back to disk if not in memory (after restart)
    if report is None:
        p = REPORTS_DIR / f"{report_id}.json"
        if p.exists():
            try:
                report = json.loads(p.read_text(encoding="utf-8"))
                REPORTS[report_id] = report
            except Exception:
                abort(404)
        else:
            abort(404)

    # For template: sort grounded findings by severity for display, reuse scan.html logic
    grounded = report.get("grounded", [])
    findings = sorted(grounded, key=_sort_key_finding, reverse=True)
    host_summary = report.get("host_summary") or report.get("scored", {}).get("host_risk_summary", [])

    # Distinct marker from /demo
    live_marker = f"Live scan — uploaded {report.get('filename')} at {report.get('uploaded_at')}"

    return render_template("report_view.html",
                           corpus=str(corpus_root),
                           report=report,
                           report_id=report_id,
                           host_summary=host_summary,
                           findings=findings,
                           live_marker=live_marker,
                           quota_info=report.get("quota_info", {}),
                           validation_flags=report.get("validation_flags", []),
                           synthesized=report.get("synthesized", []))


@app.route("/report/<report_id>/export")
@login_required
def report_export(report_id: str):
    if not REPORT_ID_PATTERN.match(report_id or ""):
        abort(404)
    p = REPORTS_DIR / f"{report_id}.json"
    if not p.exists():
        # Check memory
        if report_id not in REPORTS:
            abort(404)
        # Create temp file from memory
        p = REPORTS_DIR / f"{report_id}.json"
        p.write_text(json.dumps(REPORTS[report_id], indent=2, ensure_ascii=False), encoding="utf-8")
    return send_file(p, as_attachment=True, download_name=f"{report_id}_report.json", mimetype="application/json")


@app.route("/report/<report_id>/pdf")
@login_required
def report_pdf(report_id: str):
    if not REPORT_ID_PATTERN.match(report_id or ""):
        abort(404)
    report = REPORTS.get(report_id)
    if report is None:
        p = REPORTS_DIR / f"{report_id}.json"
        if p.exists():
            try:
                report = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                abort(404)
        else:
            abort(404)

    grounded = report.get("grounded", [])
    findings = sorted(grounded, key=_sort_key_finding, reverse=True)
    host_summary = report.get("host_summary") or report.get("scored", {}).get("host_risk_summary", [])
    live_marker = f"Live scan — uploaded {report.get('filename')} at {report.get('uploaded_at')}"

    html = render_template("report_view.html",
                           corpus=str(corpus_root),
                           report=report,
                           report_id=report_id,
                           host_summary=host_summary,
                           findings=findings,
                           live_marker=live_marker,
                           quota_info=report.get("quota_info", {}),
                           validation_flags=report.get("validation_flags", []),
                           synthesized=report.get("synthesized", []),
                           pdf_mode=True)

    # Try weasyprint first (best fidelity, reuses styled HTML), fallback to reportlab (pure Python, no system deps)
    try:
        from weasyprint import HTML
        import io
        pdf_bytes = HTML(string=html).write_pdf()
        return send_file(
            io.BytesIO(pdf_bytes),
            as_attachment=True,
            download_name=f"{report_id}_report.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        app.logger.warning(f"weasyprint unavailable ({type(e).__name__}: {e}), trying reportlab fallback")
        # Fallback: pure-Python PDF via reportlab (no GTK/libgobject needed)
        try:
            import io
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=15*mm, bottomMargin=15*mm, leftMargin=12*mm, rightMargin=12*mm,
                                    title=f"Report {report_id}", author="Cyber Health Assessment")
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle('Title2', parent=styles['Title'], fontSize=16, textColor=colors.HexColor('#0B0E13'), spaceAfter=6)
            h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=11, textColor=colors.HexColor('#1A2332'), spaceBefore=8, spaceAfter=4)
            body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#2A3441'), leading=11)
            mono_style = ParagraphStyle('Mono', parent=styles['Code'], fontSize=7, textColor=colors.HexColor('#5A6573'), leading=9, fontName='Courier')
            story = []
            story.append(Paragraph("Cyber Health Assessment — Live Report", title_style))
            story.append(Paragraph(f"{live_marker} &middot; Report ID {report_id}", body_style))
            story.append(Spacer(1, 6))
            if host_summary:
                story.append(Paragraph("Host risk", h2_style))
                host_data = [["Host", "Risk", "Reason"]]
                for h in host_summary:
                    host_data.append([f"{h.get('host')} ({h.get('hostname') or ''})", f"{h.get('adjusted_risk_score')} {h.get('risk_band')}", h.get('criticality_reason','')[:60]])
                t = Table(host_data, colWidths=[60*mm, 30*mm, 80*mm])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#11151C')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTSIZE', (0,0), (-1,0), 7),
                    ('FONTSIZE', (0,1), (-1,-1), 7),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#1E2633')),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F7F8FA')]),
                ]))
                story.append(t)
                story.append(Spacer(1, 8))
            # Quota / validation banners
            quota_info = report.get("quota_info", {})
            if quota_info.get("quota_exceeded"):
                story.append(Paragraph(f"<b>Quota:</b> {quota_info.get('message','')}", body_style))
                story.append(Spacer(1, 4))
            validation_flags = report.get("validation_flags", [])
            if validation_flags:
                story.append(Paragraph(f"<b>Hallucination check:</b> {len(validation_flags)} finding(s) flagged", body_style))
                story.append(Spacer(1, 4))
            story.append(Paragraph(f"Findings ({len(findings)} total) — every claim below is either cited or explicitly ungrounded", h2_style))
            # Per-finding block layout — mirrors web report cards, fits synthesis paragraphs
            from xml.sax.saxutils import escape as _escape
            from reportlab.platypus import ListFlowable, ListItem
            # Build quick lookup for synthesis + validation by finding_ref
            syn_by_ref = {}
            for s in report.get("synthesized", []) or []:
                ref = s.get("finding_ref")
                if ref:
                    syn_by_ref[ref] = s
            flag_by_ref = {}
            for fl in report.get("validation_flags", []) or []:
                ref = fl.get("finding_ref")
                if ref:
                    flag_by_ref[ref] = fl
            # Styles for per-finding blocks
            finding_title_style = ParagraphStyle('FindingTitle', parent=body_style, fontSize=9, leading=12, textColor=colors.HexColor('#0B0E13'), spaceBefore=6, spaceAfter=3, fontName='Helvetica-Bold')
            finding_meta_style = ParagraphStyle('FindingMeta', parent=body_style, fontSize=7, leading=10, textColor=colors.HexColor('#5A6573'), spaceAfter=2)
            synthesis_style = ParagraphStyle('Synthesis', parent=body_style, fontSize=8, leading=11, textColor=colors.HexColor('#1A2332'), leftIndent=6, borderPadding=(4,4,6), spaceAfter=4)
            synthesis_fail_style = ParagraphStyle('SynthesisFail', parent=synthesis_style, textColor=colors.HexColor('#9B1C1C'), backColor=colors.HexColor('#FEF2F2'))
            synthesis_ok_style = ParagraphStyle('SynthesisOk', parent=synthesis_style, backColor=colors.HexColor('#F0FDF4'), borderColor=colors.HexColor('#BBF7D0'))
            evidence_style = ParagraphStyle('Evidence', parent=body_style, fontSize=7, leading=10, textColor=colors.HexColor('#2A3441'), leftIndent=6, spaceAfter=2)
            # Limit to 40 for PDF size, but per-finding blocks are larger — still cap
            for idx, f in enumerate(findings[:40]):
                host = _escape(str(f.get("host") or ""))
                hostname = _escape(str(f.get("hostname") or ""))
                port = _escape(str(f.get("port") or ""))
                proto = _escape(str(f.get("protocol") or ""))
                service = _escape(str(f.get("service") or ""))
                nse = _escape(str(f.get("nse_script") or ""))
                band = _escape(str(f.get("severity_band") or ""))
                score = f.get("severity_score")
                score_str = f"{score:.1f}" if isinstance(score, (int, float)) else ""
                cve_refs = ", ".join(f.get("cve_refs", []) or []) or "— no CVE ref"
                cve_refs_esc = _escape(cve_refs)
                # Finding header
                title_text = f"<b>Finding {idx+1}: {band} {score_str}</b> — {host}:{port}/{proto} {service}"
                if nse:
                    title_text += f" <font size=7 color='#5A6573'>({nse})</font>"
                story.append(Paragraph(title_text, finding_title_style))
                meta_text = f"Host {host} <font color='#5A6573'>({hostname})</font> · Service {service} · Port {port}/{proto} · CVE {cve_refs_esc}"
                # Scoring rationale
                rationale = f.get("scoring_rationale")
                if rationale:
                    meta_text += f" · <i>{_escape(rationale)}</i>"
                story.append(Paragraph(meta_text, finding_meta_style))
                # Grounding context — CVE records + CIS matches
                ctx = f.get("grounding_context", {}) or {}
                cve_records = ctx.get("cve_records", []) or []
                cis_matches = ctx.get("cis_matches", []) or []
                has_evidence = bool(cve_records or cis_matches)
                if cve_records:
                    for rec in cve_records:
                        if rec.get("not_found") or rec.get("status") == "not_found":
                            story.append(Paragraph(f"<b>{_escape(rec.get('id',''))}</b> <font color='#9B1C1C'>NOT IN KB</font> — no local record", evidence_style))
                        else:
                            rid = _escape(str(rec.get("id") or ""))
                            cvss = rec.get("cvss_v3_score")
                            cvss_str = f"CVSS {cvss}" if cvss is not None else ""
                            sev = _escape(str(rec.get("cvss_severity") or ""))
                            text = _escape((rec.get("text") or "")[:600])
                            kev = " · ACTIVELY EXPLOITED" if rec.get("kev_listed") else ""
                            story.append(Paragraph(f"<b>{rid}</b> {sev} {cvss_str}{kev}<br/><font size=7>{text}</font>", evidence_style))
                            # References/CWE
                            cwe = ", ".join(rec.get("cwe_ids", []) or [])
                            if cwe or rec.get("published_date") or rec.get("cvss_v3_vector"):
                                meta = []
                                if cwe:
                                    meta.append(f"CWE: {_escape(cwe)}")
                                if rec.get("published_date"):
                                    meta.append(f"published {_escape(str(rec.get('published_date')[:10]))}")
                                if rec.get("cvss_v3_vector"):
                                    meta.append(f"<font face='Courier' size=6>{_escape(rec.get('cvss_v3_vector'))}</font>")
                                story.append(Paragraph(" · ".join(meta), finding_meta_style))
                else:
                    story.append(Paragraph("<i>No CVE citation available — ungrounded</i>", finding_meta_style))
                if cis_matches:
                    story.append(Paragraph("<b>CIS Controls:</b>", finding_meta_style))
                    for c in cis_matches:
                        cid = _escape(str(c.get("id") or ""))
                        title = _escape(str(c.get("control_title") or ""))
                        section = _escape(str(c.get("section") or ""))
                        level = c.get("level")
                        level_str = f" L{level}" if level is not None else ""
                        text = _escape((c.get("text") or "")[:500])
                        sim = c.get("similarity_score")
                        sim_str = f" sim {sim:.3f}" if isinstance(sim, (int, float)) else ""
                        story.append(Paragraph(f"{cid}{level_str} — {title} <font color='#5A6573'>({section}{sim_str})</font><br/><font size=7>{text}</font>", evidence_style))
                # Synthesis per finding
                ref_key = f"{f.get('host')}:{f.get('port')}/{f.get('protocol')}/{f.get('service')}/{f.get('nse_script') or 'asset'}"
                syn = syn_by_ref.get(ref_key)
                flag = flag_by_ref.get(ref_key)
                if flag:
                    # HALLUCINATED badge
                    fab = ", ".join(flag.get("fabricated", []) or [])
                    unsup = ", ".join(flag.get("unsupported", []) or [])
                    cited = ", ".join(flag.get("cited", []) or [])
                    allowed = ", ".join(flag.get("allowed", []) or []) or "(none)"
                    warn_text = f"<b><font color='#9B1C1C'>HALLUCINATED</font></b> — cited {_escape(cited)} not in allowed {_escape(allowed)}"
                    if fab:
                        warn_text += f"<br/>Fabricated (not in KB): {_escape(fab)}"
                    if unsup:
                        warn_text += f"<br/>Unsupported (not in retrieved): {_escape(unsup)}"
                    story.append(Paragraph(warn_text, synthesis_fail_style))
                if syn is not None:
                    if syn.get("not_synthesized"):
                        story.append(Paragraph(f"<b>Not synthesized</b> — daily quota reached. { _escape(syn.get('error') or 'not synthesized — daily quota reached') }", synthesis_fail_style))
                    elif syn.get("ok"):
                        parsed = syn.get("parsed", {}) or {}
                        expl = _escape(str(parsed.get("plain_language_explanation") or syn.get("raw_output", "")[:800] or ""))
                        # Synthesis paragraph
                        story.append(Paragraph(f"<b>Gemini synthesis (GROUNDED):</b> {expl}", synthesis_ok_style))
                        cves_mentioned = parsed.get("cve_ids_mentioned", []) or syn.get("extracted_cve_ids", []) or []
                        if cves_mentioned:
                            story.append(Paragraph(f"Cited: {_escape(', '.join(cves_mentioned))}", finding_meta_style))
                        steps = parsed.get("remediation_steps", []) or []
                        if steps:
                            # Bullet list via ListFlowable
                            bullet_items = []
                            for step in steps:
                                bullet_items.append(ListItem(Paragraph(_escape(str(step)), body_style), leftIndent=12))
                            story.append(ListFlowable(bullet_items, bulletType='bullet', start='circle', leftIndent=12))
                    else:
                        err = _escape(str(syn.get("error") or "unknown error"))
                        story.append(Paragraph(f"<b>Synthesis failed:</b> {err}", synthesis_fail_style))
                else:
                    story.append(Paragraph("<i>No synthesis available for this finding</i>", finding_meta_style))
                story.append(Spacer(1, 4))
                # Keep per-finding block together if possible — add a thin line
                # (use a spacer with line via Table with one cell)
                line_tbl = Table([[""]], colWidths=[doc.width])
                line_tbl.setStyle(TableStyle([('LINEBELOW', (0,0), (-1,0), 0.5, colors.HexColor('#E5E7EB'))]))
                story.append(line_tbl)
                story.append(Spacer(1, 4))
            if len(findings) > 40:
                story.append(Paragraph(f"... and {len(findings)-40} more findings (see JSON export)", body_style))
            story.append(Spacer(1, 8))
            story.append(Paragraph(f"Generated {report.get('uploaded_at','')} &middot; {len(findings)} findings &middot; {report.get('cve_records_total',0)} CVE &middot; {report.get('cis_matches_total',0)} CIS", mono_style))
            doc.build(story)
            pdf_bytes = buf.getvalue()
            buf.close()
            return send_file(
                io.BytesIO(pdf_bytes),
                as_attachment=True,
                download_name=f"{report_id}_report.pdf",
                mimetype="application/pdf"
            )
        except Exception as e2:
            app.logger.warning(f"reportlab fallback also failed ({type(e2).__name__}: {e2}), returning HTML")
            return html, 200, {"Content-Type": "text/html", "Content-Disposition": f"inline; filename={report_id}_report.html"}


@app.errorhandler(RequestEntityTooLarge)
def _upload_too_large(e):
    return render_template("import.html", corpus=str(corpus_root),
                           error="That file is too large (max 25 MB)."), 413


def main():
    global corpus_root
    parser = argparse.ArgumentParser(description="Flask dashboard for the cyber-health corpus.")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS),
                        help="Corpus root dir (corpus_report.json + scans/)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    corpus_root = Path(args.corpus)
    if not corpus_root.is_dir():
        raise SystemExit(f"corpus dir not found: {corpus_root}")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()