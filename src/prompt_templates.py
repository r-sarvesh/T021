"""
prompt_templates.py

Pure string builders — no I/O, no network, no LLM calls. Every prompt the
synthesis layer can send is defined here so the exact bytes sent to the
model can be logged, diffed, and reproduced for the hallucination
benchmark.

Two variants per finding, matching the design in rag_retrieval_schema.md
section 5:

  - `build_grounded_prompt`: the finding PLUS its retrieved CVE/CIS
    evidence (the `grounding_context` attached by retrieval.py), with an
    instruction to cite ONLY what was provided.
  - `build_ungrounded_prompt`: the same finding WITHOUT the retrieved
    context block, with the same instruction to name CVE/CVSS "if known"
    from general knowledge. This is the benchmark baseline. It must not
    be used for production reports.

Both produce instructions the LLM's reply to a JSON object with the exact
fields the synthesis layer expects. Keeping this shape stable matters: the
harness reads `cve_ids_mentioned` (and re-checks via regex on the raw
text) against `grounding_context.cve_records[*].id`.

Remediation and executive-summary prompts are also here so that ALL prompt
text lives in one module, rather than scattered across orchestration code.
"""

from typing import Optional

import re

# CVE IDs must only enter the prompt via the RETRIEVED block (grounded) or
# the LLM's own knowledge (ungrounded). The FINDING block shows scan
# evidence like NSE raw output, which can itself contain CVE references
# (e.g. "IDs: CVE:CVE-2017-0143"). If we render those verbatim, the
# ungrounded variant would leak the exact CVE ID the model is supposed to
# produce from memory, and the benchmark would measure copy-and-paste, not
# hallucination. Redact them so the finding and the evidence stay separate.
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

# The exact JSON object shape requested of the model per finding. Keeping
# the schema string inline (not a dict) means the prompt and the contract
# can't drift apart by accident.
_FINDING_JSON_INSTRUCTIONS = """
Reply with a single JSON object, no markdown, with exactly these fields:
{
  "plain_language_explanation": "2-3 sentences a non-technical stakeholder can understand. What is exposed, why it matters, how bad the rule engine rated it.",
  "cve_ids_mentioned": ["CVE-YYYY-NNNNN", ...],
  "cis_controls_referenced": ["CIS-...", ...],
  "remediation_steps": ["step 1", "step 2", ...]
}
Rules:
- "cve_ids_mentioned" must list every CVE ID you actually reference, and no others.
- "cis_controls_referenced" must list every CIS control ID you reference, and no others.
- If you reference no CVE or no CIS control, use an empty list.
"""

_GROUNDED_CITATION_RULE = (
    "CRITICAL RULE: You may only cite CVE IDs and CVSS scores that appear "
    "in the RETRIEVED data below. You may only cite CIS control IDs that "
    "appear in the RETRIEVED data below. Do not introduce any CVE ID, CVSS "
    "score, CWE, or benchmark ID that is not present in the retrieved data. "
    "If the retrieved data is insufficient to explain the severity, say so "
    "explicitly instead of estimating."
)

_UNGROUNDED_CITATION_RULE = (
    "Name the CVE ID(s), CVSS score(s), and CIS control(s) relevant to this "
    "finding if you know them from your cybersecurity knowledge. An accurate, "
    "specific citation is expected from an expert. If you are NOT certain a "
    "CVE ID or CVSS score actually exists, do not invent one — say the "
    "relevant CVE information is unavailable."
)


def _finding_context(finding: dict) -> str:
    """The FINDING block shared by both grounded and ungrounded prompts."""
    lines = [
        f"Host {finding.get('host')} ({finding.get('hostname') or 'unknown hostname'})",
        f"OS guess: {finding.get('os_guess') or 'unknown'}",
        f"Port {finding.get('port')}/{finding.get('protocol') or 'tcp'} service: {finding.get('service') or 'unknown'}",
        f"Product/version: {finding.get('product') or 'unknown'} {finding.get('version') or ''}".rstrip(),
    ]
    if finding.get("nse_script"):
        lines.append(f"Nmap NSE script flagged: {finding['nse_script']}")
    if finding.get("raw_output"):
        lines.append(f"NSE raw output: {_CVE_PATTERN.sub('[CVE ID redacted]', finding['raw_output'])}")
    # Severity is ALWAYS the rule engine's decision — never ask the LLM to
    # re-derive it. See rule_engine.py docstring: the LLM explains and
    # cites, it does not decide severity.
    lines.append(
        f"Rule-engine severity: {finding.get('severity_band') or 'UNSCORED'} "
        f"(score {finding.get('severity_score')})"
    )
    return "\n".join(lines)


def _format_cve_record(record: dict) -> str:
    """Render one cve_kb record for the retrieved-context block."""
    return (
        f"- {record.get('id')} | CVSS v3 {record.get('cvss_v3_score')} "
        f"{record.get('cvss_severity') or ''} | KEV-listed: {record.get('kev_listed')} "
        f"| Description: {record.get('text') or '(no description)'}"
    )


def _format_cis_control(control: dict) -> str:
    return (
        f"- {control.get('id')} ({control.get('benchmark')}): "
        f"{control.get('control_title')} — {control.get('text')}"
    )


def _retrieved_context_block(finding: dict) -> str:
    """The RETRIEVED CVE/CIS block. Empty in the ungrounded variant."""
    ctx = finding.get("grounding_context") or {}
    cve_records = ctx.get("cve_records") or []
    cis_matches = ctx.get("cis_matches") or []

    lines = ["RETRIEVED CVE DATA (the only CVEs you may cite):"]
    if cve_records:
        for rec in cve_records:
            if rec.get("not_found"):
                lines.append(
                    f"- {rec.get('id')}: not present in the local knowledge base — do not speculate about it"
                )
            else:
                lines.append(_format_cve_record(rec))
    else:
        lines.append("(none retrieved)")

    lines.append("\nRETRIEVED CIS CONTROLS (the only CIS controls you may cite):")
    if cis_matches:
        for ctl in cis_matches:
            lines.append(_format_cis_control(ctl))
    else:
        lines.append("(none retrieved)")

    return "\n".join(lines)


def build_grounded_prompt(finding: dict) -> str:
    """Prompt with the full retrieved-evidence context injected."""
    return (
        "You are a cybersecurity reporting assistant. Explain the following "
        "security finding to a non-technical stakeholder, using ONLY the "
        "retrieved evidence provided.\n\n"
        f"FINDING:\n{_finding_context(finding)}\n\n"
        f"{_retrieved_context_block(finding)}\n\n"
        f"INSTRUCTIONS:\n{_GROUNDED_CITATION_RULE}\n{_FINDING_JSON_INSTRUCTIONS}"
    )


def build_ungrounded_prompt(finding: dict) -> str:
    """Baseline variant: same finding, NO retrieved context. Benchmark only."""
    return (
        "You are a cybersecurity reporting assistant. Explain the following "
        "security finding to a non-technical stakeholder.\n\n"
        f"FINDING:\n{_finding_context(finding)}\n\n"
        f"INSTRUCTIONS:\n{_UNGROUNDED_CITATION_RULE}\n{_FINDING_JSON_INSTRUCTIONS}"
    )


def build_executive_summary_prompt(host_findings: list[dict]) -> str:
    """
    One prompt per host, summarizing its findings and producing the
    executive-level narrative for the report. Input is the subset of
    grounded findings belonging to that host.
    """
    finding_blocks = []
    for i, f in enumerate(host_findings, 1):
        ctx = f.get("grounding_context") or {}
        cve_ids = [r.get("id") for r in (ctx.get("cve_records") or []) if r.get("id")]
        cis_ids = [c.get("id") for c in (ctx.get("cis_matches") or [])]
        finding_blocks.append(
            f"Finding {i}: {f.get('service')} on port {f.get('port')} "
            f"[severity {f.get('severity_band')}] {f.get('nse_script') or ''} "
            f"CVEs: {cve_ids or 'none'} CIS: {cis_ids or 'none'}"
        )

    return (
        "You are a cybersecurity reporting assistant. Given the list of findings "
        "for a single host below, write a concise executive summary (max 4 "
        "sentences) a business stakeholder can act on: overall posture, the "
        "highest-risk items, and one concrete next step.\n"
        "Only reference CVE IDs, CVSS scores, and CIS control IDs shown in the "
        "finding list below.\n"
        'Reply with a single JSON object: {"executive_summary": "...", "highest_risk_items": ["..."], "next_step": "..."}\n\n'
        f"FINDINGS FOR {host_findings[0].get('host')} "
        f"({host_findings[0].get('hostname') or ''}):\n"
        + "\n".join(finding_blocks)
    )


def build_remediation_prompt(
    prioritized_findings: list[dict],
    advisory_text: Optional[str] = None,
) -> str:
    """
    Generates a prioritized remediation list across a scan. The PRIORITY
    ORDER comes from rule_engine.py's prioritized_findings (already sorted
    by severity_score) — the LLM explains and maps to CIS controls but
    must NOT re-rank.
    """
    blocks = []
    for i, f in enumerate(prioritized_findings, 1):
        ctx = f.get("grounding_context") or {}
        cve_ids = [r.get("id") for r in (ctx.get("cve_records") or []) if r.get("id")]
        cis_ids = [c.get("id") for c in (ctx.get("cis_matches") or [])]
        blocks.append(
            f"{i}. {f.get('host')} port {f.get('port')} ({f.get('service')}) — "
            f"{f.get('nse_script') or 'asset exposure'} — "
            f"severity {f.get('severity_band')} — CVEs: {cve_ids or 'none'} — "
            f"CIS: {cis_ids or 'none'}"
        )

    preamble = advisory_text or (
        "Findings below are already sorted by priority (highest risk first) "
        "by our deterministic rule engine. Preserve this exact order."
    )
    return (
        "You are a cybersecurity reporting assistant. Produce a prioritized "
        "remediation action list for the findings below.\n"
        f"{preamble}\n"
        "For each finding give a plain-language remediation action and map it "
        "to at most one CIS control ID from the finding's CIS list. Do not invent "
        "CIS control IDs or CVE IDs.\n"
        'Reply with a single JSON object: '
        '{"remediation_plan": [{"priority": 1, "host": "...", "port": ..., '
        '"service": "...", "action": "...", "cis_control_id": "..."}]}\n\n'
        "PRIORITIZED FINDINGS:\n" + "\n".join(blocks)
    )
