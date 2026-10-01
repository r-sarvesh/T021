"""
nmap_parser.py

Parses Nmap XML scan output (-oX) into a normalized list of "finding"
objects, matching the schema used downstream by the rule-based scoring
engine and the RAG retrieval layer.

Usage:
    python3 nmap_parser.py sample_scan.xml
    python3 nmap_parser.py sample_scan.xml --pretty
    python3 nmap_parser.py sample_scan.xml -o findings.json

Output: a JSON array of finding objects. Two kinds of records are emitted
per host:
  1. "asset" records — one per open port/service, always emitted.
  2. "vuln" records — one per NSE script that reported a vulnerability
     (i.e. contains a CVE ID or the literal string "VULNERABLE").

Both record types share a common shape so the rule engine and RAG layer
can consume a single flat list without branching on type unnecessarily.
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

# Matches CVE IDs anywhere in NSE script output, e.g. "CVE:CVE-2017-0143"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

# NSE scripts whose output should always be treated as a vulnerability
# finding even if they don't contain a formal CVE ID (e.g. cert issues,
# anonymous auth, weak ciphers).
VULN_SIGNAL_SCRIPTS = {
    "ftp-anon",
    "ssl-known-key",
    "ssl-cert",
    "smb-vuln-ms17-010",
    "rdp-vuln-ms12-020",
    "mysql-vuln-cve2012-2122",
}

# Static fallback: known NSE script IDs that imply a CVE even when the
# script output is truncated and lacks an explicit CVE string (e.g.
# smb-vuln-ms17-010 output "VULNERABLE: ... (ms17-010)" without "CVE-2017-0143").
# This is NOT a generic CVE-to-script table — only for cases where the
# output is known to be truncated but the script id is unambiguous.
SCRIPT_CVE_FALLBACK = {
    "smb-vuln-ms17-010": ["CVE-2017-0143"],
}


def parse_nmap_xml(xml_path: str) -> list[dict]:
    """Parse an Nmap XML file and return a flat list of finding dicts."""
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(f"Warning: failed to parse Nmap XML '{xml_path}': {e}", file=sys.stderr)
        return []
    root = tree.getroot()
    # Defensive: some malformed exports may not have <nmaprun> root but still contain hosts
    if root.tag != "nmaprun":
        print(f"Warning: unexpected root tag '{root.tag}' (expected 'nmaprun') — attempting to parse hosts anyway", file=sys.stderr)

    findings: list[dict] = []

    for host_el in root.findall("host"):
        ip_address = _get_ip(host_el)
        hostname = _get_hostname(host_el)
        os_guess = _get_os(host_el)
        # Fallback for hosts with no IPv4 (e.g. IPv6-only) — use hostname or placeholder so grouping still works
        if not ip_address:
            ip_address = hostname or "unknown-host"

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                # Skip filtered/closed ports — not actionable findings.
                continue

            portid_raw = port_el.get("portid")
            try:
                port_id = int(portid_raw) if portid_raw is not None else None
                if port_id is None:
                    raise ValueError("missing portid")
            except (ValueError, TypeError):
                print(f"Warning: skipping port with invalid portid '{portid_raw}' on host {ip_address}", file=sys.stderr)
                continue
            protocol = port_el.get("protocol", "tcp") or "tcp"

            service_el = port_el.find("service")
            # service_name defaults to "unknown" and empty string is also treated as unknown
            service_name = service_el.get("name") if service_el is not None else None
            if not service_name:
                service_name = "unknown"
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None
            # Normalize empty strings to None for downstream consistency (malformed versions)
            if product == "":
                product = None
            if version == "":
                version = None

            # Always emit an asset-level finding for every open port.
            findings.append({
                "type": "asset",
                "host": ip_address,
                "hostname": hostname,
                "os_guess": os_guess,
                "port": port_id,
                "protocol": protocol,
                "service": service_name,
                "product": product,
                "version": version,
                "cve_refs": [],
                "nse_script": None,
                "raw_output": None,
            })

            # Emit a vuln-level finding for each relevant NSE script.
            for script_el in port_el.findall("script"):
                script_id = script_el.get("id")
                output = script_el.get("output", "")
                cve_refs = CVE_PATTERN.findall(output)
                # Fallback for known scripts where output may be truncated (e.g. smb-vuln-ms17-010 without CVE string)
                if not cve_refs and script_id in SCRIPT_CVE_FALLBACK:
                    cve_refs = list(SCRIPT_CVE_FALLBACK[script_id])

                # Avoid false-positive on "not VULNERABLE" negations (e.g. banner scripts)
                upper = output.upper()
                has_vuln_keyword = "VULNERABLE" in upper and "NOT VULNERABLE" not in upper
                is_vuln = bool(cve_refs) or has_vuln_keyword \
                    or (script_id in VULN_SIGNAL_SCRIPTS)

                if not is_vuln:
                    continue

                findings.append({
                    "type": "vuln",
                    "host": ip_address,
                    "hostname": hostname,
                    "os_guess": os_guess,
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "cve_refs": cve_refs,
                    "nse_script": script_id,
                    "raw_output": output.strip(),
                })

    return findings


def _get_ip(host_el: ET.Element) -> Optional[str]:
    # Prefer IPv4, fall back to IPv6, then None (caller will use hostname fallback)
    for addrtype in ("ipv4", "ipv6"):
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == addrtype:
                addr = addr_el.get("addr")
                if addr:
                    return addr
    return None


def _get_hostname(host_el: ET.Element) -> Optional[str]:
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is None:
        return None
    hostname_el = hostnames_el.find("hostname")
    return hostname_el.get("name") if hostname_el is not None else None


def _get_os(host_el: ET.Element) -> Optional[str]:
    os_el = host_el.find("os")
    if os_el is None:
        return None
    osmatch_el = os_el.find("osmatch")
    return osmatch_el.get("name") if osmatch_el is not None else None


def main():
    parser = argparse.ArgumentParser(description="Parse Nmap XML output into structured findings.")
    parser.add_argument("xml_file", help="Path to Nmap XML scan output (-oX)")
    parser.add_argument("-o", "--output", help="Write JSON to this file instead of stdout")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    args = parser.parse_args()

    xml_path = Path(args.xml_file)
    if not xml_path.exists():
        print(f"Error: file not found: {xml_path}", file=sys.stderr)
        sys.exit(1)

    findings = parse_nmap_xml(str(xml_path))

    indent = 2 if args.pretty else None
    json_output = json.dumps(findings, indent=indent)

    if args.output:
        Path(args.output).write_text(json_output)
        print(f"Wrote {len(findings)} findings to {args.output}")
    else:
        print(json_output)

    # Quick summary to stderr so it doesn't pollute JSON stdout output.
    asset_count = sum(1 for f in findings if f["type"] == "asset")
    vuln_count = sum(1 for f in findings if f["type"] == "vuln")
    hosts = {f["host"] for f in findings}
    print(
        f"\nSummary: {len(hosts)} hosts, {asset_count} open services, "
        f"{vuln_count} vulnerability findings",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
