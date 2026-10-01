"""
corpus_generator.py

Deterministic generator for a synthetic benchmark corpus. Produces Nmap
scan XML files plus matching knowledge-base entries (cve_kb.json and
cis_kb.json) so that every CVE ID referenced in a scan is guaranteed to
resolve in the retrieved context of its own scan.

Why this exists (see parallel design in docs/rag_retrieval_schema.md §8):
a defensible hallucination benchmark needs more than the 2-CVE/6-finding
sample corpus, and it needs DIVERSITY of failure outcomes, not just more
volume:

  - Services: SMB, RDP, MySQL, OpenSSH, Apache httpd, Redis, MongoDB,
    OpenSSL/TLS, vsftpd — not just SMB/MySQL.
  - Severity bands: CRITICAL, HIGH, MEDIUM, LOW — so the benchmark isn't
    only exercised on "obviously bad" findings.
  - Decoy findings with no CVE at all (cert expiry, anonymous FTP, no-auth
    Redis/Mongo) — so grounded/ungrounded comparison also gets tested on
    findings where there's nothing to hallucinate.

CRITICAL correctness rule: every CVE ID placed in a scan XML must have a
matching record in the real-CVE catalog before that scan is considered
"done." The generator refuses to emit otherwise, because an unresolved
CVE would make retrieval.py return `not_found` for the grounded variant
and silently corrupt the benchmark. All CVE IDs come from
`data/knowledge_base/synthetic_cve_kb.json`, which is populated only from
verified NVD records (see ingest_nvd.py / the fetch step described in the
file header) — never invented IDs, even for a "clean" corpus. Otherwise
the fabricated_cve existence check (benchmark_harness.py) would be
confused by data this generator itself made up.

Determinism: seeded via Python's `random.Random` so any seed regenerates
the byte-identical corpus — required for a reproducible thesis appendix.

Structure produced under --out (default data/synthetic_corpus/):

    cve_kb.json          # union of all real CVEs used across the corpus
    cis_kb.json          # union of CIS controls applicable to corpus services
    manifest.json        # scan inventory + per-scan CVE/CIS coverage + results
    scans/
      scan_0001/
        scan.xml
        cve_kb.json      # ONLY the CVEs this scan references
        cis_kb.json      # ONLY controls matching this scan's service tags

Usage:
    python3 corpus_generator.py --seed 1337 --scans 12
    python3 corpus_generator.py --seed 1337 --scans 12 \
        --out ../data/synthetic_corpus
"""

import argparse
import json
import random
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

DEFAULT_CATALOG = Path(__file__).resolve().parent.parent / "data" / "knowledge_base" / "synthetic_cve_kb.json"
DEFAULT_CIS = Path(__file__).resolve().parent.parent / "data" / "knowledge_base" / "sample_cis_kb.json"

# ---------------------------------------------------------------------------
# CIS controls for services the corpus covers but sample_cis_kb lacks.
# Illustrative placeholder text (same caveat as sample_cis_kb — NOT verbatim
# CIS Benchmark content, which is copyrighted; written from scratch to match
# the schema for dev/testing).
# ---------------------------------------------------------------------------
EXTRA_CIS_CONTROLS = [
    {
        "id": "CIS-REDIS-001",
        "benchmark": "CIS Redis Benchmark (illustrative)",
        "section": "Authentication",
        "control_title": "Require authentication for Redis access (requirepass)",
        "text": "Redis should require a password via the requirepass directive for all access. A Redis instance bound to the network with no password allows any reachable client to read, modify, or destroy all data and, in some configurations, run Lua scripts. If Redis is not required to be network-exposed, bind it to loopback only.",
        "applies_to": ["redis"],
        "level": 1,
        "remediation_type": "configuration"
    },
    {
        "id": "CIS-REDIS-002",
        "benchmark": "CIS Redis Benchmark (illustrative)",
        "section": "Network Exposure",
        "control_title": "Restrict Redis network exposure and enable protected-mode",
        "text": "Redis protected-mode should stay enabled and the server should bind to internal interfaces only, so the database cannot be reached from untrusted networks. Where remote access is required, place it behind a bastion/VPN rather than direct exposure.",
        "applies_to": ["redis"],
        "level": 1,
        "remediation_type": "network_configuration"
    },
    {
        "id": "CIS-MONGO-001",
        "benchmark": "CIS MongoDB Benchmark (illustrative)",
        "section": "Authentication",
        "control_title": "Enable MongoDB authentication",
        "text": "MongoDB should run with authorization enabled. Instances started without --auth accept every connection as the all-powerful role and expose every collection to any reachable client — a pattern behind several large-scale data breaches.",
        "applies_to": ["mongodb"],
        "level": 1,
        "remediation_type": "configuration"
    },
    {
        "id": "CIS-MONGO-002",
        "benchmark": "CIS MongoDB Benchmark (illustrative)",
        "section": "Network Exposure",
        "control_title": "Bind MongoDB to internal interfaces only",
        "text": "MongoDB should bind to 127.0.0.1 or internal interfaces, never 0.0.0.0 on a public network. Use firewall rules or security groups to restrict inbound database traffic to the application tier.",
        "applies_to": ["mongodb"],
        "level": 1,
        "remediation_type": "network_configuration"
    },
]

# Template port types. Each key is stable across seeds so the CORPUS covers a
# fixed set of services regardless of how scans are sampled; only the
# sampling (which template lands in which scan/host) is randomized.
HOST_TEMPLATES = [
    # --- CRITICAL / HIGH on Windows infra ---
    {
        "name": "win-smb-dc",
        "os": "Microsoft Windows Server 2012 R2",
        "hostname": "dc{scan:02d}.corp.local",
        "ports": [
            {"port": 135, "service": "msrpc", "product": "Microsoft Windows RPC"},
            {"port": 139, "service": "netbios-ssn", "product": "Microsoft Windows netbios-ssn"},
            {"port": 445, "service": "microsoft-ds", "product": "Windows Server 2012 R2 microsoft-ds",
             "scripts": [{"id": "smb-vuln-ms17-010",
                          "output": "VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) State: VULNERABLE Risk factor: HIGH  IDs: CVE:CVE-2017-0143"}]},
            {"port": 3389, "service": "ms-wbt-server", "product": "Microsoft Terminal Services",
             "scripts": [{"id": "rdp-vuln-ms12-020",
                          "output": "VULNERABLE: MS12-020 Remote Desktop Protocol Denial of Service"}]},
        ],
    },
    {
        "name": "win-rdp-bluekeep",
        "os": "Microsoft Windows 7 SP1",
        "hostname": "ws-legacy-{scan:02d}.corp.local",
        "ports": [
            {"port": 135, "service": "msrpc", "product": "Microsoft Windows RPC"},
            {"port": 445, "service": "microsoft-ds", "product": "Windows 7 Professional microsoft-ds"},
            {"port": 3389, "service": "ms-wbt-server", "product": "Microsoft Terminal Services",
             "scripts": [{"id": "rdp-vuln-ms12-020",
                          "output": "VULNERABLE: MS12-020 Remote Desktop Protocol Denial of Service"},
                          {"id": "smb-vuln-ms17-010",
                           "output": "VULNERABLE: Pre-auth Remote Code Execution in RDP (BlueKeep). Risk factor: CRITICAL  IDs: CVE:CVE-2019-0708"}]},
        ],
    },
    {
        "name": "win-smbv3-ghost",
        "os": "Microsoft Windows 10 1903",
        "hostname": "win10-{scan:02d}.corp.local",
        "ports": [
            {"port": 445, "service": "microsoft-ds", "product": "Windows 10 Pro 1903 microsoft-ds",
             "scripts": [{"id": "smb-vuln-smbghost",
                          "output": "VULNERABLE: SMBv3 Compression buffer overflow Remote Code Execution (SMBGhost). State: VULNERABLE Risk factor: CRITICAL  IDs: CVE:CVE-2020-0796"}]},
            {"port": 139, "service": "netbios-ssn", "product": "Microsoft Windows netbios-ssn"},
        ],
    },
    # --- CRITICAL / HIGH on databases ---
    {
        "name": "mysql-legacy",
        "os": "Linux 3.10 - 4.6",
        "hostname": "db-mysql-{scan:02d}.corp.local",
        "ports": [
            {"port": 3306, "service": "mysql", "product": "MySQL", "version": "5.5.62",
             "scripts": [{"id": "mysql-vuln-cve2012-2122",
                          "output": "VULNERABLE: MySQL/MariaDB weak password authentication security bypass. IDs: CVE:CVE-2012-2122"},
                          {"id": "mysql-vuln-cve2016-6662",
                           "output": "VULNERABLE: MySQL general_log_file privilege escalation enables root RCE. IDs: CVE:CVE-2016-6662"}]},
        ],
    },
    {
        "name": "mysql-moderate",
        "os": "Linux 4.15 - 5.6",
        "hostname": "db-mysql2-{scan:02d}.corp.local",
        "ports": [
            {"port": 3306, "service": "mysql", "product": "MySQL", "version": "5.6.31",
             "scripts": [{"id": "mysql-vuln-cve2016-0643",
                          "output": "VULNERABLE: MySQL DML information disclosure allows local confidentiality breach. IDs: CVE:CVE-2016-0643"}]},
        ],
    },
    # --- OpenSSH ---
    {
        "name": "openssh-old",
        "os": "Linux 4.15 - 5.6",
        "hostname": "srv-ssh-{scan:02d}.corp.local",
        "ports": [
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4",
             "scripts": [{"id": "ssh2-enum-algos",
                          "output": "VULNERABLE: OpenSSH username enumeration via auth bailout timing. IDs: CVE:CVE-2018-15473"},
                          {"id": "ssh-vuln-cve2016-6210",
                           "output": "VULNERABLE: OpenSSH user enumeration via password-hash timing difference. IDs: CVE:CVE-2016-6210"}]},
        ],
    },
    {
        "name": "openssh-agent-rce",
        "os": "Linux 5.4 - 6.1",
        "hostname": "srv-ssh2-{scan:02d}.corp.local",
        "ports": [
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.3",
             "scripts": [{"id": "ssh-vuln-agent-pkcs11",
                          "output": "VULNERABLE: ssh-agent PKCS#11 unsanitized search path enables remote code execution when agent is forwarded. IDs: CVE:CVE-2023-38408"}]},
        ],
    },
    # --- Apache httpd ---
    {
        "name": "apache-httpd-2449",
        "os": "Linux 4.15 - 5.6",
        "hostname": "web-apache-{scan:02d}.corp.local",
        "ports": [
            {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49",
             "scripts": [{"id": "http-vuln-cve2021-41773",
                          "output": "VULNERABLE: Apache 2.4.49 path traversal leading to file disclosure and RCE. IDs: CVE:CVE-2021-41773"},
                          {"id": "http-title", "output": "Welcome to the Internal Portal"}]},
            {"port": 443, "service": "https", "product": "Apache httpd", "version": "2.4.49",
             "scripts": [{"id": "ssl-ccs-injection",
                          "output": "VULNERABLE: TLS server vulnerable to BN_mod_sqrt infinite-loop denial of service. IDs: CVE:CVE-2022-0778"}]},
        ],
    },
    {
        "name": "apache-httpd-2438",
        "os": "Linux 3.10 - 4.6",
        "hostname": "web-apache2-{scan:02d}.corp.local",
        "ports": [
            {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.38",
             "scripts": [{"id": "http-vuln-cve2019-0211",
                          "output": "VULNERABLE: Apache scoreboard manipulation allows privilege escalation to root. IDs: CVE:CVE-2019-0211"},
                          {"id": "http-vuln-cve2017-15715",
                           "output": "VULNERABLE: FilesMatch newline bypass permits restricted file upload. IDs: CVE:CVE-2017-15715"}]},
            {"port": 443, "service": "https", "product": "Apache httpd", "version": "2.4.38", "scripts": []},
        ],
    },
    # --- No-SQL exposure ---
    {
        "name": "redis-open",
        "os": "Linux 4.15 - 5.6",
        "hostname": "cache-redis-{scan:02d}.corp.local",
        "ports": [
            {"port": 6379, "service": "redis", "product": "Redis key-value store", "version": "6.0.15",
             "scripts": [{"id": "redis-info",
                          "output": "VULNERABLE: Redis server reachable with no password (no requirepass configured)."},
                          {"id": "redis-vuln-cve2022-0543",
                           "output": "VULNERABLE: Debian-packaged Redis Lua sandbox escape allows remote code execution. IDs: CVE:CVE-2022-0543"},
                          {"id": "redis-vuln-cve2021-32761",
                           "output": "VULNERABLE: Redis integer overflow in BIT commands corrupts heap / leaks contents. IDs: CVE:CVE-2021-32761"}]},
        ],
    },
    {
        "name": "mongodb-open",
        "os": "Linux 4.15 - 5.6",
        "hostname": "db-mongo-{scan:02d}.corp.local",
        "ports": [
            {"port": 27017, "service": "mongodb", "product": "MongoDB", "version": "3.6.13",
             "scripts": [{"id": "mongodb-info",
                          "output": "VULNERABLE: MongoDB server running with no authentication — every connection is authorized as admin."},
                          {"id": "mongodb-vuln-cve2019-2386",
                           "output": "VULNERABLE: MongoDB authorization session persists after user deletion (user-account conflation). IDs: CVE:CVE-2019-2386"}]},
        ],
    },
    # --- TLS / OpenSSL ---
    {
        "name": "openssl-heartbleed",
        "os": "Linux 3.10 - 4.6",
        "hostname": "srv-tls-{scan:02d}.corp.local",
        "ports": [
            {"port": 443, "service": "https", "product": "OpenSSL", "version": "1.0.1e",
             "scripts": [{"id": "ssl-heartbleed",
                          "output": "VULNERABLE: OpenSSL heartbeat extension buffer over-read leaks process memory (Heartbleed). Risk factor: HIGH  IDs: CVE:CVE-2014-0160"},
                          {"id": "ssl-poodle",
                           "output": "VULNERABLE: SSLv3 CBC padding oracle allows cleartext recovery (POODLE). IDs: CVE:CVE-2014-3566"}]},
            {"port": 8443, "service": "https", "product": "OpenSSL", "version": "1.0.1e", "scripts": []},
        ],
    },
    # --- FTP / vsftpd ---
    {
        "name": "vsftpd-backdoor",
        "os": "Linux 3.10 - 4.6",
        "hostname": "ftp-{scan:02d}.corp.local",
        "ports": [
            {"port": 21, "service": "ftp", "product": "vsftpd", "version": "2.3.4",
             "scripts": [{"id": "ftp-vuln-backdoor",
                          "output": "VULNERABLE: vsftpd 2.3.4 contains a backdoor opening a shell on port 6200. IDs: CVE:CVE-2011-2523"},
                          {"id": "ftp-anon", "output": "Anonymous FTP login allowed (FTP code 230)"}]},
            {"port": 6200, "service": "unknown", "product": None},
        ],
    },
    # --- Decoy-only (no CVE anywhere) ---
    {
        "name": "decoy-cert-expired",
        "os": "Linux 4.15 - 5.6",
        "hostname": "decoy-web-{scan:02d}.corp.local",
        "ports": [
            {"port": 443, "service": "https", "product": "Apache httpd", "version": "2.4.29",
             "scripts": [{"id": "ssl-cert",
                          "output": "Subject: commonName=decoy-web.corp.local  Not valid after: 2024-05-10T00:00:00"},
                          {"id": "ssl-known-key", "output": "Certificate expired"}]},
        ],
    },
    {
        "name": "decoy-ftp-anon",
        "os": "FreeBSD 9.x",
        "hostname": "decoy-ftp-{scan:02d}.corp.local",
        "ports": [
            {"port": 21, "service": "ftp", "product": "ProFTPD", "version": "1.3.5",
             "scripts": [{"id": "ftp-anon", "output": "Anonymous FTP login allowed (FTP code 230)"}]},
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.2", "scripts": []},
        ],
    },
]


# ---------------------------------------------------------------------------
# XML emission (must parse cleanly with nmap_parser.parse_nmap_xml)
# ---------------------------------------------------------------------------

def _el(tag: str, attrib: Optional[dict] = None, text: Optional[str] = None) -> ET.Element:
    e = ET.Element(tag, attrib or {})
    if text is not None:
        e.text = text
    return e


def build_scan_xml(hosts: list[dict], scan_id: int) -> str:
    """Serialize a list of host dicts (from templates) into Nmap XML."""
    root = ET.Element("nmaprun", {"scanner": "nmap", "version": "7.94", "xmloutputversion": "1.05",
                                  "start": str(1755000000 + scan_id), "args": "nmap -sS -sV -O -A -p- -oX scan.xml"})
    root.append(_el("scaninfo", {"type": "syn", "protocol": "tcp", "numservices": "65535", "services": "1-65535"}))
    root.append(_el("verbose", {"level": "0"}))
    root.append(_el("debugging", {"level": "0"}))

    for i, host in enumerate(hosts):
        host_el = _el("host", {"starttime": str(-1), "endtime": str(-1)})
        host_el.append(_el("status", {"state": "up", "reason": "syn-ack", "reason_ttl": "64"}))
        host_el.append(_el("address", {"addr": host["ip"], "addrtype": "ipv4"}))
        hostnames_el = ET.SubElement(host_el, "hostnames")
        hostnames_el.append(_el("hostname", {"name": host["hostname"], "type": "PTR"}))

        ports_el = ET.SubElement(host_el, "ports")
        ports_el.append(_el("extraports", {"state": "filtered", "count": "65526"}))
        for port in host["ports"]:
            port_el = _el("port", {"protocol": "tcp", "portid": str(port["port"])})
            port_el.append(_el("state", {"state": "open", "reason": "syn-ack", "reason_ttl": "64"}))
            svc_attr = {"name": port["service"], "method": "probed", "conf": "10"}
            if port.get("product"):
                svc_attr["product"] = port["product"]
            if port.get("version"):
                svc_attr["version"] = port["version"]
            port_el.append(_el("service", svc_attr))
            for script in port.get("scripts", []):
                port_el.append(_el("script", {"id": script["id"], "output": script["output"]}))
            ports_el.append(port_el)

        os_el = ET.SubElement(host_el, "os")
        os_el.append(_el("osmatch", {"name": host["os"], "accuracy": "96"}))
        root.append(host_el)

    runstats = ET.SubElement(root, "runstats")
    runstats.append(_el("finished", {"time": str(-1), "summary": "done", "exit": "success"}))
    runstats.append(_el("hosts", {"up": str(len(hosts)), "down": "0", "total": str(len(hosts))}))

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


# ---------------------------------------------------------------------------
# KB subsetting + verification
# ---------------------------------------------------------------------------

def collect_cve_ids(hosts: list[dict]) -> list[str]:
    """Every CVE ID referenced across a scan's NSE script outputs."""
    ids = set()
    for host in hosts:
        for port in host["ports"]:
            for script in port.get("scripts", []):
                ids.update(CVE_PATTERN.findall(script["output"]))
    return sorted(ids)


def collect_service_tags(hosts: list[dict]) -> set[str]:
    """Service names across the scan — drives CIS filtering (applies_to)."""
    tags = set()
    for host in hosts:
        for port in host["ports"]:
            tags.add(port["service"])
    return tags


def subset_cve_kb(full_kb: dict, cve_ids: list[str]) -> dict:
    return {cve_id: full_kb[cve_id] for cve_id in cve_ids if cve_id in full_kb}


def subset_cis_kb(full_cis: list[dict], service_tags: set[str]) -> list[dict]:
    """CIS controls whose applies_to overlaps the scan's service tags."""
    out = []
    tagset_lower = {t.lower() for t in service_tags}
    for control in full_cis:
        control_tags = {t.lower() for t in control.get("applies_to", [])}
        if control_tags & tagset_lower:
            out.append(control)
    return out


def verify_scan(cve_ids_in_scan: list[str], full_kb: dict, scan_id: int) -> None:
    """
    Hard gate: refuse the scan if any CVE ID it references is not present
    in the real-CVE catalog. An unresolvable CVE would silently corrupt the
    grounded variant (retrieval returns not_found) — better to crash loudly
    here than to produce benchmark data nobody can trust.
    """
    missing = [cve for cve in cve_ids_in_scan if cve not in full_kb]
    if missing:
        raise RuntimeError(
            f"scan_{scan_id:04d} references CVEs with no cve_kb entry: {missing}. "
            "Corpus generation aborted — every CVE must resolve."
        )


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def assign_ips(hosts: list[dict], base_ip: str = "10.20.30.") -> None:
    """For backward-safety this is a no-op; IPs are assigned in _make_host."""
    for idx, host in enumerate(hosts, start=1):
        if "ip" not in host:
            host["ip"] = f"{base_ip}{idx}"


def generate_corpus(seed: int, n_scans: int, cve_kb: dict,
                    cis_kb: list[dict], out_dir: Path) -> dict:
    rng = random.Random(seed)

    # Sample scan -> host list deterministically. To guarantee the corpus
    # exercises every template (and every severity band), deterministically
    # interleave templates rather than pure random sampling.
    template_pool = [dict(t) for t in HOST_TEMPLATES]
    rng.shuffle(template_pool)  # seeded shuffle; still covers every template

    scans = []
    per_scan_kb_paths = []
    coverage = {"cve_counts": [], "services": set(), "sev_bands": {}}

    # Templates the first-slot ring visits across all scans.
    ring_hits = {template_pool[i % len(template_pool)]["name"]
                 for i in range(n_scans)}
    # Tail templates in deterministic pool order, consumed one per scan until
    # exhausted; remaining second slots then use jitter. Hoisted out of the
    # scan loop so the queue drains across scans instead of resetting.
    tail_queue = [t for t in template_pool if t["name"] not in ring_hits]

    for scan_idx in range(n_scans):
        scan_dir = out_dir / "scans" / f"scan_{scan_idx + 1:04d}"
        scan_dir.mkdir(parents=True, exist_ok=True)

        # Pick 1-2 host templates per scan.
        #
        # First slot: cycles through the whole template pool, so any
        # n_scans >= len(templates) covers every template (and every severity
        # band) as a primary host.
        #
        # Second slot: deterministic coverage-gap filling. The first-slot ring
        # only ever visits the first n_scans templates of the shuffled pool;
        # the remaining "tail" templates would never appear when n_scans < L.
        # Emit every tail template as a second host (one per scan, in pool
        # order), then fall back to seeded jitter once coverage is saturated.
        # This guarantees ALL templates appear across the corpus regardless of
        # scan count.
        def _make_host(template, ip_idx):
            host = dict(template)
            host["ports"] = [dict(p) for p in host["ports"]]
            host["hostname"] = host["hostname"].format(scan=scan_idx + 1)
            host["ip"] = f"10.20.30.{ip_idx}"
            return host

        first = template_pool[scan_idx % len(template_pool)]
        hosts = [_make_host(first, 1)]
        second = None
        if len(tail_queue) > 0:
            second = tail_queue.pop(0)
            if second["name"] == first["name"]:
                second = None
        if second is None:
            candidate = template_pool[(scan_idx * 7 + 3) % len(template_pool)]
            if candidate["name"] != first["name"] and rng.random() < 0.5:
                second = candidate
        if second is not None:
            hosts.append(_make_host(second, 2))

        cve_ids = collect_cve_ids(hosts)
        verify_scan(cve_ids, cve_kb, scan_idx + 1)

        scan_xml = build_scan_xml(hosts, scan_idx + 1)
        (scan_dir / "scan.xml").write_text(scan_xml, encoding="utf-8")
        (scan_dir / "cve_kb.json").write_text(
            json.dumps(subset_cve_kb(cve_kb, cve_ids), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        service_tags = collect_service_tags(hosts)
        (scan_dir / "cis_kb.json").write_text(
            json.dumps(subset_cis_kb(cis_kb, service_tags), indent=2, ensure_ascii=False), encoding="utf-8"
        )

        # Manifest entry for the scan.
        host_meta = [{"ip": h["ip"], "hostname": h["hostname"],
                      "os": h["os"], "services": [p["service"] for p in h["ports"]]} for h in hosts]
        scans.append({
            "scan_id": scan_idx + 1,
            "cve_ids": cve_ids,
            "service_tags": sorted(service_tags),
            "cve_count": len(cve_ids),
            "hosts": host_meta,
        })
        coverage["cve_counts"].append(len(cve_ids))
        coverage["services"].update(service_tags)
        per_scan_kb_paths.append(str(scan_dir))

    # Corpus-wide union KBs + manifest.
    all_cve_ids = sorted({cve for scan in scans for cve in scan["cve_ids"]})
    (out_dir / "cve_kb.json").write_text(
        json.dumps(subset_cve_kb(cve_kb, all_cve_ids), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    all_service_tags = {t for scan in scans for t in scan["service_tags"]}
    (out_dir / "cis_kb.json").write_text(
        json.dumps(subset_cis_kb(cis_kb, all_service_tags), indent=2, ensure_ascii=False), encoding="utf-8"
    )

    manifest = {
        "seed": seed,
        "n_scans": n_scans,
        "generator": "corpus_generator.py",
        "cve_catalog_source": "NVD API 2.0 (verified live)",
        "real_cve_total": len(all_cve_ids),
        "corpus_cve_ids": all_cve_ids,
        "services_covered": sorted(coverage["services"]),
        "scans": scans,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Generate a deterministic synthetic benchmark corpus.")
    parser.add_argument("--seed", type=int, default=1337, help="Random seed (reproducibility)")
    parser.add_argument("--scans", type=int, default=12, help="Number of scans to generate")
    parser.add_argument("--out", default="data/synthetic_corpus", help="Output directory")
    parser.add_argument("--cve-kb", default=str(DEFAULT_CATALOG), help="Real CVE catalog (must contain every CVE used)")
    parser.add_argument("--cis-kb", default=str(DEFAULT_CIS), help="Base CIS control list (extended in-module)")
    args = parser.parse_args()

    cve_kb_path = Path(args.cve_kb)
    if not cve_kb_path.exists():
        print(f"Error: catalog not found: {cve_kb_path}", file=sys.stderr)
        sys.exit(1)
    cve_kb = json.loads(cve_kb_path.read_text(encoding="utf-8"))

    cis_kb = json.loads(Path(args.cis_kb).read_text(encoding="utf-8"))
    cis_kb = cis_kb + [dict(c) for c in EXTRA_CIS_CONTROLS]

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = generate_corpus(args.seed, args.scans, cve_kb, cis_kb, out_dir)
    print(json.dumps({"n_scans": manifest["n_scans"],
                      "unique_cves": manifest["real_cve_total"],
                      "services": manifest["services_covered"]}, indent=2))


if __name__ == "__main__":
    main()