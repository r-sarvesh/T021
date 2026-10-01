# Fix fixtures to exactly match required numbers
import pathlib, re

# Required totals
# Total scans: 14, Hosts: 9, Total findings: 58
# Critical: 8, High: 16, Medium: 12, Low: 22 (sums 58)
# Backed: 51, Unverified: 7 (sums 58), coverage 88% (51/58=87.9% -> 88%)
# Keep Scan 0001 as-is: 2 hosts, 6 findings, Critical, 100% (6 backed, 0 unverified, severity 2,1,2,1)

# Let's define 14 scans with the correct sums
# We have Scan 0001: 2 hosts, 6 findings, critical 2, high 1, medium 2, low 1, backed 6, missing 0
# Need remaining 13 scans to sum to: hosts 7 (9-2), findings 52 (58-6), critical 6 (8-2), high 15 (16-1), medium 10 (12-2), low 21 (22-1), backed 45 (51-6), missing 7 (7-0)

# Distribute remaining across 13 scans
# We'll create 13 scans with varying sizes to look realistic, but ensure sums

remaining_scans = [
    # id, name, filename, importedBy, hostCount, findingCount, highest, critical, high, medium, low, backed, missing
    ("scan-1042", "DMZ Perimeter Sweep", "dmz-perimeter-2026-08-14.xml", "Peter", 1, 7, "critical", 1, 2, 1, 3, 7, 0),
    ("scan-1043", "Internal App Tier", "internal-app-tier-2026-08-12.xml", "M. Lindqvist", 1, 8, "high", 0, 3, 2, 3, 7, 1),
    ("scan-1044", "Finance VLAN Audit", "finance-vlan-2026-08-09.xml", "Peter", 1, 6, "medium", 0, 1, 2, 3, 5, 1),
    ("scan-1045", "Lab Segment Scan", "lab-segment-2026-08-05.xml", "M. Lindqvist", 1, 5, "high", 1, 2, 1, 1, 4, 1),
    ("scan-1046", "DB Cluster Audit", "db-cluster-2026-08-04.xml", "Peter", 1, 6, "critical", 1, 2, 1, 2, 5, 1),
    ("scan-1047", "Web Tier Sweep", "web-tier-2026-08-03.xml", "M. Lindqvist", 1, 4, "high", 0, 2, 1, 1, 4, 0),
    ("scan-1048", "Core Switch Review", "core-switch-2026-08-02.xml", "Peter", 1, 3, "medium", 0, 0, 2, 1, 3, 0),
    ("scan-1039", "Edge Gateway Recheck", "edge-gateway-2026-08-16.xml", "M. Lindqvist", 0, 0, None, 0, 0, 0, 0, 0, 0), # processing, 0 findings, not counted in totals? But we need it for 14 scans count
    ("scan-1049", "Branch Office Scan", "branch-office-2026-08-01.xml", "M. Lindqvist", 0, 4, "medium", 1, 0, 1, 2, 3, 1),
    ("scan-1050", "DMZ Secondary", "dmz-secondary-2026-07-30.xml", "Peter", 0, 3, "high", 0, 1, 1, 1, 3, 0),
    ("scan-1051", "Test Lab", "test-lab-2026-07-28.xml", "M. Lindqvist", 0, 2, "low", 0, 0, 0, 2, 2, 0),
    ("scan-1052", "Staging Env", "staging-env-2026-07-25.xml", "Peter", 0, 0, None, 0, 0, 0, 0, 0, 0), # failed, 0
    ("scan-1053", "Legacy Segment", "legacy-segment-2026-07-20.xml", "M. Lindqvist", 0, 4, "high", 1, 2, 0, 1, 2, 2),
]

# Check sums for remaining + Scan 0001
# Scan 0001: 2 hosts, 6 findings, c2 h1 m2 l1, backed6
# Add them
total_hosts = 2 + sum(x[4] for x in remaining_scans)
total_findings = 6 + sum(x[5] for x in remaining_scans)
tot_c = 2 + sum(x[7] for x in remaining_scans)
tot_h = 1 + sum(x[8] for x in remaining_scans)
tot_m = 2 + sum(x[9] for x in remaining_scans)
tot_l = 1 + sum(x[10] for x in remaining_scans)
tot_b = 6 + sum(x[11] for x in remaining_scans)
tot_u = 0 + sum(x[12] for x in remaining_scans)
print(f"Hosts {total_hosts} Findings {total_findings} C{tot_c} H{tot_h} M{tot_m} L{tot_l} sum {tot_c+tot_h+tot_m+tot_l} Backed {tot_b} Unverified {tot_u} sum {tot_b+tot_u} coverage {round(tot_b/(tot_b+tot_u)*100) if tot_b+tot_u else 0}%")
# Should be 9,58,8,16,12,22,51,7,88%
# Currently we have hosts 9? Let's see: 2+1+1+1+1+1+1+1+0+0+0+0+0 = 9? Actually count: scan_0001 2, then 7 scans with 1 host each =7, plus 5 scans with 0 hosts =0, total 9. Good.
# Findings: 6+7+8+6+5+6+4+3+0+4+3+2+0+4 =58? Let's calculate: 6+7=13+8=21+6=27+5=32+6=38+4=42+3=45+0=45+4=49+3=52+2=54+0=54+4=58 correct.
# Critical: 2+1+0+0+1+1+0+0+0+1+0+0+0+1=7? Wait we need 8. Let's recalc: 2 (0001) +1 (1042)=3, +0(1043)=3, +0(1044)=3, +1(1045)=4, +1(1046)=5, +0(1047)=5, +0(1048)=5, +0(1039)=5, +1(1049)=6, +0(1050)=6, +0(1051)=6, +0(1052)=6, +1(1053)=7 -> need 1 more critical. So we need to add 1 critical somewhere, e.g., make 1047 critical 1 instead of 0.
# Let's adjust: make scan-1047 critical 1, high 1 (instead of 0,2) -> then critical becomes 8, high becomes 15? Need high 16, so need to keep high. Let's make 1047: critical 1, high 1, medium 1, low 1 (instead of 0,2,1,1) -> critical +1 (to 8), high -1 (to 15), need high 16, so need +1 high elsewhere. Make 1048: high 0 ->1, medium 2->1, low1->1 (no change high? Actually 1048 is 0,0,2,1 -> change to 0,1,1,1 => high +1 to 16, medium -1 to 12, low same). That fixes.
# Let's apply those fixes.

remaining_scans[5] = ("scan-1047", "Web Tier Sweep", "web-tier-2026-08-03.xml", "M. Lindqvist", 1, 4, "high", 1, 1, 1, 1, 4, 0) # was 0,2,1,1 -> now 1,1,1,1
remaining_scans[6] = ("scan-1048", "Core Switch Review", "core-switch-2026-08-02.xml", "Peter", 1, 3, "medium", 0, 1, 1, 1, 3, 0) # was 0,0,2,1 -> now 0,1,1,1

# Recalculate
tot_c = 2 + sum(x[7] for x in remaining_scans)
tot_h = 1 + sum(x[8] for x in remaining_scans)
tot_m = 2 + sum(x[9] for x in remaining_scans)
tot_l = 1 + sum(x[10] for x in remaining_scans)
print(f"After fix: C{tot_c} H{tot_h} M{tot_m} L{tot_l} sum {tot_c+tot_h+tot_m+tot_l}")
# Should be 8,16,12,22

# Now generate the file content
# Read the current fixtures template and replace the scans array
import pathlib
template = pathlib.Path("D:/Downloads/op/lib/api/fixtures.ts.bak").read_text()
# Find the scans array and replace
import re
scans_text = "export const scans: Scan[] = [\n"
scans_text += """  {
    id: 'scan_0001',
    name: 'Scan 0001',
    filename: 'scan_0001.xml',
    importedBy: 'Peter',
    importedAt: '2026-08-14T09:12:00Z',
    status: 'completed',
    hostCount: 2,
    findingCount: 6,
    highestSeverity: 'critical',
    severityCounts: { critical: 2, high: 1, medium: 2, low: 1 },
    evidenceBacked: 6,
    evidenceMissing: 0,
  },""" + "\n"
for id, name, filename, importedBy, hostCount, findingCount, highest, c, h, m, l, backed, missing in remaining_scans:
    highest_str = f"'{highest}'" if highest else "null"
    scans_text += f"""  {{
    id: '{id}',
    name: '{name}',
    filename: '{filename}',
    importedBy: '{importedBy}',
    importedAt: '2026-08-14T09:12:00Z',
    status: '{'completed' if findingCount>0 else 'processing' if id=='scan-1039' else 'failed' if id=='scan-1052' else 'completed'}',
    hostCount: {hostCount},
    findingCount: {findingCount},
    highestSeverity: {highest_str},
    severityCounts: {{ critical: {c}, high: {h}, medium: {m}, low: {l} }},
    evidenceBacked: {backed},
    evidenceMissing: {missing},
  }},
"""
scans_text += "]\n"

# Replace in template
new_text = re.sub(r"export const scans: Scan\[\] = \[.*?\];", scans_text, template, flags=re.S)
pathlib.Path("D:/Downloads/op/lib/api/fixtures.ts").write_text(new_text)
print("Wrote new fixtures")
# Verify
text = pathlib.Path("D:/Downloads/op/lib/api/fixtures.ts").read_text()
m=re.findall(r'severityCounts: \{ critical: (\d+), high: (\d+), medium: (\d+), low: (\d+) \}', text)
# Only count scans, not hosts
# Find scans section
scans_section = re.search(r"export const scans: Scan\[\] = \[(.*?)\];", text, re.S).group(1)
m2=re.findall(r'severityCounts: \{ critical: (\d+), high: (\d+), medium: (\d+), low: (\d+) \}', scans_section)
tot_c=sum(int(a) for a,b,c,d in m2)
tot_h=sum(int(b) for a,b,c,d in m2)
tot_m=sum(int(c) for a,b,c,d in m2)
tot_l=sum(int(d) for a,b,c,d in m2)
print(f"Final scans critical {tot_c} high {tot_h} medium {tot_m} low {tot_l} total {tot_c+tot_h+tot_m+tot_l}")
ev=re.findall(r'evidenceBacked: (\d+),\s+evidenceMissing: (\d+)', scans_section)
tot_b=sum(int(a) for a,b in ev)
tot_u=sum(int(b) for a,b in ev)
print(f"Backed {tot_b} Unverified {tot_u} total {tot_b+tot_u} coverage {round(tot_b/(tot_b+tot_u)*100) if tot_b+tot_u else 0}%")
print(f"Scans count {len(m2)}")
# Check Scan 0001 preserved
if "scan_0001" in text and "hostCount: 2" in text and "findingCount: 6" in text:
    print("Scan 0001 preserved: 2 hosts, 6 findings, critical, 100%")
