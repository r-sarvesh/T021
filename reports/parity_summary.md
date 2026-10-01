# Parity Summary

| Jinja | Next.js | Status | Detail |
|---|---|---|---|
| /login | /login | PASS | Flask reject:True accept:True / Next API reject:True accept:True / Next UI bad:True good:True |
| /dashboard | /dashboard | PASS | Flask {'scans': 43, 'findings': 271, 'hosts': 35, 'evidence_backed': 266, 'critical': 28, 'high': 29, 'medium': 13, 'low': 73, 'overall_risk': 'CRITICAL'} vs Next {'scans': 43, 'findings': 271, 'hosts': 35, 'evidence_backed': 266, 'critical': 28, 'high': 29, 'medium': 13, 'low': 73, 'overall_risk': 'CRITICAL'} => match; Next UI overview:False (overall_risk mapped) |
| /scans | /scans | PASS | 12 scans, first worst_band critical, evidence 6/0 / Next UI library:False |
| /scan/scan_0001 | /scans/scan_0001 | PASS | Flask HTML hosts~6 findings~6 / API hosts 2 findings 6 severities critical / Next UI has_detail:True / KNOWN-GAP: llm_exists/per-host toggle/cve_records_total not in Next (expected) |
| /scan/scan_0002 | /scans/scan_0002 | PASS | Flask HTML hosts~6 findings~10 / API hosts 2 findings 10 severities high / Next UI has_detail:True / KNOWN-GAP: llm_exists/per-host toggle/cve_records_total not in Next (expected) |
| /scan/scan_0003 | /scans/scan_0003 | PASS | Flask HTML hosts~6 findings~9 / API hosts 2 findings 9 severities critical / Next UI has_detail:True / KNOWN-GAP: llm_exists/per-host toggle/cve_records_total not in Next (expected) |
| /reports | /reports | KNOWN-GAP | Flask HTML has:True API reports 31 Next UI has_reports:True / KNOWN-GAP: PDF/JSON buttons missing in Next |
| /demo | /demo | PASS | Flask /demo/data 8 findings 2 unique CVE, Flask HTML 200 / Next UI has_demo:True hosts:True / Next JSON 8 |
| /benchmark | /benchmark | PASS | side CVE-2017-0143/0144 live_small 0/2 vs 2/2 corpus 0/58 / Next has_side:True live:True corpus:True |
| /import edge_empty | /import | PASS | Flask upload True is_empty:True id:dad9b86c7b364fc885e6822a4ed6842d / Next upload True is_empty:True id:4615fffaec794777a68874508ee7f5c0 / UI has_import:False |
| /import quota_test | /import | PASS | Flask quota {'requested': 25, 'quota_remaining': 20, 'quota_exceeded': True, 'synthesized': 20, 'skipped': 5, 'message': 'Daily Gemini quota (20/day) exceeded: requested 25, synthesized top 20 highest-severity findings, 5 not synthesized — daily quota reached. (using offline mock — no GEMINI_API_KEY)'} / Next quota {'requested': 25, 'quota_remaining': 20, 'quota_exceeded': True, 'synthesized': 20, 'skipped': 5, 'message': 'Daily Gemini quota (20/day) exceeded: requested 25, synthesized top 20 highest-severity findings, 5 not synthesized — daily quota reached. (using offline mock — no GEMINI_API_KEY)'} / both synthesized 20 skipped 5 |
| /import vsftpd | /import | PASS | Flask CVE:CVE-2011-2523 no_hallucinated:True / Next CVE:CVE-2011-2523 no_hallucinated:True |
| /audit-log | /audit-log | PASS | API admin 200 has_real:True len:124 / analyst none blocked:True / unauth 401 / UI admin table:True data:True / analyst blocked:True |
| /scan/<id>/pdf | (no Next route) | SKIP | not ported — no Next.js route yet (Flask scan_pdf renders PDF via weasyprint/reportlab) |
| /report/<id> permalink | (no Next permalink) | SKIP | no permalink route yet — Next only shows inline post-upload via ReportInlineView |
| /settings | /settings | SKIP | not implemented — stub page only |

**Totals:** PASS:12, KNOWN-GAP:1, SKIP:3 | Total:16