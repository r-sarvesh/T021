import requests, pathlib, json
BASE='http://127.0.0.1:5000'
s=requests.Session()
s.post(f'{BASE}/api/auth/login', json={'username':'admin','password':'admin123'})
r=s.post(f'{BASE}/api/auth/login', json={'username':'admin','password':'admin123'})
token=r.json()['token']
r=requests.get(f'{BASE}/api/dashboard/summary', headers={'Authorization': f'Bearer {token}'})
j=r.json()
print(f"Real dashboard: scans {j['totalScans']} findings {j['totalFindings']} hosts {j['hostsAssessed']} backed {j['evidenceBacked']} coverage {round(j['evidenceBacked']/j['totalFindings']*100) if j['totalFindings'] else 0}%")
print(f"Severity: {j['severityCounts']}")
real_scans=len(list(pathlib.Path('D:/Downloads/op/data/synthetic_corpus/scans').glob('scan_*')))
live=len(list(pathlib.Path('D:/Downloads/op/reports/live_reports').glob('*.json')))
# subtract quota file
live = live - 1 if (pathlib.Path('D:/Downloads/op/reports/live_reports/_quota.json').exists()) else live
print(f"Real: corpus {real_scans} + live {live} = {real_scans+live} scans (dashboard shows {j['totalScans']}, should be real, not hardcoded 14)")
if j['totalScans'] == real_scans+live:
    print("[PASS] Dashboard shows real computed numbers, not hardcoded 14")
else:
    print("[FAIL] Dashboard still hardcoded")
