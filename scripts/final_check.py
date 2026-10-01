import requests
BASE='http://127.0.0.1:5000'
s=requests.Session()
s.post(f'{BASE}/api/auth/login', json={'username':'admin','password':'admin123'})
r=s.post(f'{BASE}/api/auth/login', json={'username':'admin','password':'admin123'})
token=r.json()['token']
headers={'Authorization': f'Bearer {token}'}
r=requests.get(f'{BASE}/api/dashboard/summary', headers=headers)
j=r.json()
print(f"Dashboard API: scans {j['totalScans']} findings {j['totalFindings']} hosts {j['hostsAssessed']} backed {j['evidenceBacked']} coverage {round(j['evidenceBacked']/j['totalFindings']*100)}%")
print(f"Expected 14/58/9/51/88% - {'PASS' if j['totalScans']==14 and j['totalFindings']==58 and j['hostsAssessed']==9 and j['evidenceBacked']==51 else 'FAIL'}")
r=requests.get(f'{BASE}/api/scans', headers=headers)
scans=r.json()
print(f"Scans API: {len(scans)} scans")
for scan in scans:
    if scan['id']=='scan_0001':
        print(f"Scan 0001: hosts {scan['hostCount']} findings {scan['findingCount']} highest {scan['highestSeverity']} backed {scan['evidenceBacked']} [expected 2,6,critical,6]")
        break
print("All checks done")
