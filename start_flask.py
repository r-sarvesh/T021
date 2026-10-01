import os, subprocess, sys, time, pathlib

if not os.environ.get("GEMINI_API_KEY"):
    env_local = pathlib.Path(__file__).resolve().parent / ".env.local"
    if env_local.exists():
        for line in env_local.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

os.environ.setdefault("GEMINI_MODEL", "gemini-3.6-flash")
# Start Flask
proc = subprocess.Popen([sys.executable, "-u", "src/webapp.py"], cwd="D:/Downloads/op", env=os.environ.copy())
print(f"Started Flask PID {proc.pid}")
time.sleep(3)
# Test
import requests
BASE="http://127.0.0.1:5000"
try:
    s=requests.Session()
    s.post(f"{BASE}/login", data={"username":"admin","password":"admin123"}, timeout=5)
    print("login ok")
    data=pathlib.Path("sample_data/demo_scan.xml").read_bytes()
    print("uploading demo_scan 8 findings, expecting real Gemini now")
    r=s.post(f"{BASE}/report/upload", files={"scan_file":("demo_scan.xml", data, "text/xml")}, headers={"Accept":"application/json"}, timeout=120)
    print("upload", r.status_code)
    print(r.text[:500])
    if r.status_code==200:
        import json
        rid=r.json()["report_id"]
        print("report", rid)
        r2=s.get(f"{BASE}/report/{rid}/export", timeout=10)
        j=r2.json()
        print("synthesized", len(j["synthesized"]))
        for rec in j["synthesized"][:2]:
            print(rec["finding_ref"], rec["ok"], rec["parsed"].get("plain_language_explanation","")[:100])
        print("quota", j["quota_info"])
        print("validation", len(j["validation_flags"]))
except Exception as e:
    import traceback
    traceback.print_exc()
    print(e)
