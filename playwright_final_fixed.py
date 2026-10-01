from playwright.sync_api import sync_playwright
import pathlib, time

edge_files = [
    ("edge_empty.xml", "data/sample_scans/edge_empty.xml"),
    ("edge_no_open_ports.xml", "data/sample_scans/edge_no_open_ports.xml"),
    ("edge_unknown_service.xml", "data/sample_scans/edge_unknown_service.xml"),
    ("quota_test.xml", "quota_test.xml"),
    ("vsftpd_CVE-2011-2523.xml", "vsftpd_test.xml"),
]
# Ensure quota_test.xml exists
if not pathlib.Path("quota_test.xml").exists():
    xml = '<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" version="7.94">'
    for i in range(25):
        xml += f'<host><status state="up"/><address addr="10.0.1.{i}" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.52"/></port></ports></host>'
    xml += '<runstats><hosts up="25" total="25"/></runstats></nmaprun>'
    pathlib.Path("quota_test.xml").write_text(xml)
if not pathlib.Path("vsftpd_test.xml").exists():
    xml = '''<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" version="7.94"><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/><script id="ftp-vsftpd-backdoor" output="VULNERABLE: CVE-2011-2523 State: VULNERABLE IDs: CVE:CVE-2011-2523"/></port></ports></host></nmaprun>'''
    pathlib.Path("vsftpd_test.xml").write_text(xml)

# Also test demo_test_small.xml for manual check
demo_small = "demo_test_small.xml"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()
    
    # Login
    print("=== Logging in at localhost:3000/login ===")
    page.goto("http://localhost:3000/login", wait_until="networkidle")
    page.wait_for_timeout(1000)
    page.fill('input[name="username"]', 'admin')
    page.fill('input[name="password"]', 'admin123')
    page.click('button:has-text("Sign in")')
    page.wait_for_timeout(3000)
    print(f"After login URL: {page.url}")
    
    # Test each edge file
    for filename, path in edge_files:
        print(f"\n=== Testing {filename} ===")
        if not pathlib.Path(path).exists():
            print(f"  File not found: {path}")
            continue
        page.goto("http://localhost:3000/import", wait_until="networkidle")
        page.wait_for_timeout(1000)
        # Use visible workaround for hidden sr-only input
        try:
            page.evaluate('''() => {
                const el = document.querySelector('input[type="file"]');
                if(el) {
                    el.style.display = 'block';
                    el.style.opacity = '1';
                    el.style.position = 'static';
                    el.style.width = '100px';
                    el.style.height = '20px';
                    el.classList.remove('sr-only');
                }
            }''')
            page.wait_for_timeout(300)
            file_input = page.locator('input[type="file"]')
            file_input.set_input_files(path)
            print(f"  Set input files: {path}")
        except Exception as e:
            print(f"  set_input_files failed: {e}")
            continue
        page.wait_for_timeout(500)
        # Click Start assessment
        try:
            page.locator('button:has-text("Start assessment")').click()
            print(f"  Clicked Start assessment")
        except Exception as e:
            print(f"  Click failed: {e}")
            continue
        # Wait for processing to complete
        print(f"  Waiting for processing...")
        try:
            page.wait_for_selector('text=Live scan', timeout=40000)
            print(f"  Found Live scan marker - completed")
        except:
            print(f"  No Live scan yet, checking for other states")
        page.wait_for_timeout(2000)
        content = page.content()
        has_report = "Live scan" in content
        has_no_hosts = "No hosts found" in content
        has_no_findings = "Scan completed" in content and "no notable findings" in content
        has_hallucinated = "HALLUCINATED" in content
        has_quota = "quota" in content.lower() and "not synthesized" in content.lower()
        print(f"  Has report (Live scan): {has_report}")
        print(f"  No hosts found: {has_no_hosts}")
        print(f"  No findings: {has_no_findings}")
        print(f"  Hallucinated badge: {has_hallucinated}")
        print(f"  Quota banner: {has_quota}")
        screenshot_path = f"screenshot_{filename.replace('.xml','')}.png"
        page.screenshot(path=screenshot_path, full_page=True)
        print(f"  Screenshot saved: {screenshot_path}")
    
    # Manual check: demo_test_small.xml
    print(f"\n=== Manual check: demo_test_small.xml ===")
    page.goto("http://localhost:3000/import", wait_until="networkidle")
    page.wait_for_timeout(1000)
    page.evaluate('''() => {
        const el = document.querySelector('input[type="file"]');
        if(el) {
            el.style.display = 'block';
            el.style.opacity = '1';
            el.style.position = 'static';
            el.style.width = '100px';
            el.style.height = '20px';
            el.classList.remove('sr-only');
        }
    }''')
    page.wait_for_timeout(300)
    file_input = page.locator('input[type="file"]')
    file_input.set_input_files(demo_small)
    print(f"  Set input files: {demo_small}")
    page.wait_for_timeout(500)
    page.locator('button:has-text("Start assessment")').click()
    print(f"  Clicked Start assessment for demo_test_small.xml")
    try:
        page.wait_for_selector('text=Live scan', timeout=40000)
        print(f"  Found Live scan marker")
    except:
        print(f"  No Live scan marker")
    page.wait_for_timeout(2000)
    content = page.content()
    print(f"  Has report: {'Live scan' in content}")
    print(f"  Has synthesis: {'Gemini synthesis' in content or 'plain_language' in content.lower() or 'This finding exposes' in content}")
    print(f"  Has hallucinated: {'HALLUCINATED' in content}")
    print(f"  Has quota: {'quota' in content.lower()}")
    page.screenshot(path="screenshot_demo_test_small.png", full_page=True)
    print(f"  Screenshot saved: screenshot_demo_test_small.png")
    # Also check old Jinja view for comparison
    print(f"\n=== Checking old Jinja view for demo_test_small.xml ===")
    # We need to get the report_id from the last upload - we can fetch via API
    import requests
    s = requests.Session()
    s.post('http://127.0.0.1:5000/login', data={'username':'admin','password':'admin123'})
    # Find the latest report via API
    # Use the report_id from the last upload - we need to capture it
    # For now, just check that the Flask report view would show similar content
    # We can fetch the last report via the API
    try:
        r = s.get('http://127.0.0.1:5000/report/upload', timeout=5)
        print(f"  Flask report upload page: {r.status_code}")
    except Exception as e:
        print(f"  Flask check error: {e}")
    
    browser.close()
    print("\n=== Done ===")
