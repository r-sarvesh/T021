from playwright.sync_api import sync_playwright
import pathlib, time

edge_files = [
    ("edge_empty.xml", "data/sample_scans/edge_empty.xml"),
    ("edge_no_open_ports.xml", "data/sample_scans/edge_no_open_ports.xml"),
    ("edge_unknown_service.xml", "data/sample_scans/edge_unknown_service.xml"),
    ("quota_test.xml", "quota_test.xml"),
    ("vsftpd_CVE-2011-2523.xml", "vsftpd_test.xml"),
]

# Create quota test file with 25 findings if not exists
if not pathlib.Path("quota_test.xml").exists():
    xml = '<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" version="7.94">'
    for i in range(25):
        xml += f'<host><status state="up"/><address addr="10.0.1.{i}" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.52"/></port></ports></host>'
    xml += '<runstats><hosts up="25" total="25"/></runstats></nmaprun>'
    pathlib.Path("quota_test.xml").write_text(xml)
    print("Created quota_test.xml")

if not pathlib.Path("vsftpd_test.xml").exists():
    xml = '''<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" version="7.94"><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/><script id="ftp-vsftpd-backdoor" output="VULNERABLE: CVE-2011-2523 State: VULNERABLE IDs: CVE:CVE-2011-2523"/></port></ports></host></nmaprun>'''
    pathlib.Path("vsftpd_test.xml").write_text(xml)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()
    
    # Login
    print("=== Logging in ===")
    page.goto("http://localhost:3000/login", wait_until="networkidle")
    page.wait_for_timeout(1000)
    page.fill('input[name="username"]', 'admin')
    page.fill('input[name="password"]', 'admin123')
    page.click('button:has-text("Sign in")')
    page.wait_for_timeout(2000)
    print(f"After login URL: {page.url}")
    
    for filename, path in edge_files:
        print(f"\n=== Testing {filename} ===")
        if not pathlib.Path(path).exists():
            print(f"  File not found: {path}")
            continue
        
        page.goto("http://localhost:3000/import", wait_until="networkidle")
        page.wait_for_timeout(1000)
        
        # Upload file - find the hidden file input
        file_input = page.locator('input[type="file"]')
        # Make it visible for playwright if needed, or use force
        try:
            file_input.set_input_files(path)
            print(f"  Set input files: {path}")
        except Exception as e:
            print(f"  set_input_files failed: {e}")
            # Try alternative: evaluate to make it visible
            page.evaluate("() => { const el = document.querySelector('input[type=\"file\"]'); if(el) { el.style.display='block'; el.style.opacity='1'; } }")
            page.wait_for_timeout(500)
            file_input.set_input_files(path)
            print(f"  Retry set_input_files: {path}")
        
        page.wait_for_timeout(500)
        
        # Click Start assessment
        try:
            page.click('button:has-text("Start assessment")')
            print(f"  Clicked Start assessment")
        except Exception as e:
            print(f"  Click failed: {e}")
            continue
        
        # Wait for processing to complete
        print(f"  Waiting for processing...")
        try:
            # Wait for either completed report or error
            page.wait_for_selector('text=Live scan', timeout=30000)
            print(f"  Found Live scan marker - completed")
        except:
            print(f"  No Live scan yet, checking for other states")
        
        page.wait_for_timeout(2000)
        content = page.content()
        
        # Check states
        has_report = "Live scan" in content
        has_no_hosts = "No hosts found" in content
        has_no_findings = "Scan completed" in content and "no notable findings" in content
        has_hallucinated = "HALLUCINATED" in content
        has_quota = "quota" in content.lower() and "not synthesized" in content.lower()
        has_synthesis = "Gemini synthesis" in content or "plain_language" in content.lower()
        
        print(f"  Has report (Live scan): {has_report}")
        print(f"  No hosts found: {has_no_hosts}")
        print(f"  No findings: {has_no_findings}")
        print(f"  Hallucinated badge: {has_hallucinated}")
        print(f"  Quota banner: {has_quota}")
        
        # Take screenshot
        screenshot_path = f"screenshot_{filename.replace('.xml','')}.png"
        page.screenshot(path=screenshot_path, full_page=True)
        print(f"  Screenshot saved: {screenshot_path}")
    
    browser.close()
    print("\n=== Done ===")
