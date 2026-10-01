from playwright.sync_api import sync_playwright
import pathlib, time, json

# Edge files
edge_files = [
    ("edge_empty.xml", "data/sample_scans/edge_empty.xml"),
    ("edge_no_open_ports.xml", "data/sample_scans/edge_no_open_ports.xml"),
    ("edge_unknown_service.xml", "data/sample_scans/edge_unknown_service.xml"),
    ("quota_test.xml", "quota_test.xml"),  # will be created as 25 findings
    ("vsftpd_CVE-2011-2523.xml", "vsftpd_test.xml"),
]

# Create quota test file with 25 findings
if not pathlib.Path("quota_test.xml").exists():
    xml = '<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" version="7.94">'
    for i in range(25):
        xml += f'<host><status state="up"/><address addr="10.0.1.{i}" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.52"/></port></ports></host>'
    xml += '<runstats><hosts up="25" total="25"/></runstats></nmaprun>'
    pathlib.Path("quota_test.xml").write_text(xml)
    print("Created quota_test.xml with 25 hosts")

# Create vsftpd test if not exists
if not pathlib.Path("vsftpd_test.xml").exists():
    xml = '''<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" version="7.94"><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/><script id="ftp-vsftpd-backdoor" output="VULNERABLE: CVE-2011-2523 State: VULNERABLE IDs: CVE:CVE-2011-2523"/></port></ports></host></nmaprun>'''
    pathlib.Path("vsftpd_test.xml").write_text(xml)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()
    
    # Login
    print("=== Logging in at localhost:3000/login ===")
    page.goto("http://localhost:3000/login", wait_until="networkidle")
    page.wait_for_timeout(2000)
    # Try to find username input - Next.js login has placeholder "e.g. analyst"
    try:
        page.fill('input[placeholder*="analyst"]', 'admin')
        print("Filled username via placeholder")
    except:
        try:
            page.fill('input[name="username"]', 'admin')
            print("Filled username via name")
        except Exception as e:
            print(f"Failed to fill username: {e}")
            # Try to find any input
            inputs = page.locator('input')
            print(f"Found {inputs.count()} inputs")
            for i in range(inputs.count()):
                placeholder = inputs.nth(i).get_attribute('placeholder')
                typ = inputs.nth(i).get_attribute('type')
                print(f"  Input {i}: placeholder={placeholder}, type={typ}")
    
    try:
        page.fill('input[type="password"]', 'admin123')
        print("Filled password")
    except Exception as e:
        print(f"Failed to fill password: {e}")
    
    page.click('button:has-text("Sign in")')
    page.wait_for_timeout(3000)
    print(f"After login URL: {page.url}")
    if "login" in page.url:
        print("Still on login, maybe failed - content snippet:")
        print(page.content()[:500])
    else:
        print("Login succeeded")
    
    # Go to import page
    print("\n=== Going to /import ===")
    page.goto("http://localhost:3000/import", wait_until="networkidle")
    page.wait_for_timeout(2000)
    print(f"Import page URL: {page.url}")
    print(f"Contains 'Import Nmap scan': {'Import Nmap scan' in page.content()}")
    
    for filename, path in edge_files:
        print(f"\n=== Testing {filename} ===")
        if not pathlib.Path(path).exists():
            print(f"  File not found: {path}, skipping")
            continue
        
        # Ensure we're on import page
        page.goto("http://localhost:3000/import", wait_until="networkidle")
        page.wait_for_timeout(1000)
        
        # Find file input - it's hidden with sr-only, need to handle it
        # Try to make it visible or use set_input_files with force
        try:
            # The input is hidden, but we can still set files on it
            file_input = page.locator('input[type="file"]')
            # Wait for it to be attached
            file_input.wait_for(state="attached", timeout=5000)
            print(f"  Found file input, setting files: {path}")
            file_input.set_input_files(path)
            print(f"  Set input files: {path}")
            page.wait_for_timeout(500)
            
            # Check if file is selected (should show file name)
            content = page.content()
            if pathlib.Path(path).name in content:
                print(f"  File name appears in page: {pathlib.Path(path).name}")
            
            # Click Start assessment
            start_btn = page.locator('button:has-text("Start assessment")')
            if start_btn.count() > 0:
                print(f"  Found Start assessment button, clicking")
                start_btn.click()
                # Wait for processing to complete (up to 30 seconds for Gemini)
                print(f"  Waiting for processing (up to 30s)...")
                # Wait for either completed report or error
                try:
                    page.wait_for_selector('text=Live scan', timeout=30000)
                    print(f"  Found Live scan marker - completed")
                except:
                    print(f"  No Live scan marker yet, checking for other states")
                page.wait_for_timeout(2000)
                
                content = page.content()
                has_report = "Live scan" in content
                has_no_hosts = "No hosts found" in content
                has_no_findings = "Scan completed" in content and "no notable findings" in content
                has_hallucinated = "HALLUCINATED" in content
                has_quota = "quota" in content.lower() and "not synthesized" in content.lower()
                has_synthesis = "Gemini synthesis" in content or "plain_language_explanation" in content or "This finding exposes" in content
                
                print(f"  Has report (Live scan): {has_report}")
                print(f"  No hosts found: {has_no_hosts}")
                print(f"  No findings: {has_no_findings}")
                print(f"  Hallucinated badge: {has_hallucinated}")
                print(f"  Quota banner: {has_quota}")
                print(f"  Synthesis: {has_synthesis}")
                
                # Take screenshot
                screenshot_path = f"screenshot_{filename.replace('.xml','')}.png"
                page.screenshot(path=screenshot_path, full_page=True)
                print(f"  Screenshot saved: {screenshot_path}")
                
                if filename == "vsftpd_CVE-2011-2523.xml":
                    print(f"  Hallucination state for vsftpd: has_hallucinated={has_hallucinated} (should be False with synthetic KB, as CVE is grounded)")
                if "quota" in filename.lower():
                    print(f"  Quota state: has_quota_banner={has_quota}, has_not_synthesized={has_quota}")
            else:
                print(f"  Start assessment button not found")
                print(f"  Page content snippet: {page.content()[:500]}")
        except Exception as e:
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            # Try to take screenshot even on error
            try:
                page.screenshot(path=f"screenshot_{filename.replace('.xml','')}_error.png")
            except:
                pass
        
        page.wait_for_timeout(1000)
    
    browser.close()
    print("\n=== Done ===")
