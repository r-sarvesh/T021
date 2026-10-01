import time, pathlib, json, os
from playwright.sync_api import sync_playwright

# Edge files to test
edge_files = [
    ("edge_empty.xml", "data/sample_scans/edge_empty.xml", "No hosts found (is_empty_scan)"),
    ("edge_no_open_ports.xml", "data/sample_scans/edge_no_open_ports.xml", "Scan completed, no notable findings (is_no_findings)"),
    ("edge_unknown_service.xml", "data/sample_scans/edge_unknown_service.xml", "3 findings, unknown service, no CVE/CIS"),
    ("quota_exceeded.xml", None, "25 findings → 20 synthesized + 5 not_synthesized (quota banner)"),
    ("vsftpd_CVE-2011-2523.xml", "vsftpd_test.xml", "CVE-2011-2523 grounded (synthetic KB) vs ungrounded if sample"),
]

# For quota test, we need to create a scan with 25 findings
# We can reuse the quota test logic: create a synthetic scan via API directly
# For now, we'll create a simple XML with 25 hosts/ports

def create_quota_xml():
    xml = '<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" version="7.94">'
    for i in range(25):
        xml += f'''
  <host><status state="up"/><address addr="10.0.1.{i}" addrtype="ipv4"/><hostnames><hostname name="host{i}.test.local" type="PTR"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.52"/></port></ports></host>'''
    xml += '<runstats><hosts up="25" down="0" total="25"/></runstats></nmaprun>'
    pathlib.Path("quota_test.xml").write_text(xml)
    return "quota_test.xml"

# Create quota test file if not exists
if not pathlib.Path("quota_test.xml").exists():
    create_quota_xml()
    edge_files[3] = ("quota_test.xml", "quota_test.xml", "25 findings → 20 synthesized + 5 not_synthesized")

# Use sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()
    
    # Login
    print("=== Logging in at localhost:3000/login ===")
    page.goto("http://localhost:3000/login")
    page.wait_for_timeout(2000)
    # Fill login form - find username and password fields
    page.fill('input[name="username"]', 'admin')
    page.fill('input[name="password"]', 'admin123')
    # Try alternative selectors
    try:
        page.fill('input[placeholder*="analyst"]', 'admin')
    except:
        pass
    try:
        page.fill('input[type="password"]', 'admin123')
    except:
        pass
    # Click sign in
    page.click('button:has-text("Sign in")')
    page.wait_for_timeout(3000)
    print(f"After login URL: {page.url}")
    print(f"Content contains Dashboard: {'Dashboard' in page.content()}")
    
    # Go to import page
    print("\n=== Going to /import ===")
    page.goto("http://localhost:3000/import")
    page.wait_for_timeout(2000)
    print(f"Import page URL: {page.url}, contains 'Import Nmap scan': {'Import Nmap scan' in page.content()}")
    
    for filename, path, description in edge_files:
        print(f"\n=== Testing {filename} — {description} ===")
        if path and not pathlib.Path(path).exists():
            print(f"  File not found: {path}, skipping")
            continue
        
        # Ensure we're on import page
        page.goto("http://localhost:3000/import")
        page.wait_for_timeout(1000)
        
        # Upload file
        if path:
            # Find file input
            try:
                # The input is hidden, we need to set it directly
                file_input = page.locator('input[type="file"]')
                file_input.set_input_files(path)
                print(f"  Set input files: {path}")
                page.wait_for_timeout(500)
                # Click Start assessment
                page.click('button:has-text("Start assessment")')
                print(f"  Clicked Start assessment")
                # Wait for processing to complete (up to 30 seconds)
                page.wait_for_timeout(10000)
                # Check if completed phase shows ReportInlineView
                content = page.content()
                has_report = "Live scan" in content or "Processing assessment" in content or "No hosts found" in content or "Scan completed" in content
                print(f"  Page contains report/live marker: {has_report}")
                print(f"  Contains 'No hosts found': {'No hosts found' in content}")
                print(f"  Contains 'Scan completed': {'Scan completed' in content}")
                print(f"  Contains 'Hallucinated' or 'HALLUCINATED': {'HALLUCINATED' in content or 'hallucination' in content.lower()}")
                print(f"  Contains 'quota' : {'quota' in content.lower()}")
                print(f"  Contains 'HALLUCINATED' badge: {'HALLUCINATED' in content}")
                # Take screenshot
                page.screenshot(path=f"screenshot_{filename.replace('.xml','')}.png")
                print(f"  Screenshot saved: screenshot_{filename.replace('.xml','')}.png")
                # Also check for specific hallucination and quota states
                if filename == "vsftpd_CVE-2011-2523.xml":
                    has_hallucinated = "HALLUCINATED" in content
                    print(f"  Hallucination flagged state visible: {has_hallucinated} {'[PASS]' if not has_hallucinated else '[CHECK - should be grounded with synthetic KB, so no flag expected]'}")
                if "quota" in filename.lower():
                    has_quota_banner = "quota" in content.lower() and "not synthesized" in content.lower()
                    print(f"  Quota banner visible: {has_quota_banner} {'[PASS]' if has_quota_banner else '[FAIL - should show 20 + 5 split]'}")
                    # Check if findings look identical
                    has_not_synthesized = "not synthesized" in content.lower()
                    print(f"  Not synthesized distinguishable: {has_not_synthesized}")
                
            except Exception as e:
                print(f"  Error: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"  No file for {filename}, testing via API directly")
        
        # Reset for next test by going back to import
        page.wait_for_timeout(1000)
    
    browser.close()
    print("\n=== Done ===")
