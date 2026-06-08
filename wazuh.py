"""
Wazuh Dashboard - Scrape ALL Agents (Ubuntu)
Optimized for 600+ machines - direct ID + fallback search
"""

import csv
import time
import sys
from datetime import datetime
from playwright.sync_api import sync_playwright

# ------------------------------------------------------------
#  CONFIG
# ------------------------------------------------------------
WAZUH_URL   = "https://wazuh-dash.inf.bankbazaar.com"
USERNAME    = "itsupport"
PASSWORD    = "r01ddl345"
HEADLESS    = False
DELAY_SEC   = 0.5
# ------------------------------------------------------------

CSV_HEADERS = [
    "Hostname", "ID", "Status", "IP Address", "Version", "Group",
    "Operating System", "Cluster Node", "Registration Date", "Last Keep Alive",
    "Vuln Critical", "Vuln High", "Vuln Medium", "Vuln Low",
    "SCA Policy", "SCA End Scan", "SCA Passed", "SCA Failed",
    "SCA Not Applicable", "SCA Score", "Scraped At", "Error"
]

# ------------------------------------------------------------
#  LOGIN
# ------------------------------------------------------------
def login(page):
    print("\n[+] Opening Wazuh login page...")
    page.goto(WAZUH_URL, wait_until="domcontentloaded")
    time.sleep(2)

    strategies = [
        ("input[data-test-subj='user-name']", "input[data-test-subj='password']", "button[data-test-subj='submit']"),
        ("#user-name", "#password", "button[type='submit']"),
        ("input[name='username']", "input[name='password']", "button[type='submit']"),
        ("input[name='user']", "input[name='password']", "button[type='submit']"),
        ("input[placeholder*='ser']", "input[placeholder*='ass']", "button[type='submit']"),
        ("input[id*='user']", "input[id*='pass']", "button[type='submit']"),
        ("input[type='text']:visible", "input[type='password']:visible", "button[type='submit']"),
    ]

    for user_sel, pass_sel, btn_sel in strategies:
        try:
            page.wait_for_selector(user_sel, timeout=4000, state="visible")
            print(f"   [+] Found login form using: {user_sel}")
            page.fill(user_sel, USERNAME)
            page.fill(pass_sel, PASSWORD)
            page.click(btn_sel)
            page.wait_for_url(lambda url: "login" not in url and "signin" not in url, timeout=15000)
            time.sleep(2)
            if page.query_selector("text=Application Not Found"):
                page.goto(f"{WAZUH_URL}/app/wz-home", wait_until="domcontentloaded")
                page.wait_for_load_state("networkidle", timeout=8000)
            return
        except Exception:
            continue
    raise Exception("Login failed")

# ------------------------------------------------------------
#  GET ALL AGENTS (correct column mapping)
# ------------------------------------------------------------
def get_all_agents(page):
    # Load the agents table
    for url in [f"{WAZUH_URL}/app/endpoints-summary", f"{WAZUH_URL}/app/wazuh#/agents"]:
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=20000)
            time.sleep(3)
            page.wait_for_selector(".euiTableRow, table tbody tr", timeout=15000)
            print(f"   [+] Loaded: {url}")
            break
        except Exception:
            continue
    else:
        raise Exception("Could not load agents table")

    # Debug: print first row cell texts
    cells = page.evaluate("""
        () => {
            const row = document.querySelector('.euiTableRow, table tbody tr');
            if (!row) return [];
            return Array.from(row.querySelectorAll('td')).map(c => c.innerText.trim());
        }
    """)
    print(f"   First row cells: {cells}")

    # Adjust these indices based on the printed cells:
    # Our observed: col0 = '', col1 = '006', col2 = 'BBDSK0390'
    id_col = 1      # column containing the agent ID
    name_col = 2    # column containing the hostname

    agents = page.evaluate(f"""
        () => {{
            const agents = [];
            const rows = document.querySelectorAll('.euiTableRow, table tbody tr');
            const idCol = {id_col};
            const nameCol = {name_col};
            rows.forEach(row => {{
                const cells = row.querySelectorAll('td');
                if (cells.length <= Math.max(idCol, nameCol)) return;
                const id = cells[idCol]?.innerText.trim() || '';
                const name = cells[nameCol]?.innerText.trim() || '';
                if (name && id && /^\\d+$/.test(id)) {{
                    agents.push({{ name: name, id: id }});
                }}
            }});
            return agents;
        }}
    """)

    if not agents:
        raise Exception("No agents extracted – check column indices")
    print(f"   [+] Extracted {len(agents)} agents")
    for a in agents[:5]:
        print(f"       Name: {a['name']}  |  ID: {a['id']}")
    return agents

# ------------------------------------------------------------
#  NAVIGATE TO AGENT DETAIL
# ------------------------------------------------------------
def navigate_to_agent_detail(page, agent_id):
    # URL pattern that worked with your OpenSearch Dashboards
    detail_url = f"{WAZUH_URL}/app/endpoints-summary?agentId={agent_id}"
    try:
        page.goto(detail_url, wait_until="domcontentloaded", timeout=10000)
        time.sleep(2)
        # Check if we landed on a valid agent detail page
        if page.query_selector(".euiDescriptionList__title, [data-test-subj*='agentId'], .wz-welcome-page-agent-info"):
            page.wait_for_load_state("networkidle", timeout=5000)
            return True
    except Exception:
        pass
    return False

# ------------------------------------------------------------
#  FALLBACK SEARCH (original working method)
# ------------------------------------------------------------
def navigate_by_search(page, hostname):
    print(f"     [!] Falling back to search for {hostname}")
    page.goto(f"{WAZUH_URL}/app/endpoints-summary", wait_until="domcontentloaded")
    time.sleep(2)
    # Find search box
    search_box = None
    for sel in ["input[placeholder*='earch']", "input[placeholder*='ilter']", "input[type='search']", ".euiFieldSearch"]:
        try:
            search_box = page.wait_for_selector(sel, timeout=3000)
            if search_box:
                break
        except Exception:
            continue
    if not search_box:
        return False
    search_box.fill("")
    search_box.type(hostname, delay=50)
    time.sleep(1)
    search_box.press("Enter")
    time.sleep(2)
    # Click on the matching row
    for sel in [f"//span[text()='{hostname}']", f"//a[text()='{hostname}']", f"//td[text()='{hostname}']", f"text={hostname}"]:
        try:
            el = page.wait_for_selector(sel, timeout=4000)
            if el:
                el.click()
                time.sleep(2)
                return True
        except Exception:
            continue
    return False

# ------------------------------------------------------------
#  EXTRACTION FUNCTIONS
# ------------------------------------------------------------
def extract_info_bar(page):
    result = {}
    try:
        result = page.evaluate("""
            () => {
                const data = {};
                const titles = document.querySelectorAll('.euiDescriptionList__title');
                const descs  = document.querySelectorAll('.euiDescriptionList__description');
                titles.forEach((t, i) => {
                    if (descs[i]) data[t.innerText.trim()] = descs[i].innerText.trim();
                });
                return data;
            }
        """)
        if result and len(result) > 2:
            return result
    except Exception:
        pass
    try:
        result2 = page.evaluate("""
            () => {
                const data = {};
                const fieldMap = {
                    'agentId': 'ID', 'agentStatus': 'Status', 'agentIp': 'IP address',
                    'agentVersion': 'Version', 'agentGroup': 'Group', 'agentGroups': 'Groups',
                    'agentOs': 'Operating system', 'agentNode': 'Cluster node',
                    'agentRegistrationDate': 'Registration date', 'agentLastKeepAlive': 'Last keep alive'
                };
                Object.entries(fieldMap).forEach(([subj, key]) => {
                    const el = document.querySelector(`[data-test-subj*="${subj}"]`);
                    if (el && el.innerText.trim()) data[key] = el.innerText.trim();
                });
                return data;
            }
        """)
        if result2:
            result.update(result2)
    except Exception:
        pass
    return result

def extract_vulnerabilities(page):
    try:
        return page.evaluate("""
            () => {
                const result = { critical:'', high:'', medium:'', low:'' };
                const items = document.querySelectorAll('.euiFlexItem, [class*="vuln"]');
                items.forEach(item => {
                    const text = item.innerText || '';
                    const num = text.match(/^(\\d+)/);
                    if (!num) return;
                    const lower = text.toLowerCase();
                    if (lower.includes('critical') && !result.critical) result.critical = num[1];
                    else if (lower.includes('high') && !result.high) result.high = num[1];
                    else if (lower.includes('medium') && !result.medium) result.medium = num[1];
                    else if (lower.includes('low') && !result.low) result.low = num[1];
                });
                return result;
            }
        """)
    except Exception:
        return {"critical":"","high":"","medium":"","low":""}

def extract_sca(page):
    try:
        return page.evaluate("""
            () => {
                const result = { policy:'', end_scan:'', passed:'', failed:'', not_applicable:'', score:'' };
                const rows = document.querySelectorAll('table tr');
                rows.forEach(row => {
                    const cells = row.querySelectorAll('td');
                    if (cells.length >= 5 && cells[0].innerText.trim() && !result.policy) {
                        result.policy = cells[0].innerText.trim();
                        result.end_scan = cells[1]?.innerText.trim() || '';
                        result.passed = cells[2]?.innerText.trim() || '';
                        result.failed = cells[3]?.innerText.trim() || '';
                        result.not_applicable = cells[4]?.innerText.trim() || '';
                        result.score = cells[5]?.innerText.trim() || '';
                    }
                });
                return result;
            }
        """)
    except Exception:
        return {"policy":"","end_scan":"","passed":"","failed":"","not_applicable":"","score":""}

def scrape_agent_details(page, hostname):
    data = {h: "" for h in CSV_HEADERS}
    data["Hostname"] = hostname
    data["Scraped At"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        info = extract_info_bar(page)
        data["ID"] = info.get("ID", "")
        data["Status"] = info.get("Status", "")
        data["IP Address"] = info.get("IP address", info.get("IP Address", ""))
        data["Version"] = info.get("Version", "")
        data["Group"] = info.get("Group", info.get("Groups", ""))
        data["Operating System"] = info.get("Operating system", info.get("OS", ""))
        data["Cluster Node"] = info.get("Cluster node", info.get("Node", ""))
        data["Registration Date"] = info.get("Registration date", "")
        data["Last Keep Alive"] = info.get("Last keep alive", "")
        vuln = extract_vulnerabilities(page)
        data["Vuln Critical"] = vuln.get("critical", "")
        data["Vuln High"] = vuln.get("high", "")
        data["Vuln Medium"] = vuln.get("medium", "")
        data["Vuln Low"] = vuln.get("low", "")
        sca = extract_sca(page)
        data["SCA Policy"] = sca.get("policy", "")
        data["SCA End Scan"] = sca.get("end_scan", "")
        data["SCA Passed"] = sca.get("passed", "")
        data["SCA Failed"] = sca.get("failed", "")
        data["SCA Not Applicable"] = sca.get("not_applicable", "")
        data["SCA Score"] = sca.get("score", "")
    except Exception as e:
        data["Error"] = str(e)
    return data

def format_txt_row(data):
    sep = "-" * 62
    lines = [sep, f"  ASSET      : {data['Hostname']}", f"  ID         : {data['ID']}",
             f"  Status     : {data['Status']}", f"  IP Address : {data['IP Address']}",
             f"  OS         : {data['Operating System']}", f"  Version    : {data['Version']}",
             f"  Group      : {data['Group']}", f"  Cluster    : {data['Cluster Node']}",
             f"  Reg. Date  : {data['Registration Date']}", f"  Last Alive : {data['Last Keep Alive']}",
             f"  -- Vulnerabilities ------------------------------",
             f"  Critical   : {data['Vuln Critical']}", f"  High       : {data['Vuln High']}",
             f"  Medium     : {data['Vuln Medium']}", f"  Low        : {data['Vuln Low']}",
             f"  -- SCA Latest Scan ------------------------------",
             f"  Policy     : {data['SCA Policy']}", f"  End Scan   : {data['SCA End Scan']}",
             f"  Passed     : {data['SCA Passed']}", f"  Failed     : {data['SCA Failed']}",
             f"  N/A        : {data['SCA Not Applicable']}", f"  Score      : {data['SCA Score']}",
             f"  Scraped At : {data['Scraped At']}"]
    if data.get("Error"):
        lines.append(f"  [!] Error    : {data['Error']}")
    lines.append(sep)
    return "\n".join(lines)

# ------------------------------------------------------------
#  MAIN
# ------------------------------------------------------------
def main():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_csv = f"all_agents_{timestamp}.csv"
    output_txt = f"all_agents_{timestamp}.txt"

    print(f"[+] Starting FULL AGENT SCRAPE")
    print(f"[+] Output -> {output_csv}  +  {output_txt}")
    print("=" * 62)

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=CSV_HEADERS).writeheader()
    with open(output_txt, "w", encoding="utf-8") as f:
        f.write(f"WAZUH ALL AGENTS SCRAPE REPORT\n")
        f.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 62 + "\n\n")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=HEADLESS, args=["--start-maximized", "--ignore-certificate-errors"])
        context = browser.new_context(viewport={"width": 1600, "height": 900}, ignore_https_errors=True)
        page = context.new_page()

        try:
            login(page)
        except Exception as e:
            print(f"\n[-] Login failed: {e}")
            browser.close()
            sys.exit(1)

        print("\n[+] Fetching all agents from the table...")
        agents = get_all_agents(page)

        if not agents:
            print("[-] No agents found. Exiting.")
            browser.close()
            sys.exit(1)

        print(f"\n[+] Starting scrape of {len(agents)} agents...")
        failed = []
        for i, agent in enumerate(agents, 1):
            name = agent['name']
            aid = agent['id']
            print(f"\n[{i}/{len(agents)}] -- {name} (ID: {aid})")

            # Try direct navigation first
            if navigate_to_agent_detail(page, aid):
                data = scrape_agent_details(page, name)
                print(f"     [+] Status: {data['Status']} | IP: {data['IP Address']}")
            else:
                # Fallback to search method (slower but works)
                if navigate_by_search(page, name):
                    data = scrape_agent_details(page, name)
                    print(f"     [+] (search) Status: {data['Status']} | IP: {data['IP Address']}")
                else:
                    data = {h: "" for h in CSV_HEADERS}
                    data["Hostname"] = name
                    data["Error"] = "Could not load agent detail (direct + search)"
                    data["Scraped At"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    failed.append(name)
                    print(f"     [-] Failed to load detail page")

            with open(output_csv, "a", newline="", encoding="utf-8") as f:
                csv.DictWriter(f, fieldnames=CSV_HEADERS).writerow(data)
            with open(output_txt, "a", encoding="utf-8") as f:
                f.write(format_txt_row(data) + "\n\n")

            time.sleep(DELAY_SEC)

        browser.close()

    print("\n" + "=" * 62)
    print(f"[+] COMPLETE — {len(agents)} agents processed")
    print(f"   Successful: {len(agents) - len(failed)}")
    print(f"   Failed    : {len(failed)}")
    if failed:
        print(f"   Failed list: {', '.join(failed[:20])}")
    print(f"\n[+] CSV : {output_csv}")
    print(f"[+] TXT : {output_txt}")
    print("=" * 62)

if __name__ == "__main__":
    main()