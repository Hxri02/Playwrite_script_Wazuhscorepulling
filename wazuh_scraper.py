"""
╔══════════════════════════════════════════════════════════════╗
║          WAZUH DASHBOARD — ASSET BULK SCRAPER v2             ║
║          Playwright Script (Python 3.11)                     ║
╚══════════════════════════════════════════════════════════════╝
"""

import csv
import time
import os
import sys
from datetime import datetime
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

# ─────────────────────────────────────────────
#  CONFIG — Edit these before running
# ─────────────────────────────────────────────
WAZUH_URL   = "https://wazuh-dash.inf.bankbazaar.com"  # No trailing slash
USERNAME    = "itsupport"                           # ← Your Wazuh login ID
PASSWORD    = "r01ddl345"                           # ← Your Wazuh password
ASSETS_FILE = "assets.txt"                             # One hostname per line
# Use timestamped filenames to avoid "Permission denied" errors
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_CSV  = f"results_{timestamp}.csv"
OUTPUT_TXT  = f"results_{timestamp}.txt"
HEADLESS    = False   # False = see browser (recommended for first run)
DELAY_SEC   = 5       # Wait between each asset (target ~5s budget per asset)

# How long to wait for the agent-detail data (info bar/vulns/SCA) to actually
# populate after navigating to an agent. If it's still empty after this many
# seconds, the page is reloaded and we wait again — this fixes the
# "API failed to load on refresh" issue.
DATA_READY_TIMEOUT  = 3    # seconds to wait per attempt
MAX_RELOAD_ATTEMPTS = 1    # how many times to reload the page if data is empty
# ─────────────────────────────────────────────

CSV_HEADERS = [
    "Hostname", "ID", "Status", "IP Address", "Version", "Group",
    "Operating System", "Cluster Node", "Registration Date", "Last Keep Alive",
    "Vuln Critical", "Vuln High", "Vuln Medium", "Vuln Low",
    "SCA Policy", "SCA End Scan", "SCA Passed", "SCA Failed",
    "SCA Not Applicable", "SCA Score",
    "Scraped At", "Error"
]


def safe_text(page, selector, timeout=5000):
    """Safely get text content. Returns '' if not found."""
    try:
        el = page.wait_for_selector(selector, timeout=timeout, state="visible")
        return el.inner_text().strip() if el else ""
    except Exception:
        return ""


def login(page):
    """
    Login to Wazuh (OpenSearch Dashboards).
    Tries multiple selector strategies used across Wazuh versions.
    """
    print(f"\n🔐 Opening Wazuh login page...")
    page.goto(WAZUH_URL, wait_until="domcontentloaded")
    time.sleep(3)

    print(f"   Current URL: {page.url}")

    # ── Wazuh / OpenSearch Dashboards login selectors ──
    # Try each pair until one works
    login_strategies = [
        # Wazuh 4.x / OpenSearch Dashboards (most common)
        ("input[data-test-subj='user-name']",     "input[data-test-subj='password']",     "button[data-test-subj='submit']"),
        # Older Wazuh / Kibana-based
        ("#user-name",                             "#password",                             "button[type='submit']"),
        # Generic HTML name attributes
        ("input[name='username']",                 "input[name='password']",               "button[type='submit']"),
        ("input[name='user']",                     "input[name='password']",               "button[type='submit']"),
        # Placeholder-based
        ("input[placeholder*='ser']",              "input[placeholder*='ass']",            "button[type='submit']"),
        # ID-based
        ("input[id*='user']",                      "input[id*='pass']",                    "button[type='submit']"),
        # Any visible text inputs (last resort)
        ("input[type='text']:visible",             "input[type='password']:visible",       "button[type='submit']"),
    ]

    logged_in = False
    for user_sel, pass_sel, btn_sel in login_strategies:
        try:
            page.wait_for_selector(user_sel, timeout=5000, state="visible")
            print(f"   ✅ Found login form using: {user_sel}")

            page.fill(user_sel, USERNAME)
            time.sleep(0.5)
            page.fill(pass_sel, PASSWORD)
            time.sleep(0.5)
            page.click(btn_sel)

            # Wait for redirect away from login page
            # Handles both old (/app/wazuh) and new (/app/wz-home) Wazuh paths
            page.wait_for_url(
                lambda url: "login" not in url and "signin" not in url,
                timeout=20000
            )
            time.sleep(2)  # Let the SPA finish rendering
            # If we land on an "Application Not Found" page (old URL cached),
            # navigate explicitly to the new wz-home
            if page.query_selector("text=Application Not Found"):
                print("   ⚠️  Landed on old URL after login — navigating to wz-home…")
                page.goto(f"{WAZUH_URL}/app/wz-home", wait_until="domcontentloaded")
                page.wait_for_load_state("networkidle", timeout=10000)
            logged_in = True
            break
        except Exception:
            continue

    if not logged_in:
        # Last resort: dump what's on the page to help debug
        inputs = page.query_selector_all("input")
        print("\n   ⚠️  Could not find login form automatically.")
        print("   Inputs found on page:")
        for inp in inputs:
            try:
                print(f"     - type={inp.get_attribute('type')} "
                      f"name={inp.get_attribute('name')} "
                      f"id={inp.get_attribute('id')} "
                      f"placeholder={inp.get_attribute('placeholder')} "
                      f"data-test-subj={inp.get_attribute('data-test-subj')}")
            except Exception:
                pass
        raise Exception("Login failed — see input details above to fix selectors")

    time.sleep(3)
    print(f"   ✅ Login successful! URL: {page.url}")


def navigate_to_agent(page, hostname):
    """
    Navigate to the Wazuh agents list, search for hostname, and click it.
    Returns True if found, False if not.
    """
    print(f"\n  🔍 Searching: {hostname}")

    agent_list_urls = [
        f"{WAZUH_URL}/app/endpoints-summary",   # Wazuh 4.4+ / OpenSearch
        f"{WAZUH_URL}/app/wazuh#/agents",        # Wazuh 4.x / Kibana
        f"{WAZUH_URL}/app/wazuh#/agents-preview",
    ]

    # NOTE: Do NOT use go_back() or URL-matching to skip the goto().
    # In Wazuh's SPA the URL still contains "endpoints-summary" even on the
    # agent DETAIL page, so those checks give false-positives and the search
    # box is never found, causing a 5s timeout on every asset after the first.
    # After the first page load the browser caches JS/CSS, so subsequent
    # goto() calls with domcontentloaded are fast (~1-2s).
    search_selector = (
        "input[placeholder*='earch'], "
        "input[placeholder*='ilter'], "
        "input[placeholder*='agent'], "
        ".euiFieldSearch, "
        "input[data-test-subj*='search'], "
        "input[aria-label*='earch'], "
        "input[type='search']"
    )

    # ── Step 1: navigate to agents list and wait for search box ──
    search_box = None
    for url in agent_list_urls:
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
        except Exception as e:
            print(f"     ⚠️  Failed to load {url}: {e}")
            continue

        if page.query_selector("text=Application Not Found"):
            print(f"     ⚠️  Application Not Found at {url}, trying next…")
            continue

        # Use the search box appearing as the readiness signal — no fixed sleep.
        # Second+ visits load from browser cache so this resolves in ~0.5-1s.
        try:
            search_box = page.wait_for_selector(search_selector, timeout=6000, state="visible")
            print(f"     ✅ Agents page + search box ready")
            break
        except Exception:
            print(f"     ⚠️  Search box not found at {url}, trying next…")
            continue

    if not search_box:
        print(f"     ❌ Could not reach agents list with a search box")
        return False

    # ── Step 2: search for the hostname ──
    search_box.click(click_count=3)
    search_box.fill("")
    search_box.type(hostname, delay=40)
    time.sleep(0.3)
    search_box.press("Enter")
    time.sleep(0.4)

    # ── Click the matching agent row ──
    # Combined into ONE XPath union ( | ) so Playwright resolves on the
    # first match instead of trying each pattern sequentially.
    click_xpath = (
        f"//span[normalize-space(text())='{hostname}'] | "
        f"//a[normalize-space(text())='{hostname}'] | "
        f"//td[normalize-space(text())='{hostname}'] | "
        f"//div[normalize-space(text())='{hostname}']"
    )
    click_selectors = [click_xpath, f"text={hostname}"]

    for sel in click_selectors:
        try:
            el = page.wait_for_selector(sel, timeout=2500)
            if el:
                el.click()
                # Wait for agent detail panel — any of these confirm the detail page loaded.
                # Combined into ONE selector so Playwright returns as soon as the FIRST
                # one appears, instead of checking each candidate sequentially
                # (which could take up to 6 selectors x 6s = 36s in the worst case).
                detail_selector = (
                    ".euiDescriptionList__title, "          # info bar loaded
                    "[data-test-subj*='agentId'], "         # agent ID field
                    "[data-test-subj*='agentStatus'], "     # agent status badge
                    ".wz-welcome-page-agent-info"           # Wazuh welcome panel
                )
                detail_loaded = False
                try:
                    page.wait_for_selector(detail_selector, timeout=4000, state="visible")
                    detail_loaded = True
                except Exception:
                    pass
                if not detail_loaded:
                    # Final fallback: short settle pause instead of networkidle,
                    # which rarely fires on Wazuh's continuously-polling SPA
                    time.sleep(1)
                time.sleep(0.3)
                print(f"     ✅ Opened agent page for {hostname}")
                return True
        except Exception:
            continue

    print(f"     ❌ {hostname} not found in results")
    return False


def extract_info_bar(page):
    """
    Extract the top info bar fields using multiple strategies.
    Covers Wazuh 4.x (Kibana) through 4.4+ (OpenSearch Dashboards).
    Returns a dict with all field values.
    """
    result = {}

    # ── Strategy 1: EUI Description List (most common across all versions) ──
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
            return result   # got something useful
    except Exception as e:
        print(f"       Info bar S1 error: {e}")

    if len(result) > 2:
        return result

    # ── Strategy 2: data-test-subj attributes (Wazuh 4.4+ OpenSearch) ──
    try:
        result2 = page.evaluate("""
            () => {
                const data = {};
                // Wazuh 4.4+ uses data-test-subj for agent detail fields
                const fieldMap = {
                    'agentId':                'ID',
                    'agentStatus':            'Status',
                    'agentIp':                'IP address',
                    'agentVersion':           'Version',
                    'agentGroup':             'Group',
                    'agentGroups':            'Groups',
                    'agentOs':                'Operating system',
                    'agentOsPlatform':        'Operating system',
                    'agentNode':              'Cluster node',
                    'agentClusterNode':       'Cluster node',
                    'agentRegistrationDate':  'Registration date',
                    'agentLastKeepAlive':     'Last keep alive',
                };
                Object.entries(fieldMap).forEach(([subj, key]) => {
                    const el = document.querySelector(`[data-test-subj*="${subj}"]`);
                    if (el && el.innerText.trim()) data[key] = el.innerText.trim();
                });
                return data;
            }
        """)
        if result2 and len(result2) > 0:
            result.update(result2)
    except Exception as e:
        print(f"       Info bar S2 error: {e}")

    if len(result) > 2:
        return result

    # ── Strategy 3: wz-stat / React props inspection ──
    try:
        result3 = page.evaluate("""
            () => {
                const data = {};
                // wz-stat angular/react components used in some Wazuh versions
                document.querySelectorAll('wz-stat').forEach(el => {
                    const lbl = el.getAttribute('label') || el.querySelector('[class*="label"]')?.innerText;
                    const val = el.getAttribute('value') || el.querySelector('[class*="value"]')?.innerText;
                    if (lbl && val) data[lbl.trim()] = val.trim();
                });
                // Also try euiStat components
                document.querySelectorAll('.euiStat').forEach(el => {
                    const lbl = el.querySelector('.euiStat__title');
                    const val = el.querySelector('.euiStat__description');
                    if (lbl && val) data[val.innerText.trim()] = lbl.innerText.trim();
                });
                return data;
            }
        """)
        if result3 and len(result3) > 0:
            result.update(result3)
    except Exception as e:
        print(f"       Info bar S3 error: {e}")

    if len(result) > 2:
        return result

    # ── Strategy 4: Broad key-value scan of entire agent header/overview area ──
    try:
        result4 = page.evaluate("""
            () => {
                const data = {};
                // Look for any flex panels in the header region that contain label+value pairs
                const containers = document.querySelectorAll(
                    '.wz-welcome-page-agent-info, ' +
                    '[class*="agent-detail"], [class*="agentDetail"], ' +
                    '[class*="agent-info"], [class*="agentInfo"], ' +
                    '.euiPanel .euiFlexGroup, ' +
                    '.euiPageBody .euiFlexGroup'
                );
                containers.forEach(container => {
                    const titles = container.querySelectorAll('.euiDescriptionList__title');
                    const descs  = container.querySelectorAll('.euiDescriptionList__description');
                    titles.forEach((t, i) => {
                        if (descs[i] && t.innerText.trim())
                            data[t.innerText.trim()] = descs[i].innerText.trim();
                    });
                });
                return data;
            }
        """)
        if result4 and len(result4) > 0:
            result.update(result4)
    except Exception as e:
        print(f"       Info bar S4 error: {e}")

    # ── Strategy 5: Full-page label scan — last resort ──
    if len(result) == 0:
        try:
            result5 = page.evaluate("""
                () => {
                    const data = {};
                    // Known exact label texts used in Wazuh agent detail
                    const labels = [
                        'ID', 'Status', 'IP address', 'Version', 'Groups', 'Group',
                        'Operating system', 'Cluster node', 'Registration date', 'Last keep alive',
                        'OS', 'Node', 'Agent ID', 'Agent name'
                    ];
                    // Walk all elements looking for these label texts
                    document.querySelectorAll('span, dt, th, td, div, p').forEach(el => {
                        const txt = el.innerText?.trim();
                        if (!txt || el.children.length > 0) return;
                        const match = labels.find(l => l.toLowerCase() === txt.toLowerCase());
                        if (match) {
                            // Try sibling or parent's next sibling for the value
                            const next = el.nextElementSibling ||
                                         el.parentElement?.nextElementSibling;
                            if (next && !data[match]) {
                                const val = next.innerText?.trim();
                                if (val && val !== match) data[match] = val;
                            }
                        }
                    });
                    return data;
                }
            """)
            if result5 and len(result5) > 0:
                result.update(result5)
        except Exception as e:
            print(f"       Info bar S5 error: {e}")

    if not result:
        print("       ⚠️  Info bar: no data found with any strategy — dumping page structure for debug")
        try:
            structure = page.evaluate("""
                () => [...document.querySelectorAll('.euiDescriptionList__title')]
                    .map(e => e.innerText.trim()).slice(0, 10)
            """)
            print(f"       euiDescriptionList__title elements found: {structure}")
        except Exception:
            pass

    return result


def extract_vulnerabilities(page):
    """Extract vulnerability counts: Critical, High, Medium, Low."""
    try:
        return page.evaluate("""
            () => {
                const result = { critical:'', high:'', medium:'', low:'' };

                // strip() helper: remove commas from "1,117" → "1117"
                const clean = s => s.replace(/,/g, '');

                const items = document.querySelectorAll('.euiFlexItem, [class*="vuln"], [class*="Vuln"]');

                items.forEach(item => {
                    const text = item.innerText || '';
                    // Match leading number that may contain commas e.g. "1,117 Medium"
                    const num  = text.match(/^([\\d,]+)/);

                    if (!num) return;
                    const lower = text.toLowerCase();

                    if (lower.includes('critical') && !result.critical) result.critical = clean(num[1]);
                    else if (lower.includes('high')   && !result.high)   result.high     = clean(num[1]);
                    else if (lower.includes('medium') && !result.medium) result.medium   = clean(num[1]);
                    else if (lower.includes('low')    && !result.low)    result.low      = clean(num[1]);
                });

                // Fallback: scan full page text for "<number> Critical" etc.
                if (!result.critical) {
                    const allText = document.body.innerText;
                    // Allow commas in the number e.g. "1,117 Medium"
                    const crit = allText.match(/([\\d,]+)\\s*Critical/i);
                    const high = allText.match(/([\\d,]+)\\s*High/i);
                    const med  = allText.match(/([\\d,]+)\\s*Medium/i);
                    const low  = allText.match(/([\\d,]+)\\s*Low/i);
                    if (crit) result.critical = clean(crit[1]);
                    if (high) result.high     = clean(high[1]);
                    if (med)  result.medium   = clean(med[1]);
                    if (low)  result.low      = clean(low[1]);
                }
                return result;
            }
        """)
    except Exception:
        return {"critical": "", "high": "", "medium": "", "low": ""}


def extract_sca(page):
    """Extract SCA latest scan data."""
    try:
        return page.evaluate("""
            () => {
                const result = { policy:'', end_scan:'', passed:'', failed:'', not_applicable:'', score:'' };
                // Find the SCA table rows
                const rows = document.querySelectorAll('table tr');
                rows.forEach(row => {
                    const cells = row.querySelectorAll('td');
                    if (cells.length >= 5) {
                        // Row with SCA data: policy, end_scan, passed, failed, n/a, score
                        if (cells[0].innerText.trim() && !result.policy) {
                            result.policy         = cells[0].innerText.trim();
                            result.end_scan       = cells[1] ? cells[1].innerText.trim() : '';
                            result.passed         = cells[2] ? cells[2].innerText.trim() : '';
                            result.failed         = cells[3] ? cells[3].innerText.trim() : '';
                            result.not_applicable = cells[4] ? cells[4].innerText.trim() : '';
                            result.score          = cells[5] ? cells[5].innerText.trim() : '';
                        }
                    }
                });

                // Fallback: grab from text near "SCA"
                if (!result.score) {
                    const allText = document.body.innerText;
                    const score = allText.match(/(\\d+%)(?=\\s*$|\\s*\\n)/m);
                    if (score) result.score = score[1];
                }
                return result;
            }
        """)
    except Exception:
        return {"policy": "", "end_scan": "", "passed": "", "failed": "", "not_applicable": "", "score": ""}


def wait_for_agent_data_ready(page, hostname, timeout_sec=DATA_READY_TIMEOUT, max_retries=MAX_RELOAD_ATTEMPTS):
    """
    Poll the info bar until it actually has data (more than 2 fields),
    for up to `timeout_sec` seconds. If it's still empty — which usually
    means the underlying API call hasn't returned yet, or failed silently
    after the SPA navigation — reload the page and try again, up to
    `max_retries` times.

    Returns the info-bar dict (possibly empty if all retries failed).
    """
    for attempt in range(max_retries + 1):
        deadline = time.time() + timeout_sec
        info = {}
        while time.time() < deadline:
            info = extract_info_bar(page)
            if len(info) > 2:
                return info
            time.sleep(0.5)

        if attempt < max_retries:
            print(f"     ⏳ Data not ready for {hostname} after {timeout_sec}s "
                  f"— reloading page (retry {attempt + 1}/{max_retries})")
            try:
                page.reload(wait_until="domcontentloaded", timeout=15000)
            except Exception:
                pass
            time.sleep(1)

    return info


def scrape_agent_details(page, hostname):
    """Full scrape of agent detail page."""
    data = {h: "" for h in CSV_HEADERS}
    data["Hostname"]   = hostname
    data["Scraped At"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        # Info bar — wait until the API has actually returned data,
        # reloading the page if it's empty after DATA_READY_TIMEOUT seconds.
        info = wait_for_agent_data_ready(page, hostname)
        print(f"     Info bar keys found: {list(info.keys())}")

        # Map keys (Wazuh uses these exact labels)
        data["ID"]                = info.get("ID", "")
        data["Status"]            = info.get("Status", "")
        data["IP Address"]        = info.get("IP address", info.get("IP Address", ""))
        data["Version"]           = info.get("Version", "")
        data["Group"]             = info.get("Group", info.get("Groups", ""))
        data["Operating System"]  = info.get("Operating system", info.get("OS", ""))
        data["Cluster Node"]      = info.get("Cluster node", info.get("Node", ""))
        data["Registration Date"] = info.get("Registration date", "")
        data["Last Keep Alive"]   = info.get("Last keep alive", "")

        # Vulnerabilities
        vuln = extract_vulnerabilities(page)
        data["Vuln Critical"] = vuln.get("critical", "")
        data["Vuln High"]     = vuln.get("high", "")
        data["Vuln Medium"]   = vuln.get("medium", "")
        data["Vuln Low"]      = vuln.get("low", "")

        # SCA
        sca = extract_sca(page)
        data["SCA Policy"]         = sca.get("policy", "")
        data["SCA End Scan"]       = sca.get("end_scan", "")
        data["SCA Passed"]         = sca.get("passed", "")
        data["SCA Failed"]         = sca.get("failed", "")
        data["SCA Not Applicable"] = sca.get("not_applicable", "")
        data["SCA Score"]          = sca.get("score", "")

    except Exception as e:
        data["Error"] = str(e)
        print(f"     ⚠️  Scrape error: {e}")

    return data


def format_txt_row(data):
    sep = "─" * 62
    lines = [
        sep,
        f"  ASSET      : {data['Hostname']}",
        f"  ID         : {data['ID']}",
        f"  Status     : {data['Status']}",
        f"  IP Address : {data['IP Address']}",
        f"  OS         : {data['Operating System']}",
        f"  Version    : {data['Version']}",
        f"  Group      : {data['Group']}",
        f"  Cluster    : {data['Cluster Node']}",
        f"  Reg. Date  : {data['Registration Date']}",
        f"  Last Alive : {data['Last Keep Alive']}",
        f"  ── Vulnerabilities ──────────────────────────────",
        f"  Critical   : {data['Vuln Critical']}",
        f"  High       : {data['Vuln High']}",
        f"  Medium     : {data['Vuln Medium']}",
        f"  Low        : {data['Vuln Low']}",
        f"  ── SCA Latest Scan ──────────────────────────────",
        f"  Policy     : {data['SCA Policy']}",
        f"  End Scan   : {data['SCA End Scan']}",
        f"  Passed     : {data['SCA Passed']}",
        f"  Failed     : {data['SCA Failed']}",
        f"  N/A        : {data['SCA Not Applicable']}",
        f"  Score      : {data['SCA Score']}",
        f"  Scraped At : {data['Scraped At']}",
    ]
    if data.get("Error"):
        lines.append(f"  ⚠️  Error    : {data['Error']}")
    lines.append(sep)
    return "\n".join(lines)


def main():
    if not os.path.exists(ASSETS_FILE):
        print(f"❌ '{ASSETS_FILE}' not found!")
        sys.exit(1)

    with open(ASSETS_FILE) as f:
        assets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not assets:
        print("❌ assets.txt is empty!")
        sys.exit(1)

    print(f"📋 Loaded {len(assets)} assets from {ASSETS_FILE}")
    print(f"📄 Output → {OUTPUT_CSV}  +  {OUTPUT_TXT}")
    print("=" * 62)

    not_found = []

    # Init output files
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=CSV_HEADERS).writeheader()
    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        f.write(f"WAZUH ASSET SCRAPE REPORT\n")
        f.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total     : {len(assets)}\n")
        f.write("=" * 62 + "\n\n")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=HEADLESS,
            args=["--start-maximized", "--ignore-certificate-errors"]
        )
        context = browser.new_context(
            viewport={"width": 1600, "height": 900},
            ignore_https_errors=True
        )
        page = context.new_page()

        # Login
        try:
            login(page)
        except Exception as e:
            print(f"\n❌ Login failed: {e}")
            browser.close()
            sys.exit(1)

        # Process assets one by one
        for i, hostname in enumerate(assets, 1):
            asset_start = time.time()
            print(f"\n[{i}/{len(assets)}] ── {hostname} {'─'*30}")

            found = navigate_to_agent(page, hostname)

            if found:
                data = scrape_agent_details(page, hostname)
                print(f"     ID={data['ID']} | {data['Status']} | {data['IP Address']}")
                print(f"     Vuln  → Crit:{data['Vuln Critical']}  High:{data['Vuln High']}  Med:{data['Vuln Medium']}  Low:{data['Vuln Low']}")
                print(f"     SCA   → {data['SCA Score']}  Pass:{data['SCA Passed']}  Fail:{data['SCA Failed']}")
            else:
                data = {h: "" for h in CSV_HEADERS}
                data["Hostname"]   = hostname
                data["Error"]      = "NOT FOUND in Wazuh"
                data["Scraped At"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                not_found.append(hostname)

            # Save immediately (safe even if script crashes midway)
            with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
                csv.DictWriter(f, fieldnames=CSV_HEADERS).writerow(data)
            with open(OUTPUT_TXT, "a", encoding="utf-8") as f:
                f.write(format_txt_row(data) + "\n\n")

            elapsed = time.time() - asset_start
            print(f"     ⏱  Took {elapsed:.1f}s")

            # Top up to DELAY_SEC total so each asset takes ~DELAY_SEC overall,
            # without sleeping extra on assets that already took longer.
            remaining = DELAY_SEC - elapsed
            if remaining > 0:
                time.sleep(remaining)

        browser.close()

    print("\n" + "=" * 62)
    print(f"✅  COMPLETE — {len(assets)} assets processed")
    print(f"   Found     : {len(assets) - len(not_found)}")
    print(f"   Not found : {len(not_found)}")
    if not_found:
        print(f"   Missing   : {', '.join(not_found)}")
    print(f"\n📄 {OUTPUT_CSV}")
    print(f"📄 {OUTPUT_TXT}")
    print("=" * 62)


if __name__ == "__main__":
    main()