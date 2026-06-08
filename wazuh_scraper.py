"""
╔══════════════════════════════════════════════════════════════════╗
║         WAZUH DASHBOARD — ASSET BULK SCRAPER v5                  ║
║                                                                  ║
║  FLOW:                                                           ║
║   1. Login to Wazuh Dashboard                                    ║
║   2. Go to Dev Tools → Dismiss popup                             ║
║   3. Paste bulk query for ALL hostnames → click ▶ Run            ║
║   4. Parse aggregation response → extract agent IDs              ║
║   5. Save all IDs to agent_ids.txt                               ║
║   6. Open each agent via /app/wz-home#/agents?agent=<ID>         ║
║   7. Scrape all details → results.csv + results.txt              ║
╚══════════════════════════════════════════════════════════════════╝
"""

import csv
import json
import time
import os
import sys
from datetime import datetime
from playwright.sync_api import sync_playwright

# ─────────────────────────────────────────────────────────────
#  CONFIG — Edit before running
# ─────────────────────────────────────────────────────────────
WAZUH_URL     = "https://wazuh-dash.inf.bankbazaar.com"
USERNAME      = "itsupport"      # ← Your Wazuh login ID
PASSWORD      = "r01ddl345"      # ← Your Wazuh password
ASSETS_FILE   = "assets.txt"         # One hostname per line
AGENT_ID_FILE = "agent_ids.txt"      # Auto-generated: hostname → agent ID
OUTPUT_CSV    = "results.csv"
OUTPUT_TXT    = "results.txt"
HEADLESS      = False                # False = see browser window
DELAY_SEC     = 2                    # Wait between each agent page scrape
# ─────────────────────────────────────────────────────────────

DEV_TOOLS_URL = f"{WAZUH_URL}/app/dev_tools#/console"

CSV_HEADERS = [
    "Hostname", "Agent ID", "Status", "IP Address", "Version", "Group",
    "Operating System", "Cluster Node", "Registration Date", "Last Keep Alive",
    "Vuln Critical", "Vuln High", "Vuln Medium", "Vuln Low",
    "SCA Policy", "SCA End Scan", "SCA Passed", "SCA Failed",
    "SCA Not Applicable", "SCA Score",
    "Scraped At", "Error"
]


# ══════════════════════════════════════════════════════════════
#  STEP 1 — LOGIN
# ══════════════════════════════════════════════════════════════
def login(page):
    print(f"\n{'═'*62}")
    print(f"  STEP 1 — Login")
    print(f"{'═'*62}")
    print(f"  Opening: {WAZUH_URL}")

    page.goto(WAZUH_URL, wait_until="domcontentloaded")
    time.sleep(3)

    # Skip if already authenticated
    if "login" not in page.url and "signin" not in page.url and "/app/" in page.url:
        print("  ✅ Already logged in")
        return

    login_strategies = [
        ("input[data-test-subj='user-name']", "input[data-test-subj='password']", "button[data-test-subj='submit']"),
        ("#user-name",                         "#password",                         "button[type='submit']"),
        ("input[name='username']",             "input[name='password']",           "button[type='submit']"),
        ("input[name='user']",                 "input[name='password']",           "button[type='submit']"),
        ("input[type='text']",                 "input[type='password']",           "button[type='submit']"),
    ]

    for user_sel, pass_sel, btn_sel in login_strategies:
        try:
            page.wait_for_selector(user_sel, timeout=4000, state="visible")
            print(f"  Found login form → {user_sel}")
            page.fill(user_sel, USERNAME)
            time.sleep(0.4)
            page.fill(pass_sel, PASSWORD)
            time.sleep(0.4)
            page.click(btn_sel)
            page.wait_for_function(
                "() => !window.location.href.includes('login') && !window.location.href.includes('signin')",
                timeout=20000
            )
            time.sleep(3)
            print(f"  ✅ Login successful! → {page.url}")
            return
        except Exception:
            continue

    raise Exception("Login failed — check USERNAME/PASSWORD in CONFIG")


# ══════════════════════════════════════════════════════════════
#  STEP 2 — BUILD QUERY FROM ASSETS LIST
# ══════════════════════════════════════════════════════════════
def build_agent_query(hostnames):
    """
    Build a single aggregation query that fetches agent IDs
    for ALL hostnames in one request.
    Response format:
      aggregations.agents.buckets[].key        = hostname
      aggregations.agents.buckets[].agent_id.buckets[0].key = agent_id
    """
    names_json = json.dumps(hostnames)
    query = f"""GET wazuh-states-vulnerabilities-wazuh/_search
{{
  "size": 0,
  "query": {{
    "bool": {{
      "filter": [
        {{
          "terms": {{
            "agent.name": {names_json}
          }}
        }}
      ]
    }}
  }},
  "aggs": {{
    "agents": {{
      "terms": {{ "field": "agent.name", "size": 2000 }},
      "aggs": {{
        "agent_id": {{ "terms": {{ "field": "agent.id", "size": 1 }}}}
      }}
    }}
  }}
}}"""
    return query


# ══════════════════════════════════════════════════════════════
#  STEP 3 — RUN QUERY IN DEV TOOLS & GET RESPONSE
# ══════════════════════════════════════════════════════════════
def run_devtools_query(page, query_text):
    """
    1. Navigate to Dev Tools
    2. Dismiss the welcome popup if present
    3. Clear the editor and paste the query using Ace editor JS API
    4. Click the green ▶ play button
    5. Read and return the response from right pane
    """
    print(f"\n  Opening Dev Tools console...")
    page.goto(DEV_TOOLS_URL, wait_until="domcontentloaded")
    time.sleep(3)

    # ── Dismiss "Welcome to Console" popup if present ──
    try:
        dismiss_btn = page.wait_for_selector("button:has-text('Dismiss')", timeout=5000)
        if dismiss_btn:
            dismiss_btn.click()
            print("  ✅ Dismissed welcome popup")
            time.sleep(1)
    except Exception:
        print("  (No popup to dismiss)")

    # ── Set query in Ace editor via JavaScript ──
    # OpenSearch Dev Tools uses Ace editor — set value directly via JS API
    print("  Injecting query into Ace editor...")
    try:
        # Pre-escape backticks BEFORE building the f-string (can't use backslash inside f-string)
        escaped_query = query_text.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")
        js_code = """
            () => {
                const editors = document.querySelectorAll('.ace_editor');
                if (!editors.length) return false;
                const editorEl = editors[0];
                const aceEditor = ace.edit(editorEl);
                aceEditor.setValue(`""" + escaped_query + """`, -1);
                aceEditor.gotoLine(1, 0, false);
                aceEditor.focus();
                return true;
            }
        """
        page.evaluate(js_code)
        print("  ✅ Query injected into editor")
        time.sleep(1)
    except Exception as e:
        print(f"  ⚠️  JS inject failed: {e} — trying keyboard method...")

        # Fallback: click editor and use keyboard
        try:
            editor_el = page.wait_for_selector(".ace_editor", timeout=5000, state="visible")
            editor_el.click()
            time.sleep(0.5)
            # Select all and delete existing content
            page.keyboard.press("Control+a")
            time.sleep(0.3)
            page.keyboard.press("Delete")
            time.sleep(0.3)
            # Type the query
            page.keyboard.type(query_text, delay=5)
            time.sleep(1)
            print("  ✅ Query typed via keyboard")
        except Exception as e2:
            raise Exception(f"Could not set editor content: {e2}")

    # ── Click the ▶ green play/send button ──
    # In OpenSearch Dev Tools, the ▶ button appears at the top-right of the request block
    print("  Clicking ▶ Run button...")
    play_selectors = [
        # OpenSearch Dev Tools specific
        "button[aria-label='Click to send request']",
        "button[aria-label='Run']",
        "[data-test-subj='sendRequestButton']",
        ".conApp__editorActionBar button:first-child",
        # The triangle icon button near line 1
        "button.euiButtonIcon[aria-label*='end']",
        "button.euiButtonIcon[aria-label*='run']",
        "button.euiButtonIcon[aria-label*='Run']",
        # Generic green button in editor area
        ".ace_gutter-layer + * button",
        "[class*='actions'] button:first-child",
    ]

    played = False
    for sel in play_selectors:
        try:
            btn = page.wait_for_selector(sel, timeout=3000, state="visible")
            if btn:
                btn.click()
                played = True
                print(f"  ✅ Clicked play button: {sel}")
                break
        except Exception:
            continue

    if not played:
        # Final fallback: position cursor at line 1 and use Ctrl+Enter
        print("  Using Ctrl+Enter to execute...")
        try:
            editor_el = page.query_selector(".ace_editor")
            if editor_el:
                editor_el.click()
        except Exception:
            pass
        page.keyboard.press("Control+Enter")
        played = True

    # ── Wait for response to appear in right pane ──
    print("  Waiting for query response...")
    time.sleep(5)  # Give enough time for the query to execute

    # ── Read response from right pane ──
    # The output pane is the second Ace editor OR a separate response div
    response_text = ""

    # Method 1: Read second Ace editor (response pane)
    try:
        response_text = page.evaluate("""
            () => {
                const editors = document.querySelectorAll('.ace_editor');
                // Second editor = response pane
                if (editors.length >= 2) {
                    const lines = editors[1].querySelectorAll('.ace_line');
                    return Array.from(lines).map(l => l.innerText).join('\\n');
                }
                return '';
            }
        """)
    except Exception:
        pass

    # Method 2: Get via Ace JS API
    if not response_text or "{" not in response_text:
        try:
            response_text = page.evaluate("""
                () => {
                    const editors = document.querySelectorAll('.ace_editor');
                    if (editors.length >= 2) {
                        return ace.edit(editors[1]).getValue();
                    }
                    return '';
                }
            """)
        except Exception:
            pass

    # Method 3: Look for output/response container
    if not response_text or "{" not in response_text:
        try:
            response_text = page.evaluate("""
                () => {
                    const selectors = [
                        '[data-test-subj="response-editor"]',
                        '.conApp__output',
                        '[class*="output"] .ace_editor',
                        '[class*="response"]',
                    ];
                    for (const sel of selectors) {
                        const el = document.querySelector(sel);
                        if (el && el.innerText.includes('{')) {
                            return el.innerText;
                        }
                    }
                    return '';
                }
            """)
        except Exception:
            pass

    if response_text:
        print(f"  ✅ Got response ({len(response_text)} chars)")
    else:
        print(f"  ⚠️  Response pane appears empty")

    return response_text


# ══════════════════════════════════════════════════════════════
#  STEP 4 — PARSE AGENT IDs FROM AGGREGATION RESPONSE
# ══════════════════════════════════════════════════════════════
def parse_agent_ids(response_text, hostnames):
    """
    Parse the aggregation response and return a dict:
    { "BBDSK0823": "456", "BBDSK0802": "123", ... }
    """
    agent_id_map = {}

    if not response_text:
        print("  ⚠️  Empty response — cannot parse agent IDs")
        return agent_id_map

    # Clean response: find first { to last }
    try:
        start = response_text.find("{")
        end   = response_text.rfind("}") + 1
        if start == -1 or end == 0:
            print("  ⚠️  No JSON object found in response")
            print(f"  Response preview: {response_text[:300]}")
            return agent_id_map

        clean_json = response_text[start:end]
        data = json.loads(clean_json)

        # Navigate: aggregations → agents → buckets
        buckets = (
            data.get("aggregations", {})
                .get("agents", {})
                .get("buckets", [])
        )

        if not buckets:
            print("  ⚠️  No buckets in aggregation response")
            print(f"  Top-level keys: {list(data.keys())}")
            return agent_id_map

        print(f"  Found {len(buckets)} agent buckets in response")

        for bucket in buckets:
            hostname  = bucket.get("key", "")
            id_buckets = bucket.get("agent_id", {}).get("buckets", [])
            if id_buckets:
                raw_id   = str(id_buckets[0].get("key", ""))
                # Strip leading zeros: "0639" → "639"
                agent_id = raw_id.lstrip("0") or raw_id
                agent_id_map[hostname] = agent_id

        return agent_id_map

    except json.JSONDecodeError as e:
        print(f"  ⚠️  JSON parse error: {e}")
        print(f"  Response (first 500 chars):\n{response_text[:500]}")
        return agent_id_map
    except Exception as e:
        print(f"  ⚠️  Parse error: {e}")
        return agent_id_map


# ══════════════════════════════════════════════════════════════
#  STEP 5 — OPEN AGENT PAGE BY ID
# ══════════════════════════════════════════════════════════════
def open_agent_page(page, agent_id, hostname):
    """Navigate directly to agent detail page using agent ID in URL."""
    url = f"{WAZUH_URL}/app/wz-home#/agents?agent={agent_id}"
    print(f"  Opening: {url}")
    page.goto(url, wait_until="domcontentloaded")
    time.sleep(3)

    # Verify page loaded — look for hostname or agent ID on page
    try:
        page.wait_for_function(
            f"() => document.body.innerText.includes('{hostname}') || "
            f"document.body.innerText.includes('{agent_id}')",
            timeout=10000
        )
        print(f"  ✅ Agent page loaded for {hostname} (ID: {agent_id})")
    except Exception:
        snippet = page.inner_text("body")[:150].replace('\n', ' ')
        print(f"  ⚠️  Page may differ — continuing anyway. Body: {snippet}")


# ══════════════════════════════════════════════════════════════
#  STEP 6 — SCRAPE AGENT DETAILS
# ══════════════════════════════════════════════════════════════
def extract_info_bar(page):
    try:
        return page.evaluate("""
            () => {
                const data = {};

                // EUI Description List — standard Wazuh layout
                const titles = document.querySelectorAll('.euiDescriptionList__title');
                const descs  = document.querySelectorAll('.euiDescriptionList__description');
                titles.forEach((t, i) => {
                    if (descs[i]) data[t.innerText.trim()] = descs[i].innerText.trim();
                });

                // Fallback: stat/summary panels
                document.querySelectorAll('[class*="stat"], [class*="Stat"], [class*="summary"]')
                    .forEach(el => {
                        const children = el.querySelectorAll('span, p, div');
                        for (let i = 0; i < children.length - 1; i++) {
                            const k = children[i].innerText.trim();
                            const v = children[i+1].innerText.trim();
                            if (k && v && k.length < 40 && !data[k]) data[k] = v;
                        }
                    });
                return data;
            }
        """)
    except Exception:
        return {}


def extract_vulnerabilities(page):
    try:
        return page.evaluate("""
            () => {
                const r = { critical:'', high:'', medium:'', low:'' };

                // Scan flex/card items for "number + severity" pattern
                document.querySelectorAll('.euiFlexItem, [class*="card"], [class*="Card"]')
                    .forEach(el => {
                        const txt = (el.innerText || '').trim();
                        let m = txt.match(/^(\\d+)\\s*(Critical|High|Medium|Low)/im)
                             || txt.match(/(Critical|High|Medium|Low)\\s*[:\\n]?\\s*(\\d+)/im);
                        if (!m) return;
                        let num, sev;
                        if (/^\\d/.test(m[1])) { num=m[1]; sev=m[2]; }
                        else                   { sev=m[1]; num=m[2]; }
                        sev = sev.toLowerCase();
                        if      (sev==='critical' && !r.critical) r.critical=num;
                        else if (sev==='high'     && !r.high)     r.high=num;
                        else if (sev==='medium'   && !r.medium)   r.medium=num;
                        else if (sev==='low'      && !r.low)      r.low=num;
                    });

                // Fallback: body text regex
                if (!r.critical) {
                    const t = document.body.innerText;
                    const pats = {
                        critical: [/(\\d+)\\s*Critical/i, /Critical\\D*(\\d+)/i],
                        high:     [/(\\d+)\\s*High/i,     /High\\D*(\\d+)/i],
                        medium:   [/(\\d+)\\s*Medium/i,   /Medium\\D*(\\d+)/i],
                        low:      [/(\\d+)\\s*Low/i,      /Low\\D*(\\d+)/i],
                    };
                    for (const [k, pp] of Object.entries(pats)) {
                        for (const p of pp) {
                            const m = t.match(p);
                            if (m && !r[k]) { r[k]=m[1]; break; }
                        }
                    }
                }
                return r;
            }
        """)
    except Exception:
        return {"critical": "", "high": "", "medium": "", "low": ""}


def extract_sca(page):
    try:
        return page.evaluate("""
            () => {
                const r = { policy:'', end_scan:'', passed:'', failed:'', not_applicable:'', score:'' };
                for (const row of document.querySelectorAll('table tr')) {
                    const cells = row.querySelectorAll('td');
                    if (cells.length >= 5) {
                        const first = cells[0].innerText.trim();
                        if (first && first.length > 5 && !/^\\d+$/.test(first)) {
                            r.policy         = first;
                            r.end_scan       = cells[1]?.innerText.trim() || '';
                            r.passed         = cells[2]?.innerText.trim() || '';
                            r.failed         = cells[3]?.innerText.trim() || '';
                            r.not_applicable = cells[4]?.innerText.trim() || '';
                            r.score          = cells[5]?.innerText.trim() || '';
                            break;
                        }
                    }
                }
                if (!r.score) {
                    const m = document.body.innerText.match(/(\\d{1,3}%)/);
                    if (m) r.score = m[1];
                }
                return r;
            }
        """)
    except Exception:
        return {"policy": "", "end_scan": "", "passed": "", "failed": "", "not_applicable": "", "score": ""}


def scrape_agent_details(page, hostname, agent_id):
    data = {h: "" for h in CSV_HEADERS}
    data["Hostname"]   = hostname
    data["Agent ID"]   = agent_id
    data["Scraped At"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        info = extract_info_bar(page)
        print(f"  Info bar keys: {list(info.keys())[:10]}")

        data["Status"]            = info.get("Status", "")
        data["IP Address"]        = info.get("IP address", info.get("IP Address", ""))
        data["Version"]           = info.get("Version", "")
        data["Group"]             = info.get("Group", info.get("Groups", ""))
        data["Operating System"]  = info.get("Operating system", info.get("OS", ""))
        data["Cluster Node"]      = info.get("Cluster node", info.get("Node", ""))
        data["Registration Date"] = info.get("Registration date", "")
        data["Last Keep Alive"]   = info.get("Last keep alive", "")

        vuln = extract_vulnerabilities(page)
        data["Vuln Critical"] = vuln.get("critical", "")
        data["Vuln High"]     = vuln.get("high", "")
        data["Vuln Medium"]   = vuln.get("medium", "")
        data["Vuln Low"]      = vuln.get("low", "")

        sca = extract_sca(page)
        data["SCA Policy"]         = sca.get("policy", "")
        data["SCA End Scan"]       = sca.get("end_scan", "")
        data["SCA Passed"]         = sca.get("passed", "")
        data["SCA Failed"]         = sca.get("failed", "")
        data["SCA Not Applicable"] = sca.get("not_applicable", "")
        data["SCA Score"]          = sca.get("score", "")

    except Exception as e:
        data["Error"] = str(e)
        print(f"  ⚠️  Scrape error: {e}")

    return data


# ══════════════════════════════════════════════════════════════
#  OUTPUT HELPERS
# ══════════════════════════════════════════════════════════════
def format_txt_row(data):
    sep = "─" * 64
    lines = [
        sep,
        f"  ASSET        : {data['Hostname']}",
        f"  AGENT ID     : {data['Agent ID']}",
        f"  Status       : {data['Status']}",
        f"  IP Address   : {data['IP Address']}",
        f"  OS           : {data['Operating System']}",
        f"  Version      : {data['Version']}",
        f"  Group        : {data['Group']}",
        f"  Cluster Node : {data['Cluster Node']}",
        f"  Reg. Date    : {data['Registration Date']}",
        f"  Last Alive   : {data['Last Keep Alive']}",
        f"  ── Vulnerabilities ────────────────────────────────",
        f"  Critical     : {data['Vuln Critical']}",
        f"  High         : {data['Vuln High']}",
        f"  Medium       : {data['Vuln Medium']}",
        f"  Low          : {data['Vuln Low']}",
        f"  ── SCA Latest Scan ────────────────────────────────",
        f"  Policy       : {data['SCA Policy']}",
        f"  End Scan     : {data['SCA End Scan']}",
        f"  Passed       : {data['SCA Passed']}",
        f"  Failed       : {data['SCA Failed']}",
        f"  N/A          : {data['SCA Not Applicable']}",
        f"  Score        : {data['SCA Score']}",
        f"  Scraped At   : {data['Scraped At']}",
    ]
    if data.get("Error"):
        lines.append(f"  ⚠️  Error      : {data['Error']}")
    lines.append(sep)
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════
def main():
    if not os.path.exists(ASSETS_FILE):
        print(f"❌ '{ASSETS_FILE}' not found!")
        sys.exit(1)

    with open(ASSETS_FILE) as f:
        assets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not assets:
        print("❌ assets.txt is empty!")
        sys.exit(1)

    print(f"\n{'═'*62}")
    print(f"  WAZUH BULK SCRAPER v5")
    print(f"{'═'*62}")
    print(f"  Assets loaded : {len(assets)}")
    print(f"  Output CSV    : {OUTPUT_CSV}")
    print(f"  Output TXT    : {OUTPUT_TXT}")
    print(f"  Agent IDs     : {AGENT_ID_FILE}")
    print(f"{'═'*62}")

    # Init output files
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=CSV_HEADERS).writeheader()
    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        f.write(f"WAZUH ASSET SCRAPE REPORT\n")
        f.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total     : {len(assets)} assets\n")
        f.write("=" * 64 + "\n\n")

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

        # ── STEP 1: Login ──────────────────────────────────
        try:
            login(page)
        except Exception as e:
            print(f"\n❌ Login failed: {e}")
            browser.close()
            sys.exit(1)

        # ── STEP 2: Build & run bulk query in Dev Tools ────
        print(f"\n{'═'*62}")
        print(f"  STEP 2 — Fetching ALL Agent IDs via Dev Tools")
        print(f"{'═'*62}")

        query = build_agent_query(assets)
        print(f"  Query built for {len(assets)} hostnames")

        try:
            response_text = run_devtools_query(page, query)
        except Exception as e:
            print(f"  ❌ Dev Tools query failed: {e}")
            browser.close()
            sys.exit(1)

        # ── STEP 3: Parse agent IDs from response ──────────
        agent_id_map = parse_agent_ids(response_text, assets)
        found_count  = len(agent_id_map)
        print(f"\n  Agent IDs resolved: {found_count}/{len(assets)}")

        # ── STEP 4: Save agent_ids.txt ─────────────────────
        with open(AGENT_ID_FILE, "w", encoding="utf-8") as f:
            f.write(f"# Wazuh Agent ID Lookup\n")
            f.write(f"# Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Format    : HOSTNAME  →  AGENT_ID\n")
            f.write("─" * 42 + "\n")
            for hostname in assets:
                agent_id = agent_id_map.get(hostname, "NOT FOUND")
                f.write(f"{hostname:<30} →  {agent_id}\n")

        print(f"  💾 Saved → {AGENT_ID_FILE}")
        # Print the ID map to console
        print(f"\n  {'HOSTNAME':<30}  AGENT ID")
        print(f"  {'─'*30}  {'─'*10}")
        for h in assets:
            print(f"  {h:<30}  {agent_id_map.get(h, '❌ NOT FOUND')}")

        # ── STEP 5: Scrape each agent page ─────────────────
        print(f"\n{'═'*62}")
        print(f"  STEP 3 — Scraping Agent Detail Pages")
        print(f"{'═'*62}")

        not_found = []
        for i, hostname in enumerate(assets, 1):
            agent_id = agent_id_map.get(hostname)
            print(f"\n  [{i}/{len(assets)}] {hostname}  (ID: {agent_id})")

            if not agent_id:
                data = {h: "" for h in CSV_HEADERS}
                data["Hostname"]   = hostname
                data["Agent ID"]   = ""
                data["Error"]      = "Agent ID not found in wazuh-states-vulnerabilities index"
                data["Scraped At"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                not_found.append(hostname)
            else:
                open_agent_page(page, agent_id, hostname)
                data = scrape_agent_details(page, hostname, agent_id)

                print(f"  Status : {data['Status']}  |  IP: {data['IP Address']}  |  OS: {data['Operating System']}")
                print(f"  Vuln   → Crit:{data['Vuln Critical']}  High:{data['Vuln High']}  Med:{data['Vuln Medium']}  Low:{data['Vuln Low']}")
                print(f"  SCA    → Score:{data['SCA Score']}  Pass:{data['SCA Passed']}  Fail:{data['SCA Failed']}")

            # Write immediately (crash-safe)
            with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
                csv.DictWriter(f, fieldnames=CSV_HEADERS).writerow(data)
            with open(OUTPUT_TXT, "a", encoding="utf-8") as f:
                f.write(format_txt_row(data) + "\n\n")

            time.sleep(DELAY_SEC)

        browser.close()

    # ── Summary ────────────────────────────────────────────
    print(f"\n{'═'*62}")
    print(f"  ✅  COMPLETE")
    print(f"{'═'*62}")
    print(f"  Total    : {len(assets)}")
    print(f"  Found    : {len(assets) - len(not_found)}")
    print(f"  Missing  : {len(not_found)}")
    if not_found:
        print(f"  ⚠️  No ID  : {', '.join(not_found)}")
    print(f"\n  📄 {AGENT_ID_FILE}")
    print(f"  📄 {OUTPUT_CSV}")
    print(f"  📄 {OUTPUT_TXT}")
    print(f"{'═'*62}\n")


if __name__ == "__main__":
    main()