import os
import csv
import time
import random
import argparse
from pathlib import Path
from playwright.sync_api import sync_playwright

# Path to the unpacked extension
EXTENSION_PATH = Path(r"d:\staticanalysis\vt-hash-scraper").resolve()
USER_DATA_DIR = Path(r"d:\staticanalysis\vt-hash-scraper\automation\chrome_profile").resolve()

def load_hashes(csv_path):
    hashes = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row: continue
            h = row[0].strip()
            # Skip the header row if it exists
            if h.lower() in ['hash', 'md5', 'sha1', 'sha256', 'sha-256', 'hashes']:
                continue
            if h:
                hashes.append(h)
    return hashes

def simulate_human_behavior(page):
    """Simulate some random scrolling and mouse movements to avoid bot detection."""
    # Scroll down a bit randomly
    for _ in range(random.randint(1, 3)):
        scroll_amount = random.randint(300, 800)
        page.mouse.wheel(0, scroll_amount)
        time.sleep(random.uniform(0.5, 2.0))
        
    # Scroll back up
    page.mouse.wheel(0, -random.randint(300, 800))
    time.sleep(random.uniform(0.5, 1.0))

def run_scraper(csv_path):
    print(f"[*] Loading hashes from {csv_path}")
    hashes = load_hashes(csv_path)
    print(f"[*] Found {len(hashes)} hashes to process.")
    
    if not hashes:
        print("[-] No hashes found. Exiting.")
        return

    print(f"[*] Starting Playwright with extension from {EXTENSION_PATH}")
    
    with sync_playwright() as p:
        # Launch persistent context to keep the extension loaded and save cookies/login sessions
        context = p.chromium.launch_persistent_context(
            USER_DATA_DIR,
            headless=False, # Extensions only work in headful mode
            args=[
                f"--disable-extensions-except={EXTENSION_PATH}",
                f"--load-extension={EXTENSION_PATH}",
            ]
        )
        
        # In a persistent context, a default page is already created
        page = context.pages[0] if context.pages else context.new_page()
        
        print("[!] IMPORTANT: If this is your first run, you might want to log in to VirusTotal to increase your scraping limits.")
        print("[!] The script will pause for 10 seconds to let you do this manually if needed.")
        try:
            page.goto("https://www.virustotal.com/")
            time.sleep(10)
        except KeyboardInterrupt:
            print("Aborted.")
            context.close()
            return
        
        for idx, h in enumerate(hashes):
            print(f"\n[{idx+1}/{len(hashes)}] Navigating to VT for hash: {h}")
            try:
                url = f"https://www.virustotal.com/gui/file/{h}"
                page.goto(url, wait_until="domcontentloaded")
                
                # Wait for the main UI components to load to ensure our extension can scrape
                try:
                    page.wait_for_selector('vt-ui-file-card', timeout=15000)
                except Exception:
                    print(f"    [-] Timeout waiting for file card. It might be a new file or VT is blocking us.")
                
                # Our extension runs automatically when the API payload is intercepted.
                # We just need to give it enough time to catch the fetch request and push to Google Sheets.
                wait_time = random.uniform(8.0, 14.0)
                print(f"    [*] Simulating human reading. Waiting for {wait_time:.1f} seconds to allow extension auto-push...")
                
                # Do some random scrolling while waiting
                simulate_human_behavior(page)
                
                # Sleep the remaining time
                time.sleep(max(1.0, wait_time - 3.0)) 
                
                print(f"    [+] Done reading.")
            except Exception as e:
                print(f"    [-] Error processing {h}: {e}")
                
            # Random wait between requests to avoid rate limiting
            between_req_sleep = random.uniform(2.0, 6.0)
            print(f"    [*] Sleeping {between_req_sleep:.1f}s before next request...")
            time.sleep(between_req_sleep)
            
        print("[*] Completed processing all hashes.")
        context.close()

if __name__ == "__main__":
    script_dir = Path(__file__).parent.resolve()
    csv_file = script_dir / "cleaned.csv"
    
    if not csv_file.exists():
        print(f"[-] File not found: {csv_file}")
    else:
        run_scraper(csv_file)
