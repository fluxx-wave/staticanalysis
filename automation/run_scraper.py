import os
import csv
import time
import random
import argparse
from pathlib import Path
from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth


# Base directory for paths
SCRIPT_DIR = Path(__file__).parent.resolve()

# Path to the unpacked extension (assumes it's alongside the automation folder)
EXTENSION_PATH = (SCRIPT_DIR.parent / "vt-hash-scraper").resolve()
# Path to the Chrome profile (now in the root automation folder)
USER_DATA_DIR = (SCRIPT_DIR / "chrome_profile").resolve()

def load_hashes(csv_path, start_row=1, end_row=None):
    hashes = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row_num, row in enumerate(reader, start=1):
            if row_num < start_row:
                continue
            if end_row is not None and row_num > end_row:
                break
            if not row: continue
            h = row[0].strip()
            # Skip the header row if it exists
            if h.lower() in ['hash', 'md5', 'sha1', 'sha256', 'sha-256', 'hashes']:
                continue
            if h:
                hashes.append((row_num, h))
    return hashes

def simulate_human_behavior(page):
    """Simulate some random scrolling and mouse movements to avoid bot detection."""
    # Scroll down a bit randomly
    for _ in range(random.randint(1, 3)):
        scroll_amount = random.randint(300, 800)
        page.mouse.wheel(0, scroll_amount)
        time.sleep(random.uniform(0.5, 2.0))
        
    # Scroll back up
    try:
        page.mouse.wheel(0, -random.randint(300, 800))
    except Exception:
        pass
    time.sleep(random.uniform(0.5, 1.0))

def run_scraper(csv_path, start_row=1, end_row=None):
    print(f"[*] Loading hashes from {csv_path}")
    hashes = load_hashes(csv_path, start_row, end_row)
    if end_row:
        print(f"[*] Found {len(hashes)} hashes to process starting from row {start_row} to {end_row}.")
    else:
        print(f"[*] Found {len(hashes)} hashes to process starting from row {start_row}.")
    
    if not hashes:
        print("[-] No hashes found. Exiting.")
        return

    print(f"[*] Starting Playwright with extension from {EXTENSION_PATH}")
    
    with sync_playwright() as p:
        # Dynamically load any custom extensions placed in the 'extentions' folder
        extension_paths = str(EXTENSION_PATH)
        extentions_dir = SCRIPT_DIR / "extentions"
        if extentions_dir.exists():
            for ext_folder in extentions_dir.iterdir():
                if ext_folder.is_dir():
                    extension_paths += f",{ext_folder.resolve()}"
                    print(f"[*] Found custom Extension, loading it alongside VT Scraper: {ext_folder.name}")

        # Launch persistent context to keep the extension loaded and save cookies/login sessions
        context = p.chromium.launch_persistent_context(
            USER_DATA_DIR,
            headless=False, # Extensions only work in headful mode
            args=[
                f"--disable-extensions-except={extension_paths}",
                f"--load-extension={extension_paths}",
            ]
        )
        
        # In a persistent context, a default page is already created
        page = context.pages[0] if context.pages else context.new_page()
        
        # Apply stealth to evade bot detection
        Stealth().apply_stealth_sync(page)
        print("[*] Playwright-stealth enabled.")
        
        print("[!] IMPORTANT: If this is your first run, you might want to log in to VirusTotal to increase your scraping limits.")
        print("[!] The script will pause for 10 seconds to let you do this manually if needed.")
        try:
            page.goto("https://www.virustotal.com/")
            time.sleep(10)
        except KeyboardInterrupt:
            print("Aborted.")
            context.close()
            return
        
        for idx, (row_num, h) in enumerate(hashes):
            print(f"\n[{idx+1}/{len(hashes)}] [CSV Row: {row_num}] Navigating to VT for hash: {h}")
            
            max_retries = 2
            attempts = 0
            success = False
            
            while attempts < max_retries and not success:
                attempts += 1
                if attempts > 1:
                    print(f"    [*] Retrying hash {h} (Attempt {attempts}/{max_retries})...")
                    
                try:
                    url = f"https://www.virustotal.com/gui/file/{h}"
                    page.goto(url, wait_until="domcontentloaded")
                    
                    # Wait for the main UI components to load to ensure our extension can scrape
                    try:
                        page.wait_for_selector('vt-ui-file-card', timeout=15000)
                    except Exception:
                        print(f"    [-] Timeout waiting for file card. It might be a new file or blocked.")
                        
                    def is_captcha_present():
                        try:
                            # Check if any captcha element is actually visible on the screen
                            if "captcha" in page.url.lower():
                                return True
                                
                            # Try to find visible iframes or vt-ui-captcha
                            for selector in ['iframe[src*="recaptcha"]', 'iframe[src*="turnstile"]', 'vt-ui-captcha']:
                                locator = page.locator(selector)
                                if locator.count() > 0 and locator.first.is_visible():
                                    return True
                            return False
                        except Exception:
                            return False
    
                    def notify_captcha():
                        try:
                            from plyer import notification
                            notification.notify(title="VirusTotal Scraper", message="CAPTCHA DETECTED! Please solve it in the browser.", timeout=10)
                        except Exception:
                            pass

                    # Handle immediate CAPTCHA
                    captcha_solved = False
                    if is_captcha_present():
                        print("    [!] CAPTCHA DETECTED! Waiting 10s for auto-solver...")
                        
                        # Give auto-solver 10 seconds silently
                        waited = 0
                        while is_captcha_present() and waited < 10:
                            time.sleep(2)
                            waited += 2
                            
                        if is_captcha_present():
                            notify_captcha()
                            while is_captcha_present():
                                print("    [!] Please solve the CAPTCHA in the open Chromium browser...")
                                print('\a', end='', flush=True) # Ring bell
                                time.sleep(4)
                                
                        print("    [+] CAPTCHA solved!")
                        captcha_solved = True
                        
                    if captcha_solved:
                        print("    [*] Refreshing page after CAPTCHA to trigger extension again...")
                        page.reload(wait_until="domcontentloaded")
                        try:
                            page.wait_for_selector('vt-ui-file-card', timeout=15000)
                        except:
                            pass
                    
                    # Our extension runs automatically when the API payload is intercepted.
                    print(f"    [*] Simulating human reading. Waiting for extension to push data...")
                    
                    max_wait = 25
                    slept = 0
                    pushed = False
                    
                    while slept < max_wait:
                        # Check for CAPTCHA periodically
                        if is_captcha_present():
                            print("    [!] CAPTCHA DETECTED dynamically! Waiting 10s for auto-solver...")
                            
                            waited = 0
                            while is_captcha_present() and waited < 10:
                                time.sleep(2)
                                waited += 2
                                
                            if is_captcha_present():
                                notify_captcha()
                                while is_captcha_present():
                                    print("    [!] Please solve the CAPTCHA in the browser window...")
                                    print('\a', end='', flush=True)
                                    time.sleep(4)
                                    
                            print("    [+] CAPTCHA solved! Refreshing page to trigger extension again...")
                            page.reload(wait_until="domcontentloaded")
                            try:
                                page.wait_for_selector('vt-ui-file-card', timeout=15000)
                            except:
                                pass
                            slept = 0 # reset sleep counter
                            continue
                            
                        # Wait for the toast notification confirming the push.
                        # This acts as our sleep, but will return instantly if the toast appears.
                        try:
                            page.wait_for_selector('.vts-toast:has-text("pushed")', state='attached', timeout=2000)
                            print("    [+] Extension push confirmed via toast!")
                            pushed = True
                            break
                        except Exception:
                            pass
                            
                        # Do some small scrolling to look human while waiting
                        try:
                            page.mouse.wheel(0, random.randint(200, 500))
                        except Exception:
                            pass
                            
                        slept += 2
                    
                    if not pushed:
                        print("    [-] Timed out waiting for push toast.")
                        if attempts < max_retries:
                            print("    [*] Refreshing the page to try again...")
                            time.sleep(3)
                        else:
                            print("    [-] Proceeding to next hash after max retries.")
                    else:
                        success = True
                    
                    print(f"    [+] Done reading.")
                except Exception as e:
                    print(f"    [-] Error processing {h}: {e}")
                    if attempts < max_retries:
                        time.sleep(3)
                
            # Random wait between requests to avoid rate limiting
            between_req_sleep = random.uniform(2.0, 6.0)
            print(f"    [*] Sleeping {between_req_sleep:.1f}s before next request...")
            time.sleep(between_req_sleep)
            
        print("[*] Completed processing all hashes.")
        context.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VT Hash Scraper Automation")
    parser.add_argument("--csv", default="cleaned.csv", help="Name of the CSV file to process")
    parser.add_argument("--start", type=int, default=1, help="Row number to start from (1-indexed)")
    parser.add_argument("--end", type=int, default=None, help="Row number to end at")
    parser.add_argument("--profile", default="chrome_profile", help="Name of the profile directory to use (e.g., chrome_profile_1)")
    
    args = parser.parse_args()
    
    # Update the global USER_DATA_DIR based on the selected profile
    USER_DATA_DIR = (SCRIPT_DIR / args.profile).resolve()
    
    csv_file = SCRIPT_DIR / args.csv
    
    if not csv_file.exists():
        print(f"[-] File not found: {csv_file}")
    else:
        print(f"[*] Using Profile Directory: {USER_DATA_DIR}")
        run_scraper(csv_file, args.start, args.end)
