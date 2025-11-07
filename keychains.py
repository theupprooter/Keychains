import os
import requests
import time
import json
import argparse
import re
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---

# ANSI color codes for console logging
class ColorFormatter(logging.Formatter):
    GREY = "\x1b[38;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    GREEN = "\x1b[92m"
    CYAN = "\x1b[96m"
    MAGENTA = "\x1b[95m"
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    UNDERLINE = "\x1b[4m"

    FORMATS = {
        logging.DEBUG: GREY + "%(asctime)s - %(message)s" + RESET,
        logging.INFO: GREY + "%(asctime)s - %(message)s" + RESET,
        logging.WARNING: YELLOW + "%(asctime)s - [WARN] %(message)s" + RESET,
        logging.ERROR: RED + "%(asctime)s - [ERROR] %(message)s" + RESET,
        logging.CRITICAL: BOLD_RED + "%(asctime)s - [FATAL] %(message)s" + RESET,
        'LEAK': BOLD + GREEN + "%(asctime)s - [LEAK CONFIRMED] - %(message)s" + RESET,
        'SCAN': CYAN + "%(asctime)s - [SCAN] %(message)s" + RESET,
        'ROTATE': MAGENTA + "%(asctime)s - [ROTATE] %(message)s" + RESET,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        if hasattr(record, 'custom_level_name'):
             log_fmt = self.FORMATS.get(record.custom_level_name)

        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

# Add custom log levels
LEAK_LEVEL = 25
SCAN_LEVEL = 26
ROTATE_LEVEL = 27
logging.addLevelName(LEAK_LEVEL, "LEAK")
logging.addLevelName(SCAN_LEVEL, "SCAN")
logging.addLevelName(ROTATE_LEVEL, "ROTATE")
log = logging.getLogger(__name__)

# Search patterns, validation regex, and live validation endpoints
SERVICE_DEFINITIONS = {
    'OpenAI': {
        'pattern': 'sk-proj-[a-zA-Z0-9]{24} OR "sk-[a-zA-Z0-9]{48}"',
        'regex': re.compile(r'sk-(proj-)?[a-zA-Z0-9]{24,48}'),
        'validation': {
            'method': 'GET', 'url': 'https://api.openai.com/v1/models',
            'auth_type': 'bearer'
        }
    },
    'Anthropic': {
        'pattern': '"sk-ant-api03-[a-zA-Z0-9_-]{95}"',
        'regex': re.compile(r'sk-ant-api03-[a-zA-Z0-9_-]{95}'),
        'validation': {
            'method': 'GET', 'url': 'https://api.anthropic.com/v1/ping',
            'auth_type': 'header', 'header_name': 'x-api-key'
        }
    },
    'Cohere': {
        'pattern': '"[a-zA-Z0-9]{40}"',
        'query_prefix': 'COHERE_API_KEY=',
        'regex': re.compile(r'[a-zA-Z0-9]{40}'),
        'validation': {
            'method': 'GET', 'url': 'https://api.cohere.ai/v1/models',
            'auth_type': 'bearer'
        }
    },
    'HuggingFace': {
        'pattern': '"hf_[a-zA-Z0-9]{35}"',
        'regex': re.compile(r'hf_[a-zA-Z0-9]{35}'),
        'validation': {
            'method': 'GET', 'url': 'https://api-inference.huggingface.co/models',
            'auth_type': 'bearer'
        }
    },
    'GoogleAI': {
        'pattern': 'AIzaSy[a-zA-Z0-9_-]{33}',
        'regex': re.compile(r'AIzaSy[a-zA-Z0-9_-]{33}'),
        'validation': {
            'method': 'GET', 'url': 'https://generativelanguage.googleapis.com/v1beta/models',
            'auth_type': 'query_param', 'param_name': 'key'
        }
    },
}

# Common filename patterns to exclude from search
EXCLUSIONS = " -path:*.md -path:*.txt -path:*.lock -path:*.example -path:package.json -path:yarn.lock -path:pnpm-lock.yaml"
CACHE_FILE = ".keyguardian_cache.json"

# --- Helper Functions ---
def display_banner():
    banner = f"""
{ColorFormatter.CYAN}
  _  __       _                  _ _           {ColorFormatter.RESET}
 {ColorFormatter.CYAN}| |/ /      | |                | (_)          {ColorFormatter.RESET}
 {ColorFormatter.CYAN}| ' /  _ __ | | __ _ _   _  ___ | |_  _ __   __ _ {ColorFormatter.RESET}
 {ColorFormatter.CYAN}|  <  | '_ \| |/ _` | | | |/ _ \| | || '_ \ / _` |{ColorFormatter.RESET}
 {ColorFormatter.CYAN}| . \ | | | | | (_| | |_| | (_) | | || | | | (_| |{ColorFormatter.RESET}
 {ColorFormatter.CYAN}|_|\_\|_| |_|_|\__,_|\__, |\___/|_|_||_| |_|\__, |{ColorFormatter.RESET}
 {ColorFormatter.CYAN}                      __/ |                 __/ |{ColorFormatter.RESET}
 {ColorFormatter.CYAN}                     |___/                 |___/ {ColorFormatter.RESET}
    {ColorFormatter.BOLD}AI Key Scanner & Rotator{ColorFormatter.RESET}
    """
    print(banner, file=sys.stderr)

def print_scan_summary_table(leaks):
    if not leaks:
        return
    
    headers = ["Service", "Repository", "File URL"]
    widths = [len(h) for h in headers]
    for leak in leaks:
        widths[0] = max(widths[0], len(leak['service']))
        widths[1] = max(widths[1], len(leak['repository']))
        widths[2] = max(widths[2], len(leak['url']))

    header_line = f" {ColorFormatter.BOLD}" + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + f"{ColorFormatter.RESET}"
    separator_line = "-+-".join("-" * w for w in widths)
    
    log.info("")
    log.info(f"{ColorFormatter.BOLD}Scan Summary:{ColorFormatter.RESET}")
    log.info(separator_line)
    log.info(header_line)
    log.info(separator_line)
    
    for leak in leaks:
        row_data = [leak['service'], leak['repository'], leak['url']]
        row_line = " | ".join(d.ljust(widths[i]) for i, d in enumerate(row_data))
        log.info(f" {row_line}")
    log.info(separator_line)

def setup_logging(log_file=None):
    log.setLevel(logging.INFO)
    if not log.handlers:
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(ColorFormatter())
        log.addHandler(ch)
    
        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
            log.addHandler(fh)

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            try: return set(json.load(f))
            except json.JSONDecodeError: return set()
    return set()

def save_cache(cache_data):
    with open(CACHE_FILE, 'w') as f:
        json.dump(list(cache_data), f)

def is_false_positive(fragment):
    lower_fragment = fragment.lower()
    placeholders = ['xxxx', 'your_key', 'your-api-key', 'placeholder', '<key>', 'env.example']
    if any(p in lower_fragment for p in placeholders): return True, "Contains placeholder text"
    
    stripped_fragment = fragment.strip()
    if stripped_fragment.startswith('#') or stripped_fragment.startswith('//') or stripped_fragment.startswith('/*'): return True, "Key is in a comment"
    
    return False, ""

# --- Mode: SCAN ---

def check_rate_limit(headers):
    try:
        response = requests.get("https://api.github.com/rate_limit", headers=headers)
        response.raise_for_status()
        data = response.json()['resources']['search']
        log.info(f"GitHub search rate limit: {data['remaining']}/{data['limit']} remaining.")
        return data['remaining']
    except requests.exceptions.RequestException as e:
        log.error(f"Could not fetch rate limit info: {e}")
        return 0

def scan_service(service, definition, headers, no_forks):
    pattern = definition.get('query_prefix', '') + definition['pattern']
    full_query = f'{pattern}{EXCLUSIONS}' + (' -fork:true' if no_forks else '')
    params = {'q': full_query, 'per_page': 100}
    
    log.log(SCAN_LEVEL, f"Querying GitHub API for {ColorFormatter.BOLD}{service}{ColorFormatter.RESET} keys...", extra={'custom_level_name': 'SCAN'})
    
    try:
        response = requests.get('https://api.github.com/search/code', headers=headers, params=params)
        response.raise_for_status()
        results = response.json().get('items', [])
        log.info(f"  -> GitHub API returned {len(results)} potential code matches for {service}.")
        return service, results
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403: # Rate limit exceeded
            log.error("GitHub API rate limit exceeded. Waiting for 60 seconds.")
            time.sleep(60)
        else:
            log.warning(f"API request failed for {service} (Status {e.response.status_code}). Skipping.")
    except requests.exceptions.RequestException as e:
        log.error(f"Network error during scan for {service}: {e}")
    
    return service, []

def run_scan(args):
    display_banner()
    log.info("--- KeyGuardian AI Key Scanner ---")

    TOKEN = os.getenv('GITHUB_TOKEN')
    if not TOKEN:
        log.critical("GITHUB_TOKEN environment variable not set.")
        return

    HEADERS = {'Authorization': f'token {TOKEN}', 'Accept': 'application/vnd.github.v3.text-match+json'}
    if check_rate_limit(HEADERS) == 0:
        log.error("Initial rate limit is zero. Exiting.")
        return

    services_to_scan = {k: v for k, v in SERVICE_DEFINITIONS.items() if args.services.lower() == 'all' or k in args.services.split(',')}

    log.info("")
    log.info(f"{ColorFormatter.BOLD}Configuration:{ColorFormatter.RESET}")
    log.info(f"  - Services: {', '.join(services_to_scan.keys())}")
    log.info(f"  - Workers: {args.workers}")
    log.info(f"  - Exclude Forks: {'Yes' if args.no_forks else 'No'}")
    log.info(f"  - Output File: {args.output or 'None'}")
    log.info("-" * 40)


    found_leaks = []
    cache = load_cache()
    log.info(f"Loaded {len(cache)} items from cache.")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(scan_service, s, d, HEADERS, args.no_forks): s for s, d in services_to_scan.items()}
        
        for future in as_completed(futures):
            service, items = future.result()
            definition = SERVICE_DEFINITIONS[service]
            
            for item in items:
                file_url = item['html_url']
                if file_url in cache:
                    continue

                fragment = item['text_matches'][0]['fragment']
                is_fp, reason = is_false_positive(fragment)
                if is_fp:
                    continue
                
                match = definition['regex'].search(fragment)
                if not match:
                    continue
                
                key_found = match.group(0)
                leak_details = {"service": service, "repository": item['repository']['full_name'], "file": item['path'], "url": file_url, "key_snippet": key_found}
                found_leaks.append(leak_details)
                cache.add(file_url)
                log.log(LEAK_LEVEL, f"{ColorFormatter.YELLOW}{service}{ColorFormatter.RESET} key in {ColorFormatter.BOLD}{item['repository']['full_name']}{ColorFormatter.RESET}", extra={'custom_level_name': 'LEAK'})
                log.log(LEAK_LEVEL, f"  -> {ColorFormatter.UNDERLINE}{file_url}{ColorFormatter.RESET}", extra={'custom_level_name': 'LEAK'})

    log.info("--- Scan Complete ---")

    if found_leaks:
        print_scan_summary_table(found_leaks)
    
    log.info(f"Total new leaks found in this session: {ColorFormatter.BOLD}{ColorFormatter.GREEN}{len(found_leaks)}{ColorFormatter.RESET}")

    if args.output:
        try:
            existing_leaks = []
            if os.path.exists(args.output):
                 with open(args.output, 'r') as f_read:
                    try: existing_leaks = json.load(f_read)
                    except json.JSONDecodeError: pass
            
            existing_urls = {leak['url'] for leak in existing_leaks}
            new_leaks_to_add = [leak for leak in found_leaks if leak['url'] not in existing_urls]
            
            with open(args.output, 'w') as f_write:
                json.dump(existing_leaks + new_leaks_to_add, f_write, indent=2)
            log.info(f"Results saved to {ColorFormatter.UNDERLINE}{args.output}{ColorFormatter.RESET}")
        except IOError as e:
            log.error(f"Could not write to output file: {e}")
    
    save_cache(cache)
    log.info(f"Cache updated with {len(cache)} total items.")
    log.info("Please manually verify findings and report them responsibly.")

# --- Mode: ROTATE ---

def validate_key(service, key, definition):
    val_config = definition['validation']
    method, url = val_config['method'], val_config['url']
    headers, params = {}, {}

    auth_type = val_config['auth_type']
    if auth_type == 'bearer': headers['Authorization'] = f'Bearer {key}'
    elif auth_type == 'header': headers[val_config['header_name']] = key
    elif auth_type == 'query_param': params[val_config['param_name']] = key

    try:
        response = requests.request(method, url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            return True, "Active"
        elif response.status_code in [401, 403]:
            return False, "Invalid/Forbidden"
        elif response.status_code == 429:
            return False, "Rate-Limited"
        else:
            return False, f"HTTP {response.status_code}"
    except requests.exceptions.RequestException as e:
        return False, f"Request Failed ({e.__class__.__name__})"

def run_rotate(args):
    display_banner()
    log.info("--- KeyGuardian Key Rotator ---")
    service = args.service
    if service not in SERVICE_DEFINITIONS:
        log.critical(f"Service '{service}' is not defined. Available: {', '.join(SERVICE_DEFINITIONS.keys())}")
        sys.exit(1)
        
    if not os.path.exists(args.key_file):
        log.critical(f"Key file not found at '{args.key_file}'. Please run a scan first to generate it.")
        sys.exit(1)

    with open(args.key_file, 'r') as f:
        try:
            all_keys = json.load(f)
        except json.JSONDecodeError:
            log.critical(f"Could not parse JSON from '{args.key_file}'.")
            sys.exit(1)

    service_keys = [item for item in all_keys if item['service'] == service]
    if not service_keys:
        log.error(f"No keys for service '{service}' found in '{args.key_file}'.")
        sys.exit(1)

    log.log(ROTATE_LEVEL, f"Found {len(service_keys)} potential keys for {service}. Attempting to validate...", extra={'custom_level_name': 'ROTATE'})
    
    for item in service_keys:
        key = item['key_snippet']
        repo = item['repository']
        log.info(f"Testing key from {ColorFormatter.BOLD}{repo}{ColorFormatter.RESET}...")
        is_valid, reason = validate_key(service, key, SERVICE_DEFINITIONS[service])
        
        if is_valid:
            log.log(ROTATE_LEVEL, f"{ColorFormatter.GREEN}SUCCESS: Found a working {service} key.{ColorFormatter.RESET}", extra={'custom_level_name': 'ROTATE'})
            print(key) # Print the key to stdout for capture
            sys.exit(0)
        else:
            log.warning(f"  -> Key is not active. Reason: {reason}")
            
    log.error(f"Failed to find any working keys for {service} after trying {len(service_keys)} candidates.")
    sys.exit(1)

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="KeyGuardian: A tool for finding and managing AI API keys on GitHub.")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- Parser for 'scan' command ---
    parser_scan = subparsers.add_parser("scan", help="Scan GitHub for exposed API keys.")
    parser_scan.add_argument("--output", "-o", help="Save results to a JSON file.", metavar="FILENAME")
    parser_scan.add_argument("--services", "-s", help="Comma-separated list of services to scan.", default="all")
    parser_scan.add_argument("--workers", "-w", help="Number of concurrent threads.", type=int, default=5)
    parser_scan.add_argument("--no-forks", help="Exclude forked repositories.", action="store_true")
    parser_scan.add_argument("--log-file", help="Save detailed logs to a file.", metavar="LOGFILE")
    parser_scan.set_defaults(func=run_scan)

    # --- Parser for 'rotate' command ---
    parser_rotate = subparsers.add_parser("rotate", help="Fetch a validated, working API key from a file of found keys.")
    parser_rotate.add_argument("--service", "-s", required=True, help="The service for which to fetch a key (e.g., OpenAI).")
    parser_rotate.add_argument("--key-file", "-k", default="findings.json", help="Path to the JSON file containing found keys.", metavar="FILENAME")
    parser_rotate.set_defaults(func=run_rotate)

    args = parser.parse_args()
    log_file = getattr(args, 'log_file', None)
    setup_logging(log_file)
    args.func(args)

if __name__ == "__main__":
    main()
