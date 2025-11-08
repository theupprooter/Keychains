import os
import requests
import time
import json
import re
import sys
import datetime
import math
import threading
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# BULLSHIT BASICALLY 
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.align import Align

# --- Configuration ---
console = Console(stderr=True, highlight=False)

# Confidence scoring based on file path patterns
PATH_CONFIDENCE = {
    re.compile(r'\.env(\.|$)', re.IGNORECASE): (0.99, "Environment File"),
    re.compile(r'^\.env', re.IGNORECASE): (0.99, "Environment File"),
    re.compile(r'credentials|secrets', re.IGNORECASE): (0.95, "Credentials/Secrets File"),
    re.compile(r'settings\.py$', re.IGNORECASE): (0.90, "Django/Python Settings"),
    re.compile(r'\/initializers\/', re.IGNORECASE): (0.85, "Rails Initializer"),
    re.compile(r'config\.py|config\.json|config\.yml', re.IGNORECASE): (0.85, "Configuration File"),
    re.compile(r'docker-compose\.yml', re.IGNORECASE): (0.80, "Docker Compose"),
    re.compile(r'test', re.IGNORECASE): (0.30, "Test File"),
    re.compile(r'example|sample|demo', re.IGNORECASE): (0.10, "Example/Demo Code"),
    re.compile(r'\.md$|\.txt$', re.IGNORECASE): (0.05, "Documentation"),
}

# service definitions
SERVICE_DEFINITIONS = {
    'OpenAI': {
        'search_dorks': [
            '("sk-proj-" OR "sk-") AND ("OPENAI_API_KEY" OR "openai.api_key")',
            '("sk-proj-" OR "sk-") AND ("os.getenv" OR "process.env")',
            '("sk-proj-" OR "sk-") filename:.env',
            '("sk-proj-" OR "sk-") language:python "import openai"',
            '("sk-proj-" OR "sk-") language:javascript "new OpenAI"',
            '("sk-proj-" OR "sk-") language:bash export',
        ],
        'negative_keywords': ['example', 'placeholder', 'your-api-key', 'YOUR_API_KEY', 'xxxxxxxx'],
        'regex': re.compile(r'sk-(proj-)?[a-zA-Z0-9]{24,48}'),
        'validation': { 'method': 'GET', 'url': 'https://api.openai.com/v1/models', 'auth_type': 'bearer' },
        'entropy_threshold': 4.0
    },
    'Anthropic': {
        'search_dorks': [
            '"sk-ant-api03-" AND ("ANTHROPIC_API_KEY" OR "anthropic.api_key")',
            '"sk-ant-api03-" filename:config.py',
            '"sk-ant-api03-" language:typescript "Anthropic"',
            '"sk-ant-api03-" filename:secrets.toml'
        ],
        'negative_keywords': ['example', 'placeholder'],
        'regex': re.compile(r'sk-ant-api03-[a-zA-Z0-9_-]{95}'),
        'validation': { 'method': 'GET', 'url': 'https://api.anthropic.com/v1/ping', 'auth_type': 'header', 'header_name': 'x-api-key' },
        'entropy_threshold': 4.5
    },
    'Cohere': {
        'search_dorks': [
            '("COHERE_API_KEY" OR "cohere.Client" OR "CohereClient") -test -example',
            'language:python "import cohere" "api_key="',
            'language:javascript "new CohereClient("',
        ],
        'negative_keywords': ['placeholder', 'YOUR_COHERE_API_KEY'],
        'regex': re.compile(r'[a-zA-Z0-9]{40}'),
        'validation': { 'method': 'GET', 'url': 'https://api.cohere.ai/v1/models', 'auth_type': 'bearer' },
        'entropy_threshold': 3.8
    },
    'HuggingFace': {
        'search_dorks': [
            '"hf_" AND ("HUGGING_FACE_HUB_TOKEN" OR "HF_TOKEN")',
            '"huggingface_hub.login(token="hf_"',
            '"hf_" filename:secrets.sh',
            '"hf_" filename:.env'
        ],
        'negative_keywords': ['example', 'YOUR_TOKEN_HERE'],
        'regex': re.compile(r'hf_[a-zA-Z0-9]{35}'),
        'validation': { 'method': 'GET', 'url': 'https://api-inference.huggingface.co/models', 'auth_type': 'bearer' },
        'entropy_threshold': 4.2
    },
    'GoogleAI': {
        'search_dorks': [
            '"AIzaSy" AND ("GOOGLE_API_KEY" OR "GEMINI_API_KEY")',
            '"genai.configure(api_key=\\"AIzaSy"', # Escaped quote for exact match
            '"AIzaSy" path:app/src/main',
            '"AIzaSy" filename:.env',
        ],
        'negative_keywords': ['placeholder', 'YOUR_GOOGLE_API_KEY'],
        'regex': re.compile(r'AIzaSy[a-zA-Z0-9_-]{33}'),
        'validation': { 'method': 'GET', 'url': 'https://generativelanguage.googleapis.com/v1beta/models', 'auth_type': 'query_param', 'param_name': 'key' },
        'entropy_threshold': 4.3
    },
    'AWS': {
        'search_dorks': [
            '("AKIA" OR "ASIA") AND ("AWS_ACCESS_KEY_ID" OR "aws_access_key")',
            '"AKIA" filename:credentials',
            '"AKIA" filename:config',
            '"AWS_SECRET_ACCESS_KEY" AND ("AKIA" OR "ASIA")',
            'boto3.client "aws_access_key_id"',
        ],
        'negative_keywords': ['AKIAEXAMPLE', 'ASIAEXAMPLE', 'placeholder'],
        'regex': re.compile(r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
        'validation': {
            'method': 'GET',
            'url': 'https://iam.amazonaws.com/?Action=GetUser&Version=2010-05-08',
            'auth_type': 'bearer' # Note: Fails safely due to AWS's complex auth. Detection only.
        },
        'entropy_threshold': 4.0
    },
    'Slack': {
        'search_dorks': [
            '("xoxb-" OR "xoxp-") AND ("SLACK_API_TOKEN" OR "SLACK_BOT_TOKEN")',
            '"xoxb-" filename:.env',
            '"xoxp-" language:python "slack_sdk"',
            'slack_bolt "token=" "xoxb-"',
        ],
        'negative_keywords': ['example', 'placeholder'],
        'regex': re.compile(r'xox[baprs]-(\d{10,13}-){2}[a-zA-Z0-9]{24,32}'),
        'validation': { 'method': 'POST', 'url': 'https://slack.com/api/auth.test', 'auth_type': 'bearer' },
        'entropy_threshold': 4.5
    },
    'Stripe': {
        'search_dorks': [
            '("sk_live_" OR "rk_live_") AND ("STRIPE_API_KEY" OR "stripe.api_key")',
            '"sk_live_" filename:config',
            '"rk_live_" filename:.env',
            'language:php "Stripe::setApiKey(\\"sk_live_"',
        ],
        'negative_keywords': ['sk_test_', 'pk_live_', 'pk_test_', 'example'],
        'regex': re.compile(r'(sk|rk)_(live)_[0-9a-zA-Z]{24,99}'),
        'validation': { 'method': 'GET', 'url': 'https://api.stripe.com/v1/customers?limit=1', 'auth_type': 'bearer' },
        'entropy_threshold': 4.3
    },
}

# Common filename patterns to exclude from search
EXCLUSIONS = " -path:*.md -path:*.txt -path:*.lock -path:*.example -path:package.json -path:yarn.lock -path:pnpm-lock.yaml"
CACHE_FILE = ".keychains_cache.json"
ISSUE_BODY_TEMPLATE = """Hey :) this issue was automated through one of my programs aka keychains because it found a hard coded api key laying around.

Here is more information:
- **File containing the key:** `{file_path}`
- **Detected at:** `{timestamp}`

This issue was created to alert you about the exposed key. For security, you should **invalidate the key immediately** and then purge it from your repository's history.

Stay safe!
"""

# --- UI and Helper Functions ---
class RateLimitHandler:
    """Manages GitHub API rate limits with exponential backoff in a thread-safe manner."""
    def __init__(self, log_file):
        self._lock = threading.Lock()
        self._backoff_factor = 1
        self._log_file = log_file

    def handle_error(self, headers):
        """Called when a 403 rate limit error occurs. Sleeps the current thread."""
        with self._lock:
            reset_time = int(headers.get('x-ratelimit-reset', time.time() + 60))
            wait_duration = max(0, reset_time - time.time())
            sleep_time = (wait_duration + 2) * self._backoff_factor
            
            console.log(f"[bold red]Rate limit hit! Applying backoff factor {self._backoff_factor:.1f}. Pausing for {sleep_time:.1f}s...[/bold red]")
            log_error(f"Rate limit exceeded. Backoff factor: {self._backoff_factor}. Pausing thread for {sleep_time:.1f}s.", self._log_file)
            
            self._backoff_factor = min(self._backoff_factor * 2, 16)
        
        time.sleep(sleep_time)

    def request_succeeded(self):
        """Resets the backoff factor after a successful request."""
        with self._lock:
            if self._backoff_factor > 1:
                self._backoff_factor = 1
                log_error("API request succeeded, resetting backoff factor to 1.", self._log_file)

def display_banner():
    banner = """
     _  __           _                 _               
    | |/ /          | |               (_)              
    | ' /  _ __   __| | __ _ _ __ __ _ _ _ __   __ _ 
    |  <  | '_ \\ / _` |/ _` | '__/ _` | | '_ \\ / _` |
    | . \\ | | | | (_| | (_| | | | (_| | | | | | (_| |
    |_|\\_\\|_| |_|\\__,_|\\__,_|_|  \\__,_|_|_| |_|\\__, |
                                               __/ |
                                              |___/ 
    [bold]AI Key Scanner & Rotator[/bold]
    """
    console.print(Panel(Align.center(banner, vertical="middle"), style="cyan"), highlight=True)

def log_error(message, log_file):
    if not log_file: return
    try:
        with open(log_file, 'a') as f:
            timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            f.write(f"[{timestamp}] {message}\n")
    except IOError as e:
        console.print(f"[bold red]CRITICAL: Could not write to error log file '{log_file}': {e}[/bold red]")

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            try: return set(json.load(f))
            except json.JSONDecodeError: return set()
    return set()

def save_cache(cache_data):
    with open(CACHE_FILE, 'w') as f:
        json.dump(list(cache_data), f)

def calculate_entropy(s: str) -> float:
    if not s or len(s) == 0: return 0.0
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def get_path_confidence(path: str) -> tuple[float, str]:
    for pattern, (score, desc) in PATH_CONFIDENCE.items():
        if pattern.search(path):
            return score, desc
    return 0.2, "Generic Code File"

def passes_heuristics(key_candidate, service_def, file_path, log_file):
    entropy = calculate_entropy(key_candidate)
    entropy_threshold = service_def.get('entropy_threshold', 3.5)
    if entropy < entropy_threshold:
        log_error(f"Rejected key '{key_candidate[:10]}...' due to low entropy ({entropy:.2f} < {entropy_threshold}).", log_file)
        return False

    confidence, _ = get_path_confidence(file_path)
    if confidence < 0.15:
        log_error(f"Rejected key from low-confidence path '{file_path}' (Confidence: {confidence:.2f}).", log_file)
        return False
        
    return True

# --- Mode: SCAN ---

def create_dashboard_layout():
    layout = Layout(name="root")
    layout.split(Layout(name="header", size=10), Layout(ratio=1, name="main"), Layout(size=4, name="footer"))
    layout["main"].split_row(Layout(name="side"), Layout(name="body", ratio=2))
    return layout

def get_leaks_table():
    table = Table(title="[bold green]Confirmed Leaks[/bold green]", expand=True)
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("Repository", style="magenta")
    table.add_column("File URL", style="yellow")
    table.add_column("Confidence", style="bold blue")
    table.add_column("Issue Status", style="green")
    return table

def check_rate_limit(headers):
    try:
        r = requests.get("https://api.github.com/rate_limit", headers=headers)
        r.raise_for_status()
        return r.json()['resources']['search']['remaining']
    except requests.exceptions.RequestException:
        return 0

def update_countdown(end_time, duration, countdown_container, stop_event):
    """A thread target function to update the countdown timer every second."""
    while not stop_event.is_set():
        if duration > 0:
            remaining_seconds = max(0, end_time - time.time())
            if remaining_seconds == 0:
                stop_event.set() # Signal main thread that time is up
            
            mins, secs = divmod(int(remaining_seconds), 60)
            countdown_text = f"[bold yellow]{mins:02d}:{secs:02d}[/bold yellow]"
        else:
            countdown_text = "Single Run"

        countdown_panel = Panel(Align.center(countdown_text, vertical="middle"), title="[bold blue]Time Remaining[/bold blue]", border_style="blue")
        countdown_container.update(countdown_panel)

        if duration == 0:
            break
        
        time.sleep(1)

def run_queries_for_service(service, definition, headers, no_forks, progress, task_id, log_file, rate_limit_handler):
    dorks = definition['search_dorks']
    negatives = ' '.join([f'NOT "{n}"' for n in definition.get('negative_keywords', [])])
    unique_items_found = {}

    for i, dork in enumerate(dorks):
        progress.update(task_id, description=f"[cyan]Scanning {service}[/cyan] (Query {i+1}/{len(dorks)})")
        
        full_query = f'{dork} {negatives}{EXCLUSIONS}' + (' -fork:true' if no_forks else '')
        params = {'q': full_query, 'per_page': 100}
        
        retries = 3
        while retries > 0:
            try:
                response = requests.get('https://api.github.com/search/code', headers=headers, params=params)
                response.raise_for_status()
                rate_limit_handler.request_succeeded()
                for item in response.json().get('items', []):
                    unique_items_found[item['html_url']] = item
                break
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403 and 'rate limit exceeded' in e.response.text.lower():
                    retries -= 1
                    rate_limit_handler.handle_error(e.response.headers)
                    if retries > 0:
                        progress.update(task_id, description=f"[bold yellow]Rate limited on {service}. Retrying... ({retries} left)[/bold yellow]")
                    else:
                        log_error(f"API error on {service}: Failed dork '{dork}' after multiple retries.", log_file)
                else:
                    log_error(f"API error on {service} with dork '{dork}': {e}", log_file)
                    break
            except requests.exceptions.RequestException as e:
                log_error(f"Network error on {service}: {e}", log_file)
                break
        progress.update(task_id, advance=1)

    progress.update(task_id, description=f"[bold green]Finished {service}[/bold green]")
    return service, list(unique_items_found.values())

def create_leak_issue(leak, token, log_file):
    repo_full_name = leak['repository']
    headers = {'Authorization': f'token {token}', 'Accept': 'application/vnd.github.v3+json'}
    
    issue_title = f"Security Vulnerability: Hardcoded API Key in {leak['file']}"
    issue_body = ISSUE_BODY_TEMPLATE.format(
        file_path=leak['file'],
        timestamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    )
    
    payload = {"title": issue_title, "body": issue_body}
    url = f"https://api.github.com/repos/{repo_full_name}/issues"

    try:
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 201:
            return "[green]Issue Created[/green]"
        elif response.status_code == 410:
            log_error(f"Could not create issue for {repo_full_name}: Issues are disabled.", log_file)
            return "[grey50]Issues N/A[/grey50]"
        else:
            response.raise_for_status()
            
    except requests.exceptions.RequestException as e:
        log_error(f"Failed to create issue for {repo_full_name}: {e}", log_file)
        return "[red]Issue Failed[/red]"

    return "[bold red]Issue Error[/bold red]"


def run_scan(args):
    TOKEN = args.token or os.getenv('GITHUB_TOKEN')
    if not TOKEN:
        console.print("[bold red]GitHub token not found. Please provide one or set GITHUB_TOKEN.[/bold red]")
        return

    HEADERS = {'Authorization': f'token {TOKEN}', 'Accept': 'application/vnd.github.v3.text-match+json'}
    if check_rate_limit(HEADERS) == 0:
        console.print("[bold red]Initial GitHub search rate limit is zero. Exiting.[/bold red]")
        return
        
    rate_limit_handler = RateLimitHandler(args.error_log_file)
    services_to_scan = {k: v for k, v in SERVICE_DEFINITIONS.items() if args.services.lower() == 'all' or k in args.services.split(',')}
    cache = load_cache()

    layout = create_dashboard_layout()
    display_banner()
    
    config_panel = Panel(
        f"[b]Services[/b]: {', '.join(services_to_scan.keys())}\n"
        f"[b]Exclude Forks[/b]: {'Yes' if args.no_forks else 'No'}\n"
        f"[b]Auto-Report (Issue)[/b]: {'[green]Yes[/green]' if args.report else 'No'}\n"
        f"[b]Duration[/b]: {f'{args.duration} mins' if args.duration > 0 else 'Run once'}",
        title="[bold blue]Scan Configuration[/bold blue]", border_style="blue"
    )
    
    progress = Progress(SpinnerColumn(), TextColumn("[progress.description]", justify="left"), BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeElapsedColumn())
    leaks_table = get_leaks_table()

    layout["side"].update(Panel(progress, title="[b]Progress[/b]"))
    layout["body"].update(leaks_table)

    countdown_container = Layout(name="countdown")
    footer_layout = Layout()
    footer_layout.split_row(config_panel, countdown_container)
    layout["footer"].update(footer_layout)

    total_found_leaks = []
    
    with Live(layout, console=console, screen=True, redirect_stderr=False, vertical_overflow="visible") as live:
        start_time = time.time()
        end_time = start_time + args.duration * 60
        
        stop_countdown_event = threading.Event()
        countdown_thread = threading.Thread(target=update_countdown, args=(end_time, args.duration, countdown_container, stop_countdown_event))
        countdown_thread.start()

        while not stop_countdown_event.is_set():
            scan_tasks = {s: progress.add_task(f"[cyan]Scanning {s}[/cyan]", total=len(d['search_dorks'])) for s, d in services_to_scan.items()}

            with ThreadPoolExecutor(max_workers=args.workers) as scan_executor, ThreadPoolExecutor(max_workers=args.workers) as report_executor:
                scan_futures = {scan_executor.submit(run_queries_for_service, s, d, HEADERS, args.no_forks, progress, scan_tasks[s], args.error_log_file, rate_limit_handler): s for s, d in services_to_scan.items()}
                
                report_futures_map = {}

                for future in as_completed(scan_futures):
                    service, items = future.result()
                    definition = SERVICE_DEFINITIONS[service]
                    
                    for item in items:
                        if item['html_url'] in cache: continue
                        match = definition['regex'].search(item['text_matches'][0]['fragment'])
                        if not match: continue
                        
                        key_found = match.group(0)
                        if not passes_heuristics(key_found, definition, item['path'], args.error_log_file): continue
                        
                        confidence, conf_desc = get_path_confidence(item['path'])
                        
                        leak_details = { "service": service, "repository": item['repository']['full_name'], "file": item['path'], "url": item['html_url'], "key_snippet": key_found, "confidence": confidence, "confidence_description": conf_desc }
                        
                        cache.add(item['html_url'])
                        total_found_leaks.append(leak_details)
                        
                        issue_status = "[grey50]N/A[/grey50]"
                        if args.report:
                            issue_status = "[yellow]Creating Issue...[/yellow]"
                            report_future = report_executor.submit(create_leak_issue, leak_details, TOKEN, args.error_log_file)
                            report_futures_map[report_future] = (leaks_table.row_count, 4) # (row_index, col_index)

                        confidence_str = f"{int(confidence*100)}% ({conf_desc})"
                        leaks_table.add_row(service, item['repository']['full_name'], item['html_url'], confidence_str, issue_status)

                for future in as_completed(report_futures_map):
                    row, col = report_futures_map[future]
                    issue_status_result = future.result()
                    leaks_table.rows[row].cells[col] = issue_status_result
                    leaks_table.rows[row].end_section = True


            if args.duration == 0: break
            
            # Check event again before sleeping
            if stop_countdown_event.is_set(): break

            live.console.log(f"Cycle complete. Waiting 60s...")
            time.sleep(60)
            for task_id in scan_tasks.values(): progress.remove_task(task_id)

        stop_countdown_event.set()
        countdown_thread.join()

    console.print(Panel(f"Scan Complete. Found [bold green]{len(total_found_leaks)}[/bold green] new leaks.", style="bold green"))
    
    if args.output:
        try:
            existing_leaks = []
            if os.path.exists(args.output):
                 with open(args.output, 'r') as f:
                    try: existing_leaks = json.load(f)
                    except json.JSONDecodeError: pass
            
            with open(args.output, 'w') as f:
                json.dump(existing_leaks + total_found_leaks, f, indent=2)
            console.print(f"Results saved to [cyan u]{args.output}[/cyan u]")
        except IOError as e:
            log_error(f"Could not write to output file: {e}", args.error_log_file)
    
    save_cache(cache)

# --- Mode: ROTATE ---

def validate_key(service, key, definition):
    val_config = definition['validation']
    headers, params = {}, {}
    auth_type = val_config['auth_type']
    if auth_type == 'bearer': headers['Authorization'] = f'Bearer {key}'
    elif auth_type == 'header': headers[val_config['header_name']] = key
    elif auth_type == 'query_param': params[val_config['param_name']] = key

    try:
        response = requests.request(val_config['method'], val_config['url'], headers=headers, params=params, timeout=5)
        if response.status_code == 200: return True, "Active"
        elif response.status_code in [401, 403]: return False, "Invalid/Forbidden"
        elif response.status_code == 429: return False, "Rate-Limited"
        else: return False, f"HTTP {response.status_code}"
    except requests.exceptions.RequestException as e:
        return False, f"Request Failed ({e.__class__.__name__})"

def run_rotate(args):
    display_banner()
    service = args.service
    if service not in SERVICE_DEFINITIONS:
        log_error(f"Service '{service}' is not defined.", args.error_log_file)
        sys.exit(1)
        
    if not os.path.exists(args.key_file):
        log_error(f"Key file not found at '{args.key_file}'.", args.error_log_file)
        sys.exit(1)

    with open(args.key_file, 'r') as f:
        try: all_keys = json.load(f)
        except json.JSONDecodeError:
            log_error(f"Could not parse JSON from '{args.key_file}'.", args.error_log_file)
            sys.exit(1)

    service_keys = [item for item in all_keys if item['service'] == service]
    if not service_keys:
        log_error(f"No keys for service '{service}' found in '{args.key_file}'.", args.error_log_file)
        sys.exit(1)

    console.print(f"Found [cyan]{len(service_keys)}[/cyan] potential keys for [bold]{service}[/bold]. Validating...")
    
    for item in service_keys:
        key, repo = item['key_snippet'], item['repository']
        console.print(f"Testing key from [magenta]{repo}[/magenta]...")
        is_valid, reason = validate_key(service, key, SERVICE_DEFINITIONS[service])
        
        if is_valid:
            console.print(f"[bold green]SUCCESS: Found a working {service} key.[/bold green]")
            print(key)
            sys.exit(0)
        else:
            log_error(f"Key from {repo} is not active. Reason: {reason}", args.error_log_file)
            
    log_error(f"Failed to find any working keys for {service}.", args.error_log_file)
    sys.exit(1)

# --- Main Execution ---
def get_input(prompt, default=None, optional=False):
    prompt_text = f"{prompt} "
    if default is not None: prompt_text += f"[default: {default}]: "
    elif optional: prompt_text += f"[optional, press Enter to skip]: "
    else: prompt_text += ": "
    value = input(prompt_text).strip()
    return value or (default if default is not None else value)

def get_bool_input(prompt, default='n'):
    val = input(f"{prompt} (y/n) [default: {default}]: ").lower().strip() or default
    return val == 'y'

def get_int_input(prompt, default=0):
    while True:
        val_str = input(f"{prompt} [default: {default}]: ").strip() or str(default)
        try: return int(val_str)
        except ValueError: console.print("[bold red]Invalid input. Please enter a number.[/bold red]")

def main():
    display_banner()
    
    command = ""
    while command not in ["scan", "rotate"]:
        command = get_input("Enter command (scan / rotate)").lower()

    if command == "scan":
        console.print("\n--- [bold blue]Configure Scan Parameters[/bold blue] ---\n")
        
        token = get_input("Enter GitHub Token (or press Enter to use GITHUB_TOKEN env var)", optional=True)
        output = get_input("Enter filename to save results (e.g., findings.json)", optional=True)
        services = get_input("Services to scan (comma-separated or 'all')", default="all")
        workers = get_int_input("Number of concurrent workers", default=5)
        no_forks = get_bool_input("Exclude forked repositories from search results?", default='n')
        duration = get_int_input("Duration to run in minutes (0 for single run)", default=0)
        report = get_bool_input("Automatically create a GitHub issue to report the leak?", default='n')
        error_log_file = get_input("Enter filename to log errors (e.g., errors.log)", optional=True)

        class Args: pass
        args = Args()
        args.token, args.output, args.services, args.workers, args.no_forks, args.duration, args.report, args.error_log_file = \
            token or None, output or None, services, workers, no_forks, duration, report, error_log_file or None
        
        run_scan(args)

    elif command == "rotate":
        console.print("\n--- [bold blue]Configure Key Rotation[/bold blue] ---\n")
        
        service = ""
        while not service or service not in SERVICE_DEFINITIONS:
            service = get_input(f"Enter the service for the key (e.g., OpenAI)").strip()
            if service and service not in SERVICE_DEFINITIONS:
                console.print(f"[bold red]Invalid. Choose from: {', '.join(SERVICE_DEFINITIONS.keys())}[/bold red]")
        
        key_file = get_input("Path to the JSON file with keys", default="findings.json")
        error_log_file = get_input("Enter filename to log errors", optional=True)

        class Args: pass
        args = Args()
        args.service, args.key_file, args.error_log_file = service, key_file, error_log_file or None
        run_rotate(args)


if __name__ == "__main__":
    main()
