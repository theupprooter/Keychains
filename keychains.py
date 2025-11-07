import os
import requests
import time
import json
import argparse
import re
import sys
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from github import Github, GithubException

# Rich for beautiful terminal UI
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.align import Align

# --- Configuration ---
console = Console(stderr=True, highlight=False)

# Search patterns, validation regex, and live validation endpoints
SERVICE_DEFINITIONS = {
    'OpenAI': {
        'pattern': 'sk-proj-[a-zA-Z0-9]{24} OR "sk-[a-zA-Z0-9]{48}"',
        'regex': re.compile(r'sk-(proj-)?[a-zA-Z0-9]{24,48}'),
        'validation': { 'method': 'GET', 'url': 'https://api.openai.com/v1/models', 'auth_type': 'bearer' }
    },
    'Anthropic': {
        'pattern': '"sk-ant-api03-[a-zA-Z0-9_-]{95}"',
        'regex': re.compile(r'sk-ant-api03-[a-zA-Z0-9_-]{95}'),
        'validation': { 'method': 'GET', 'url': 'https://api.anthropic.com/v1/ping', 'auth_type': 'header', 'header_name': 'x-api-key' }
    },
    'Cohere': {
        'pattern': '"[a-zA-Z0-9]{40}"',
        'query_prefix': 'COHERE_API_KEY=',
        'regex': re.compile(r'[a-zA-Z0-9]{40}'),
        'validation': { 'method': 'GET', 'url': 'https://api.cohere.ai/v1/models', 'auth_type': 'bearer' }
    },
    'HuggingFace': {
        'pattern': '"hf_[a-zA-Z0-9]{35}"',
        'regex': re.compile(r'hf_[a-zA-Z0-9]{35}'),
        'validation': { 'method': 'GET', 'url': 'https://api-inference.huggingface.co/models', 'auth_type': 'bearer' }
    },
    'GoogleAI': {
        'pattern': 'AIzaSy[a-zA-Z0-9_-]{33}',
        'regex': re.compile(r'AIzaSy[a-zA-Z0-9_-]{33}'),
        'validation': { 'method': 'GET', 'url': 'https://generativelanguage.googleapis.com/v1beta/models', 'auth_type': 'query_param', 'param_name': 'key' }
    },
}

# Common filename patterns to exclude from search
EXCLUSIONS = " -path:*.md -path:*.txt -path:*.lock -path:*.example -path:package.json -path:yarn.lock -path:pnpm-lock.yaml"
CACHE_FILE = ".keyguardian_cache.json"
PR_BODY_TEMPLATE = """### 🚨 Security Alert: Potential API Key Exposure

Hello! I am an automated security bot.

I've detected a potential API key in your repository. To protect your credentials, I have created this pull request to redact the exposed key.

- **File:** `{file_path}`
- **Detected at:** `{timestamp}`

Please review this change, invalidate the leaked key immediately with your service provider, and merge this PR.

---
*Reported by KeyGuardian, on behalf of @theuzae at Instagram.*
"""

# --- UI and Helper Functions ---
def display_banner():
    banner = """
  _  __       _                  _ _           
 | |/ /      | |                | (_)          
 | ' /  _ __ | | __ _ _   _  ___ | |_  _ __   __ _ 
 |  <  | '_ \\| |/ _` | | | |/ _ \\| | || '_ \\ / _` |
 | . \\ | | | | | (_| | |_| | (_) | | || | | | (_| |
 |_|\\_\\|_| |_|_\\__,_|\\__, |\\___/|_|_||_| |_|\\__, |
                      __/ |                 __/ |
                     |___/                 |___/ 
    [bold]AI Key Scanner & Rotator[/bold]
    """
    console.print(Panel(Align.center(banner, vertical="middle"), style="cyan"), highlight=True)

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
    if any(p in lower_fragment for p in placeholders): return True
    
    stripped_fragment = fragment.strip()
    if stripped_fragment.startswith('#') or stripped_fragment.startswith('//') or stripped_fragment.startswith('/*'): return True
    
    return False

# --- Mode: SCAN ---

def create_dashboard_layout():
    layout = Layout(name="root")
    layout.split(
        Layout(name="header", size=10),
        Layout(ratio=1, name="main"),
        Layout(size=3, name="footer")
    )
    layout["main"].split_row(Layout(name="side"), Layout(name="body", ratio=2))
    return layout

def get_leaks_table():
    table = Table(title="[bold green]Confirmed Leaks[/bold green]", expand=True)
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("Repository", style="magenta")
    table.add_column("File URL", style="yellow")
    table.add_column("Report PR", style="green")
    return table

def check_rate_limit(headers):
    try:
        response = requests.get("https://api.github.com/rate_limit", headers=headers)
        response.raise_for_status()
        data = response.json()['resources']['search']
        return data['remaining']
    except requests.exceptions.RequestException:
        return 0

def scan_service(service, definition, headers, no_forks, progress, task_id):
    pattern = definition.get('query_prefix', '') + definition['pattern']
    full_query = f'{pattern}{EXCLUSIONS}' + (' -fork:true' if no_forks else '')
    params = {'q': full_query, 'per_page': 100}
    
    try:
        response = requests.get('https://api.github.com/search/code', headers=headers, params=params)
        response.raise_for_status()
        results = response.json().get('items', [])
        progress.update(task_id, advance=1, description=f"[green]Scanned {service} ({len(results)} found)[/green]")
        return service, results
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            progress.update(task_id, description=f"[bold red]Rate limited on {service}. Waiting...[/bold red]")
            time.sleep(60)
        else:
            progress.update(task_id, description=f"[red]API error on {service}[/red]")
    except requests.exceptions.RequestException:
        progress.update(task_id, description=f"[red]Network error on {service}[/red]")
    
    return service, []

def create_pr_for_leak(leak, token, console):
    try:
        g = Github(token)
        user = g.get_user()
        repo_to_fork = g.get_repo(leak['repository'])

        # Fork the repository
        my_fork = user.create_fork(repo_to_fork)
        console.log(f"[grey50]Forked {repo_to_fork.full_name} to {my_fork.full_name}[/grey50]")

        time.sleep(5) # Give GitHub a moment to create the fork properly

        # Create a new branch
        branch_name = f"keyguardian-patch-{int(time.time())}"
        default_branch = my_fork.get_branch(my_fork.default_branch)
        my_fork.create_git_ref(ref=f"refs/heads/{branch_name}", sha=default_branch.commit.sha)

        # Get file content and redact key
        file_contents = my_fork.get_contents(leak['file'], ref=branch_name)
        decoded_content = file_contents.decoded_content.decode('utf-8')
        redacted_content = decoded_content.replace(leak['key_snippet'], '[REDACTED_BY_KEYGUARDIAN]')
        
        # Commit the change
        commit_message = f"chore: Redact exposed API key in {leak['file']}"
        my_fork.update_file(leak['file'], commit_message, redacted_content.encode('utf-8'), file_contents.sha, branch=branch_name)

        # Create Pull Request
        pr_body = PR_BODY_TEMPLATE.format(
            file_path=leak['file'],
            timestamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        )
        pr = repo_to_fork.create_pull(
            title=f"Security: Redact Exposed API Key in {leak['file']}",
            body=pr_body,
            head=f"{user.login}:{branch_name}",
            base=repo_to_fork.default_branch
        )
        return pr.html_url
    except GithubException as e:
        console.log(f"[red]GitHub API Error during reporting for {leak['repository']}: {e.data.get('message', str(e))}[/red]")
        return "Failed"
    except Exception as e:
        console.log(f"[red]An unexpected error occurred during reporting: {e}[/red]")
        return "Failed"

def run_scan(args):
    TOKEN = os.getenv('GITHUB_TOKEN')
    if not TOKEN:
        console.print("[bold red]GITHUB_TOKEN environment variable not set.[/bold red]")
        return

    HEADERS = {'Authorization': f'token {TOKEN}', 'Accept': 'application/vnd.github.v3.text-match+json'}
    if check_rate_limit(HEADERS) == 0:
        console.print("[bold red]Initial GitHub search rate limit is zero. Exiting.[/bold red]")
        return

    services_to_scan = {k: v for k, v in SERVICE_DEFINITIONS.items() if args.services.lower() == 'all' or k in args.services.split(',')}
    cache = load_cache()

    # Setup Dashboard
    layout = create_dashboard_layout()
    display_banner() # Print banner once outside live
    
    config_panel = Panel(
        f"[b]Services[/b]: {', '.join(services_to_scan.keys())}\n"
        f"[b]Exclude Forks[/b]: {'Yes' if args.no_forks else 'No'}\n"
        f"[b]Auto-Report[/b]: {'[green]Yes[/green]' if args.report else 'No'}\n"
        f"[b]Duration[/b]: {f'{args.duration} mins' if args.duration > 0 else 'Run once'}",
        title="[bold blue]Scan Configuration[/bold blue]",
        border_style="blue"
    )
    
    progress = Progress(
        TextColumn("[bold blue]{task.description}", justify="right"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn()
    )
    scan_task = progress.add_task("Scanning Services", total=len(services_to_scan))
    
    leaks_table = get_leaks_table()

    layout["side"].update(Panel(progress, title="[b]Progress[/b]"))
    layout["body"].update(leaks_table)
    layout["footer"].update(config_panel)

    total_found_leaks = []
    
    with Live(layout, console=console, screen=True, redirect_stderr=False, vertical_overflow="visible") as live:
        start_time = time.time()
        end_time = start_time + args.duration * 60
        
        while True:
            current_time = time.time()
            if args.duration > 0 and current_time >= end_time:
                break

            with ThreadPoolExecutor(max_workers=args.workers) as scan_executor, \
                 ThreadPoolExecutor(max_workers=args.workers) as report_executor:
                
                scan_futures = {scan_executor.submit(scan_service, s, d, HEADERS, args.no_forks, progress, scan_task): s for s, d in services_to_scan.items()}
                
                for future in as_completed(scan_futures):
                    service, items = future.result()
                    definition = SERVICE_DEFINITIONS[service]
                    
                    for item in items:
                        file_url = item['html_url']
                        if file_url in cache: continue

                        fragment = item['text_matches'][0]['fragment']
                        if is_false_positive(fragment): continue
                        
                        match = definition['regex'].search(fragment)
                        if not match: continue
                        
                        key_found = match.group(0)
                        leak_details = {
                            "service": service, 
                            "repository": item['repository']['full_name'], 
                            "file": item['path'], 
                            "url": file_url, 
                            "key_snippet": key_found
                        }
                        
                        cache.add(file_url)
                        total_found_leaks.append(leak_details)
                        
                        pr_url = "[grey50]N/A[/grey50]"
                        if args.report:
                            pr_url = "[yellow]Reporting...[/yellow]"
                            report_future = report_executor.submit(create_pr_for_leak, leak_details, TOKEN, console)
                            leak_details['report_future'] = report_future

                        leaks_table.add_row(service, item['repository']['full_name'], file_url, pr_url)
                        
            # Update PR links after they are created
            if args.report:
                for leak in total_found_leaks:
                    if 'report_future' in leak and leak['report_future'].done():
                        pr_result = leak['report_future'].result()
                        # This is tricky in a live table update; for simplicity, we print results to console log
                        # A more complex state management would be needed to update rows.
                        del leak['report_future']


            if args.duration == 0:
                break
            
            live.console.log(f"Cycle complete. Waiting 60s...")
            time.sleep(60)
            progress.reset(scan_task)

    console.print(Panel(f"Scan Complete. Found [bold green]{len(total_found_leaks)}[/bold green] new leaks.", style="bold green"))
    
    if args.output:
        try:
            existing_leaks = []
            if os.path.exists(args.output):
                 with open(args.output, 'r') as f_read:
                    try: existing_leaks = json.load(f_read)
                    except json.JSONDecodeError: pass
            
            for leak in total_found_leaks:
                if 'report_future' in leak: del leak['report_future'] # Don't save future objects

            with open(args.output, 'w') as f_write:
                json.dump(existing_leaks + total_found_leaks, f_write, indent=2)
            console.print(f"Results saved to [cyan u]{args.output}[/cyan u]")
        except IOError as e:
            console.print(f"[bold red]Could not write to output file: {e}[/bold red]")
    
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
        console.print(f"[bold red]Service '{service}' is not defined. Available: {', '.join(SERVICE_DEFINITIONS.keys())}[/bold red]")
        sys.exit(1)
        
    if not os.path.exists(args.key_file):
        console.print(f"[bold red]Key file not found at '{args.key_file}'. Please run a scan first to generate it.[/bold red]")
        sys.exit(1)

    with open(args.key_file, 'r') as f:
        try: all_keys = json.load(f)
        except json.JSONDecodeError:
            console.print(f"[bold red]Could not parse JSON from '{args.key_file}'.[/bold red]")
            sys.exit(1)

    service_keys = [item for item in all_keys if item['service'] == service]
    if not service_keys:
        console.print(f"[bold red]No keys for service '{service}' found in '{args.key_file}'.[/bold red]")
        sys.exit(1)

    console.print(f"Found [cyan]{len(service_keys)}[/cyan] potential keys for [bold]{service}[/bold]. Validating...")
    
    for item in service_keys:
        key = item['key_snippet']
        console.print(f"Testing key from [magenta]{item['repository']}[/magenta]...")
        is_valid, reason = validate_key(service, key, SERVICE_DEFINITIONS[service])
        
        if is_valid:
            console.print(f"[bold green]SUCCESS: Found a working {service} key.[/bold green]")
            print(key) # Print the key to stdout for capture
            sys.exit(0)
        else:
            console.print(f"  -> [yellow]Key is not active. Reason: {reason}[/yellow]")
            
    console.print(f"[bold red]Failed to find any working keys for {service} after trying {len(service_keys)} candidates.[/bold red]")
    sys.exit(1)

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="KeyGuardian: A tool for finding and managing AI API keys on GitHub.")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Parser for 'scan' command
    parser_scan = subparsers.add_parser("scan", help="Scan GitHub for exposed API keys with a live dashboard.")
    parser_scan.add_argument("--output", "-o", help="Save results to a JSON file.", metavar="FILENAME")
    parser_scan.add_argument("--services", "-s", help="Comma-separated list of services to scan.", default="all")
    parser_scan.add_argument("--workers", "-w", help="Number of concurrent threads.", type=int, default=5)
    parser_scan.add_argument("--no-forks", help="Exclude forked repositories.", action="store_true")
    parser_scan.add_argument("--duration", "-d", help="Duration to run the scan in minutes.", type=int, default=0)
    parser_scan.add_argument("--report", help="Automatically create a pull request to fix found leaks.", action="store_true")
    parser_scan.set_defaults(func=run_scan)

    # Parser for 'rotate' command
    parser_rotate = subparsers.add_parser("rotate", help="Fetch a validated, working API key from a file.")
    parser_rotate.add_argument("--service", "-s", required=True, help="The service for which to fetch a key (e.g., OpenAI).")
    parser_rotate.add_argument("--key-file", "-k", default="findings.json", help="Path to the JSON file with keys.", metavar="FILENAME")
    parser_rotate.set_defaults(func=run_rotate)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
