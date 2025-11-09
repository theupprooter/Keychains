#  v.2.0.0 - Live Key Validation Update
import os
import requests
import time
import json
import re
import sys
import datetime
import math
import asyncio
import aiohttp
import argparse
from collections import Counter

# terminal UI
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
from rich.panel import Panel
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
    [bold]AI Key Scanner & Rotator v2.0.0[/bold]
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

async def check_rate_limit(headers, session):
    try:
        async with session.get("https://api.github.com/rate_limit", headers=headers) as r:
            r.raise_for_status()
            data = await r.json()
            return data['resources']['search']['remaining']
    except (aiohttp.ClientError, json.JSONDecodeError):
        return 0

async def run_queries_for_service(service, definition, headers, no_forks, progress, task_id, log_file, session, semaphore):
    dorks = definition['search_dorks']
    negatives = ' '.join([f'NOT "{n}"' for n in definition.get('negative_keywords', [])])
    unique_items_found = {}
    backoff_factor = 1

    for i, dork in enumerate(dorks):
        if progress:
            progress.update(task_id, description=f"[cyan]Scanning {service}[/cyan] (Query {i+1}/{len(dorks)})")
        
        full_query = f'{dork} {negatives}{EXCLUSIONS}' + (' -fork:true' if no_forks else '')
        params = {'q': full_query, 'per_page': 100}
        
        retries = 3
        while retries > 0:
            async with semaphore:
                try:
                    async with session.get('https://api.github.com/search/code', headers=headers, params=params, timeout=20) as response:
                        if response.status == 200:
                            backoff_factor = 1 # Reset backoff on success
                            data = await response.json()
                            for item in data.get('items', []):
                                unique_items_found[item['html_url']] = item
                            break # Success, move to next dork
                        elif response.status in [403, 429]: # Rate limit
                            retries -= 1
                            resp_headers = response.headers
                            reset_time = int(resp_headers.get('x-ratelimit-reset', time.time() + 60))
                            wait_duration = max(0, reset_time - time.time())
                            sleep_time = (wait_duration + 2) * backoff_factor

                            console.log(f"[bold red]Rate limit on {service}. Pausing for {sleep_time:.1f}s...[/bold red]")
                            await asyncio.sleep(sleep_time)
                            backoff_factor = min(backoff_factor * 2, 16) # Increase backoff
                        else:
                            response.raise_for_status() # Raise for other client/server errors
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    retries -= 1
                    log_error(f"Network error on {service} with dork '{dork}': {e}", log_file)
                    if retries <= 0: break
                    await asyncio.sleep(2 * (3 - retries)) # Simple backoff for network issues

        if progress:
            progress.update(task_id, advance=1)
    
    if progress:
        progress.update(task_id, description=f"[bold green]Finished {service}[/bold green]")
    return service, list(unique_items_found.values())


async def create_leak_issue(leak, token, log_file, session, semaphore):
    repo_full_name = leak['repository']
    headers = {'Authorization': f'token {token}', 'Accept': 'application/vnd.github.v3+json'}
    
    issue_title = f"Security Vulnerability: Hardcoded API Key in {leak['file']}"
    issue_body = ISSUE_BODY_TEMPLATE.format(
        file_path=leak['file'],
        timestamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    )
    
    payload = {"title": issue_title, "body": issue_body}
    url = f"https://api.github.com/repos/{repo_full_name}/issues"

    async with semaphore:
        try:
            async with session.post(url, headers=headers, json=payload, timeout=15) as response:
                if response.status == 201:
                    return "[green]Issue Created[/green]"
                elif response.status == 410:
                    log_error(f"Could not create issue for {repo_full_name}: Issues are disabled.", log_file)
                    return "[grey50]Issues N/A[/grey50]"
                else:
                    response.raise_for_status()
                    
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log_error(f"Failed to create issue for {repo_full_name}: {e}", log_file)
            return "[red]Issue Failed[/red]"

    return "[bold red]Issue Error[/bold red]"


async def run_scan(args):
    TOKEN = args.token or os.getenv('GITHUB_TOKEN')
    if not TOKEN:
        console.print("[bold red]GitHub token not found. Please provide one or set GITHUB_TOKEN.[/bold red]")
        return

    HEADERS = {'Authorization': f'token {TOKEN}', 'Accept': 'application/vnd.github.v3.text-match+json'}
    
    services_to_scan = {k: v for k, v in SERVICE_DEFINITIONS.items() if args.services.lower() == 'all' or k in args.services.split(',')}
    cache = load_cache()
    total_found_leaks = []
    validation_summary = Counter()

    config_panel = Panel(
        f"[b]Services[/b]: {', '.join(services_to_scan.keys())}\n"
        f"[b]Exclude Forks[/b]: {'Yes' if args.no_forks else 'No'}\n"
        f"[b]Validate Keys[/b]: {'[green]Yes[/green]' if args.validate else 'No'}\n"
        f"[b]Auto-Report (Issue)[/b]: {'[green]Yes[/green]' if args.report else 'No'}\n"
        f"[b]Duration[/b]: {f'{args.duration} mins' if args.duration > 0 else 'Run once'}",
        title="[bold blue]Scan Configuration[/bold blue]", border_style="blue"
    )
    console.print(config_panel)

    semaphore = asyncio.Semaphore(args.workers)
    
    async with aiohttp.ClientSession(headers=HEADERS) as session, aiohttp.ClientSession() as validation_session:
        initial_rate_limit = await check_rate_limit(HEADERS, session)
        if initial_rate_limit == 0:
            console.print("[bold red]Initial GitHub search rate limit is zero. Exiting.[/bold red]")
            return

        start_time = time.time()
        end_time = start_time + args.duration * 60
        
        run_cycle = 0
        while True:
            run_cycle += 1
            if args.duration > 0:
                console.print(f"\n[bold cyan]--- Starting Scan Cycle {run_cycle} ---[/bold cyan]")
            
            new_leaks_in_cycle = []
            scan_progress = Progress(SpinnerColumn(), TextColumn("[progress.description]", justify="left"), BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeElapsedColumn())
            
            with scan_progress as progress:
                scan_tasks = {s: progress.add_task(f"[cyan]Scanning {s}[/cyan]", total=len(d['search_dorks'])) for s, d in services_to_scan.items()}
                
                tasks = [run_queries_for_service(s, d, HEADERS, args.no_forks, progress, scan_tasks[s], args.error_log_file, session, semaphore) for s, d in services_to_scan.items()]
                
                results = await asyncio.gather(*tasks)

            for service, items in results:
                definition = SERVICE_DEFINITIONS[service]
                for item in items:
                    if item['html_url'] in cache: continue
                    match = definition['regex'].search(item['text_matches'][0]['fragment'])
                    if not match: continue
                    
                    key_found = match.group(0)
                    if not passes_heuristics(key_found, definition, item['path'], args.error_log_file): continue
                    
                    validation_status_text = "Not Checked"
                    validation_status_rich = "[grey50]Not Checked[/grey50]"
                    if args.validate:
                        is_valid, reason = await validate_key(service, key_found, definition, validation_session)
                        validation_status_text = reason
                        if is_valid:
                            validation_status_rich = f"[bold green]{reason}[/bold green]"
                        else:
                            validation_status_rich = f"[bold red]{reason}[/bold red]"

                    validation_summary[validation_status_text] += 1
                    confidence, conf_desc = get_path_confidence(item['path'])
                    leak_details = {
                        "service": service, "repository": item['repository']['full_name'], "file": item['path'],
                        "url": item['html_url'], "key_snippet": key_found, "confidence": confidence,
                        "confidence_description": conf_desc, "validation_status": validation_status_text,
                        "validation_status_rich": validation_status_rich, "issue_status": "[grey50]N/A[/grey50]"
                    }
                    
                    cache.add(item['html_url'])
                    new_leaks_in_cycle.append(leak_details)
            
            total_found_leaks.extend(new_leaks_in_cycle)

            if args.report and new_leaks_in_cycle:
                console.print(f"\n[bold]Found {len(new_leaks_in_cycle)} new leaks. Creating GitHub issues...[/bold]")
                report_tasks = [create_leak_issue(leak, TOKEN, args.error_log_file, session, semaphore) for leak in new_leaks_in_cycle]
                issue_statuses = await asyncio.gather(*report_tasks)
                for leak, status in zip(new_leaks_in_cycle, issue_statuses):
                    leak["issue_status"] = status
            
            if new_leaks_in_cycle:
                leaks_table = Table(title="[bold green]Newly Confirmed Leaks[/bold green]", expand=True)
                leaks_table.add_column("Service", style="cyan", no_wrap=True)
                leaks_table.add_column("Repository", style="magenta")
                leaks_table.add_column("File URL", style="yellow")
                leaks_table.add_column("Confidence", style="bold blue")
                leaks_table.add_column("Validation", style="white")
                leaks_table.add_column("Issue Status", style="green")

                for leak in new_leaks_in_cycle:
                    confidence_str = f"{int(leak['confidence']*100)}% ({leak['confidence_description']})"
                    leaks_table.add_row(leak['service'], leak['repository'], leak['url'], confidence_str, leak['validation_status_rich'], leak['issue_status'])
                console.print(leaks_table)
            else:
                console.print("\n[bold]No new leaks found in this cycle.[/bold]")

            if args.duration == 0 or time.time() >= end_time:
                break
            
            console.print(f"\nCycle complete. Waiting 60s...")
            await asyncio.sleep(60)

    # Build and display the final summary panel
    summary_text = f"Scan Complete. Found a total of [bold green]{len(total_found_leaks)}[/bold green] new leaks."
    if args.validate and total_found_leaks:
        status_colors = { "Active": "green", "Invalid/Forbidden": "red", "Rate-Limited": "yellow" }
        summary_items = []
        # Sort for consistent output
        for status, count in sorted(validation_summary.items()):
            color = status_colors.get(status, "white")
            summary_items.append(f"[{color}]{count} {status}[/{color}]")
        
        summary_text += f"\n\n[b]Validation Summary[/b]: {', '.join(summary_items)}"
    
    console.print(Panel(summary_text, title="[bold green]Scan Results[/bold green]", border_style="green"))
    
    if args.output and total_found_leaks:
        try:
            existing_leaks = []
            if os.path.exists(args.output):
                 with open(args.output, 'r') as f:
                    try: existing_leaks = json.load(f)
                    except json.JSONDecodeError: pass
            
            cleaned_leaks = []
            for leak in total_found_leaks:
                clean_leak = leak.copy()
                clean_leak.pop('validation_status_rich', None)
                clean_leak['issue_status'] = re.sub(r'\[/?.*?\]', '', clean_leak['issue_status'])
                cleaned_leaks.append(clean_leak)

            with open(args.output, 'w') as f:
                json.dump(existing_leaks + cleaned_leaks, f, indent=2)
            console.print(f"Results saved to [cyan u]{args.output}[/cyan u]")
        except IOError as e:
            log_error(f"Could not write to output file: {e}", args.error_log_file)
    
    save_cache(cache)

# --- Mode: ROTATE ---

async def validate_key(service, key, definition, session):
    val_config = definition['validation']
    headers, params = {'User-Agent': 'keychains-scanner/1.0'}, {}
    auth_type = val_config['auth_type']
    if auth_type == 'bearer': headers['Authorization'] = f'Bearer {key}'
    elif auth_type == 'header': headers[val_config['header_name']] = key
    elif auth_type == 'query_param': params[val_config['param_name']] = key

    try:
        async with session.request(val_config['method'], val_config['url'], headers=headers, params=params, timeout=5) as response:
            if response.status == 200: return True, "Active"
            elif response.status in [401, 403]: return False, "Invalid/Forbidden"
            elif response.status == 429: return False, "Rate-Limited"
            else: return False, f"HTTP {response.status}"
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        return False, f"Request Failed ({e.__class__.__name__})"

async def run_rotate(args):
    service = args.service
    if service not in SERVICE_DEFINITIONS:
        console.print(f"[bold red]Error: Service '{service}' is not defined.[/bold red]")
        log_error(f"Service '{service}' is not defined.", args.error_log_file)
        sys.exit(1)
        
    if not os.path.exists(args.key_file):
        console.print(f"[bold red]Error: Key file not found at '{args.key_file}'.[/bold red]")
        log_error(f"Key file not found at '{args.key_file}'.", args.error_log_file)
        sys.exit(1)

    with open(args.key_file, 'r') as f:
        try: all_keys = json.load(f)
        except json.JSONDecodeError:
            console.print(f"[bold red]Error: Could not parse JSON from '{args.key_file}'.[/bold red]")
            log_error(f"Could not parse JSON from '{args.key_file}'.", args.error_log_file)
            sys.exit(1)

    service_keys = [item for item in all_keys if item.get('service') == service]
    if not service_keys:
        console.print(f"[bold yellow]No keys for service '{service}' found in '{args.key_file}'.[/bold yellow]")
        log_error(f"No keys for service '{service}' found in '{args.key_file}'.", args.error_log_file)
        sys.exit(1)

    service_keys.reverse()
    service_keys.sort(key=lambda x: x.get('confidence', 0), reverse=True)

    console.print(f"Found [cyan]{len(service_keys)}[/cyan] potential keys for [bold]{service}[/bold]. Validating concurrently...")
    
    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(validate_key(service, item['key_snippet'], SERVICE_DEFINITIONS[service], session)) for item in service_keys]
        future_to_item = {task: item for task, item in zip(tasks, service_keys)}
        
        for future in asyncio.as_completed(tasks):
            item = future_to_item[future]
            repo = item.get('repository', 'N/A')
            try:
                is_valid, reason = await future
                if is_valid:
                    console.print(f"[bold green]SUCCESS: Found a working {service} key from [magenta]{repo}[/magenta].[/bold green]")
                    
                    if args.json_output:
                        print(json.dumps(item, indent=2))
                    else:
                        print(item['key_snippet'])
                    
                    for task in tasks: task.cancel() # Cancel remaining tasks
                    return
            except Exception as exc:
                log_error(f"An error occurred validating key from {repo}: {exc}", args.error_log_file)
    
    console.print(f"[bold red]Failed to find any working keys for {service} after checking all candidates.[/bold red]")
    log_error(f"Failed to find any working keys for {service}.", args.error_log_file)
    sys.exit(1)


# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(
        description="keychains: AI Key Scanner & Rotator. A powerful command-line tool for finding and validating exposed API keys on public GitHub repositories.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Run a basic scan for all services and show the results
  python keychains.ts scan

  # Scan for OpenAI keys, validate them, and create GitHub issues to report leaks
  python keychains.ts scan --services OpenAI --report --validate --output findings.json
  
  # Fetch a single working Cohere key from a file and print it for another program to use
  export COHERE_API_KEY=$(python keychains.ts rotate --service Cohere --key-file findings.json)
"""
    )
    parser.add_argument('--error-log-file', type=str, default="errors.log", help="File to log errors and non-critical information to.")
    
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    # --- Scan command parser ---
    scan_parser = subparsers.add_parser(
        'scan',
        help='Scan GitHub for exposed API keys.',
        description='Scans public GitHub repositories for exposed API keys using a variety of search dorks and heuristics. Displays results and can optionally report findings by creating issues.'
    )
    scan_parser.add_argument('--token', type=str, default=None, help='GitHub Personal Access Token. If not provided, defaults to GITHUB_TOKEN environment variable.')
    scan_parser.add_argument('--output', '-o', type=str, help='File to save JSON results of found leaks to.')
    scan_parser.add_argument('--services', '-s', type=str, default='all', help='Comma-separated list of services to scan for (e.g., OpenAI,Cohere). Defaults to "all".')
    scan_parser.add_argument('--workers', '-w', type=int, default=10, help='Max number of concurrent requests to GitHub.')
    scan_parser.add_argument('--no-forks', action='store_true', help='Exclude forked repositories from search results.')
    scan_parser.add_argument('--duration', '-d', type=int, default=0, help='Duration to run the scan in minutes. 0 means a single run, exiting after one cycle.')
    scan_parser.add_argument('--report', action='store_true', help='Automatically create a GitHub issue in the repository to report found leaks.')
    scan_parser.add_argument('--validate', action='store_true', help='Validate found keys against their respective service APIs to check if they are active.')
    scan_parser.set_defaults(func=run_scan)

    # --- Rotate command parser ---
    rotate_parser = subparsers.add_parser(
        'rotate',
        help='Get a single working API key from a file of candidates.',
        description='Reads a list of potential API keys from a JSON file (typically generated by the scan command), validates them concurrently, and prints the first working key it finds. Designed for scripting and CI/CD integration.'
    )
    rotate_parser.add_argument('--service', '-s', type=str, required=True, help='The service to get a key for (e.g., OpenAI). Must be one of the defined services.')
    rotate_parser.add_argument('--key-file', '-k', type=str, default='findings.json', help='The JSON file to read potential keys from.')
    rotate_parser.add_argument('--json-output', '-j', action='store_true', help='Output the result as a full JSON object instead of just the key string.')
    rotate_parser.set_defaults(func=run_rotate)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    
    if args.command:
        display_banner()
    
    if hasattr(args, 'func'):
        try:
            if asyncio.iscoroutinefunction(args.func):
                asyncio.run(args.func(args))
            else:
                args.func(args)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Operation cancelled by user.[/bold yellow]")
            sys.exit(0)

if __name__ == "__main__":
    main()
