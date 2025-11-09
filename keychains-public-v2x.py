# keychains.ts v3.0.0 - The Monster Update
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
from collections import Counter, deque
from typing import Optional, Dict, Any, List, Set, Tuple
from itertools import product

try:
    from keyguardian import KeyGuardian, collect_training_data
except ImportError:
    KeyGuardian = None
    collect_training_data = None

try:
    import yaml
except ImportError:
    yaml = None

# --- Configuration ---

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

SERVICE_DEFINITIONS = {
    'OpenAI': {
        'dork_components': {
            'keys': ['"sk-proj-"', '"sk-"'],
            'vars': ['"OPENAI_API_KEY"', '"openai.api_key"'],
            'patterns': ['"os.getenv"', '"process.env"'],
            'filenames': ['filename:.env', 'filename:secrets.toml'],
            'extensions': ['extension:py', 'extension:js', 'extension:sh']
        },
        'negative_keywords': ['example', 'placeholder', 'your-api-key', 'YOUR_API_KEY', 'xxxxxxxx'],
        'regex': re.compile(r'sk-(proj-)?[a-zA-Z0-9]{24,48}'),
        'validation': { 'method': 'GET', 'url': 'https://api.openai.com/v1/models', 'auth_type': 'bearer' },
        'entropy_threshold': 4.0
    },
    'Anthropic': {
        'dork_components': {
            'keys': ['"sk-ant-api03-"'],
            'vars': ['"ANTHROPIC_API_KEY"'],
            'filenames': ['filename:config.py', 'filename:secrets.toml'],
            'extensions': ['extension:py', 'extension:ts']
        },
        'negative_keywords': ['example', 'placeholder'],
        'regex': re.compile(r'sk-ant-api03-[a-zA-Z0-9_-]{95}'),
        'validation': { 'method': 'GET', 'url': 'https://api.anthropic.com/v1/ping', 'auth_type': 'header', 'header_name': 'x-api-key' },
        'entropy_threshold': 4.5
    },
    'GoogleAI': {
        'dork_components': {
            'keys': ['"AIzaSy"'],
            'vars': ['"GOOGLE_API_KEY"', '"GEMINI_API_KEY"'],
            'patterns': ['"genai.configure(api_key=\\"AIzaSy"'],
            'filenames': ['filename:.env'],
            'extensions': ['extension:py', 'extension:java', 'extension:kt']
        },
        'negative_keywords': ['placeholder', 'YOUR_GOOGLE_API_KEY'],
        'regex': re.compile(r'AIzaSy[a-zA-Z0-9_-]{33}'),
        'validation': { 'method': 'GET', 'url': 'https://generativelanguage.googleapis.com/v1beta/models', 'auth_type': 'query_param', 'param_name': 'key' },
        'entropy_threshold': 4.3
    },
    'Stripe': {
        'dork_components': {
            'keys': ['"sk_live_"', '"rk_live_"'],
            'vars': ['"STRIPE_API_KEY"', '"stripe.api_key"'],
            'filenames': ['filename:config', 'filename:.env'],
            'extensions': ['extension:php', 'extension:rb']
        },
        'negative_keywords': ['sk_test_', 'pk_live_', 'pk_test_', 'example'],
        'regex': re.compile(r'(sk|rk)_(live)_[0-9a-zA-Z]{24,99}'),
        'validation': { 'method': 'GET', 'url': 'https://api.stripe.com/v1/customers?limit=1', 'auth_type': 'bearer' },
        'entropy_threshold': 4.3
    },
}

EXCLUSIONS = " -path:*.md -path:*.txt -path:*.lock -path:*.example -path:package.json -path:yarn.lock -path:pnpm-lock.yaml"
CACHE_FILE = ".keychains_cache.json"
ISSUE_BODY_TEMPLATE = """Hey :) this issue was automated through one of my programs aka keychains because it found a hard coded api key laying around.

Here is more information:
- **File containing the key:** `{file_path}`
- **Detected at:** `{timestamp}`

This issue was created to alert you about the exposed key. For security, you should **invalidate the key immediately** and then purge it from your repository's history.

Stay safe!
"""

# --- ANSI Escape Codes for TUI ---
class Ansi:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# --- Simplified Logger / Progress Reporter ---
class Dashboard:
    def __init__(self, services: List[str]):
        self.stats = Counter()
        self.services = services
        self.lock = asyncio.Lock()

    async def log(self, message: str):
        async with self.lock:
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            print(f"{Ansi.CYAN}[{timestamp}]{Ansi.RESET} {message}")

    async def add_leak(self, leak: Dict[str, Any]):
        self.stats['confirmed_leaks'] += 1
        async with self.lock:
            val_status = leak['validation_status']
            color = Ansi.GREEN if val_status == 'Active' else Ansi.YELLOW
            print(
                f"  {Ansi.GREEN}{Ansi.BOLD}Leak Found:{Ansi.RESET} {leak['service']} key in "
                f"{Ansi.BOLD}{leak['repository']}{Ansi.RESET} "
                f"({color}{val_status}{Ansi.RESET}) -> {leak['url']}"
            )

    def update_stats(self, key: str, value: int = 1):
        self.stats[key] += value

    async def set_status(self, status: str):
        async with self.lock:
            print(f"{Ansi.YELLOW}Status:{Ansi.RESET} {status}")

    async def set_rate_limit(self, remaining: int, limit: int, reset_time: int):
        reset_delta = max(0, reset_time - time.time())
        rate_limit_info = f"{remaining}/{limit} (Resets in {int(reset_delta)}s)"
        # We don't print this on every request to avoid spam, but the info is available if needed.

# --- Core Logic Classes ---

class Scanner:
    def __init__(self, config: Dict[str, Any], session: aiohttp.ClientSession, dashboard: Dashboard):
        self.config = config
        self.session = session
        self.dashboard = dashboard
        self.cache = self._load_cache()
        self.rate_limit_remaining = 5000
        self.rate_limit_reset = time.time()
        self.headers = {
            'Authorization': f'token {config["token"]}',
            'Accept': 'application/vnd.github.v3.text-match+json'
        }

    def _load_cache(self) -> Set[str]:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                try: return set(json.load(f))
                except json.JSONDecodeError: return set()
        return set()

    def save_cache(self):
        with open(CACHE_FILE, 'w') as f:
            json.dump(list(self.cache), f)

    async def _generate_dorks(self) -> List[Tuple[str, str]]:
        dorks = []
        services_to_scan = {k: v for k, v in SERVICE_DEFINITIONS.items() if self.config['services'].lower() == 'all' or k in self.config['services'].split(',')}
        
        await self.dashboard.log(f"Generating dorks for services: {', '.join(services_to_scan.keys())}")

        for service, definition in services_to_scan.items():
            components = definition.get('dork_components', {})
            if not components:
                continue

            primary_keywords = components.get('keys', []) + components.get('vars', [])
            qualifiers = components.get('filenames', []) + components.get('extensions', [])
            patterns = components.get('patterns', [])

            # Dorks combining a primary keyword with a qualifier
            for keyword in primary_keywords:
                for qualifier in qualifiers:
                    dorks.append((service, f'{keyword} {qualifier}'))
            
            # Dorks for specific patterns
            for pattern in patterns:
                dorks.append((service, pattern))

        # Remove duplicates while preserving order
        unique_dorks = list(dict.fromkeys(dorks))
        
        await self.dashboard.log(f"Generated {len(unique_dorks)} unique, simplified search dorks.")
        return unique_dorks

    async def run_scan(self) -> List[Dict[str, Any]]:
        dorks = await self._generate_dorks()
        semaphore = asyncio.Semaphore(self.config['workers'])
        tasks = [self._run_query(service, dork, semaphore) for service, dork in dorks]
        
        all_items = []
        for future in asyncio.as_completed(tasks):
            result = await future
            if result:
                all_items.extend(result)
        
        await self.dashboard.log(f"GitHub queries complete. Found {len(all_items)} raw items.")
        return await self._process_items(all_items)

    async def _update_rate_limit(self, headers):
        self.rate_limit_remaining = int(headers.get('x-ratelimit-remaining', 0))
        self.rate_limit_reset = int(headers.get('x-ratelimit-reset', time.time()))
        limit = int(headers.get('x-ratelimit-limit', 0))
        await self.dashboard.set_rate_limit(self.rate_limit_remaining, limit, self.rate_limit_reset)

    async def _run_query(self, service: str, dork: str, semaphore: asyncio.Semaphore) -> Optional[List[Dict]]:
        negatives = ' '.join([f'NOT "{n}"' for n in SERVICE_DEFINITIONS[service].get('negative_keywords', [])])
        full_query = f'{dork} {negatives}{EXCLUSIONS}' + (' -fork:true' if self.config['no_forks'] else '')
        params = {'q': full_query, 'per_page': 100}

        async with semaphore:
            if self.rate_limit_remaining < 5:
                wait_time = max(0, self.rate_limit_reset - time.time()) + 2
                await self.dashboard.log(f"Approaching rate limit. Pausing for {wait_time:.1f}s...")
                await asyncio.sleep(wait_time)

            try:
                async with self.session.get('https://api.github.com/search/code', headers=self.headers, params=params, timeout=30) as response:
                    self.dashboard.update_stats('queries_sent')
                    await self._update_rate_limit(response.headers)
                    if response.status == 200:
                        data = await response.json()
                        items = data.get('items', [])
                        for item in items:
                            item['found_for_service'] = service
                        return items
                    elif response.status == 422:
                        await self.dashboard.log(f"{Ansi.YELLOW}GitHub API rejected a query (422 Unprocessable). Query was likely too complex. Skipping.{Ansi.RESET}")
                    elif response.status in [403, 429]:
                        await self.dashboard.log(f"{Ansi.RED}Rate limit hit hard. Backing off...{Ansi.RESET}")
                        await asyncio.sleep(10)
                    else:
                        response.raise_for_status()
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                await self.dashboard.log(f"{Ansi.RED}Network error: {e}{Ansi.RESET}")
        return None
    
    async def _process_items(self, items: List[Dict]) -> List[Dict[str, Any]]:
        await self.dashboard.set_status("Processing and filtering results...")
        potential_leaks = []
        guardian = KeyGuardian(model_path=self.config['ml_model']) if self.config['ml_filter'] and KeyGuardian else None
        
        for item in items:
            self.dashboard.update_stats('items_processed')
            if item['html_url'] in self.cache: continue

            service = item['found_for_service']
            definition = SERVICE_DEFINITIONS[service]
            
            fragment = item['text_matches'][0]['fragment']
            match = definition['regex'].search(fragment)
            if not match: continue

            key_found = match.group(0)

            if not self._passes_heuristics(key_found, definition, item['path']):
                continue

            if guardian and guardian.session:
                confidence = guardian.predict(key_found, fragment)
                if confidence < self.config['ml_threshold']:
                    continue

            self.cache.add(item['html_url'])
            self.dashboard.update_stats('potential_leaks')
            path_confidence, conf_desc = self._get_path_confidence(item['path'])
            
            leak_details = {
                "service": service, "repository": item['repository']['full_name'], "file": item['path'],
                "url": item['html_url'], "key_snippet": key_found, "confidence": path_confidence,
                "confidence_description": conf_desc, "fragment": fragment
            }
            potential_leaks.append(leak_details)
        
        await self.dashboard.log(f"Identified {len(potential_leaks)} new, unique potential leaks.")
        return potential_leaks

    def _passes_heuristics(self, key: str, definition: Dict, path: str) -> bool:
        entropy = self._calculate_entropy(key)
        if entropy < definition.get('entropy_threshold', 3.5): return False
        
        confidence, _ = self._get_path_confidence(path)
        if confidence < 0.15: return False
        
        return True

    def _calculate_entropy(self, s: str) -> float:
        if not s: return 0.0
        p, lns = Counter(s), float(len(s))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

    def _get_path_confidence(self, path: str) -> Tuple[float, str]:
        for pattern, (score, desc) in PATH_CONFIDENCE.items():
            if pattern.search(path):
                return score, desc
        return 0.2, "Generic Code File"


class Validator:
    def __init__(self, config: Dict[str, Any], session: aiohttp.ClientSession, dashboard: Dashboard):
        self.config = config
        self.session = session
        self.dashboard = dashboard

    async def validate_all(self, leaks: List[Dict]) -> List[Dict]:
        if not self.config['validate']:
            for leak in leaks:
                leak['validation_status'] = "Not Checked"
            return leaks

        if not leaks:
            return []

        await self.dashboard.set_status(f"Validating {len(leaks)} keys...")
        semaphore = asyncio.Semaphore(self.config['workers'])
        tasks = [self._validate_key(leak, semaphore) for leak in leaks]
        validated_leaks = await asyncio.gather(*tasks)
        await self.dashboard.log(f"Validation complete.")
        return validated_leaks

    async def _validate_key(self, leak: Dict, semaphore: asyncio.Semaphore) -> Dict:
        service, key = leak['service'], leak['key_snippet']
        definition = SERVICE_DEFINITIONS[service]
        val_config = definition['validation']
        
        headers, params = {'User-Agent': 'keychains-scanner/3.0'}, {}
        if val_config['auth_type'] == 'bearer': headers['Authorization'] = f'Bearer {key}'
        elif val_config['auth_type'] == 'header': headers[val_config['header_name']] = key
        elif val_config['auth_type'] == 'query_param': params[val_config['param_name']] = key

        is_valid, reason = False, "Request Failed"
        async with semaphore:
            try:
                proxy = self.config.get('proxy')
                async with self.session.request(val_config['method'], val_config['url'], headers=headers, params=params, timeout=10, proxy=proxy) as response:
                    if response.status == 200: is_valid, reason = True, "Active"
                    elif response.status in [401, 403]: is_valid, reason = False, "Invalid/Forbidden"
                    elif response.status == 429: is_valid, reason = False, "Rate-Limited"
                    else: is_valid, reason = False, f"HTTP {response.status}"
            except (aiohttp.ClientError, asyncio.TimeoutError):
                is_valid, reason = False, "Request Failed"
        
        leak['validation_status'] = reason
        if is_valid: self.dashboard.update_stats('valid_keys')
        else: self.dashboard.update_stats('invalid_keys')

        if self.config['collect_data'] and collect_training_data:
            label = 1 if is_valid else (0 if reason == "Invalid/Forbidden" else None)
            if label is not None:
                collect_training_data(self.config['collect_data'], leak['key_snippet'], leak['fragment'], label)

        return leak

class Reporter:
    def __init__(self, config: Dict[str, Any], session: aiohttp.ClientSession, dashboard: Dashboard):
        self.config = config
        self.session = session
        self.dashboard = dashboard

    async def report_all(self, leaks: List[Dict]):
        valid_leaks = [leak for leak in leaks if leak.get('validation_status') == 'Active']
        if not valid_leaks:
            return

        await self.dashboard.set_status(f"Reporting {len(valid_leaks)} valid leaks...")
        
        tasks = []
        if self.config['report']:
            semaphore = asyncio.Semaphore(5) # Lower semaphore for issue creation
            tasks.extend([self._create_github_issue(leak, semaphore) for leak in valid_leaks])
        
        if self.config['webhook_url']:
            tasks.extend([self._send_webhook(leak) for leak in valid_leaks])

        if tasks:
            await asyncio.gather(*tasks)

        for leak in valid_leaks:
            await self.dashboard.add_leak(leak)
        
        await self.dashboard.log(f"Reporting complete.")


    async def _create_github_issue(self, leak: Dict, semaphore: asyncio.Semaphore):
        repo = leak['repository']
        headers = {'Authorization': f'token {self.config["token"]}', 'Accept': 'application/vnd.github.v3+json'}
        issue_body = ISSUE_BODY_TEMPLATE.format(
            file_path=leak['url'],
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        payload = {"title": f"Security Alert: Hardcoded API Key in {leak['file']}", "body": issue_body}
        url = f"https://api.github.com/repos/{repo}/issues"

        async with semaphore:
            try:
                async with self.session.post(url, headers=headers, json=payload, timeout=15) as response:
                    if response.status == 201: leak['issue_status'] = "Created"
                    else: leak['issue_status'] = f"Failed (HTTP {response.status})"
            except (aiohttp.ClientError, asyncio.TimeoutError):
                leak['issue_status'] = "Failed (Network)"


    async def _send_webhook(self, leak: Dict):
        payload = {
            "embeds": [{
                "title": "🚨 New API Key Leak Detected! 🚨",
                "color": 15158332, # Red
                "fields": [
                    {"name": "Service", "value": leak['service'], "inline": True},
                    {"name": "Repository", "value": leak['repository'], "inline": True},
                    {"name": "Confidence", "value": f"{int(leak['confidence']*100)}% ({leak['confidence_description']})", "inline": True},
                    {"name": "File", "value": f"[{leak['file']}]({leak['url']})"},
                    {"name": "Key Snippet", "value": f"`{leak['key_snippet']}`"}
                ],
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }]
        }
        try:
            async with self.session.post(self.config['webhook_url'], json=payload, timeout=10) as response:
                 leak['webhook_status'] = "Sent" if response.status in [200, 204] else f"Failed (HTTP {response.status})"
        except (aiohttp.ClientError, asyncio.TimeoutError):
            leak['webhook_status'] = "Failed (Network)"

# --- Orchestrator ---

async def run_scan_orchestrator(args):
    config = vars(args)
    if not config['token']: config['token'] = os.getenv('GITHUB_TOKEN')
    if not config['token']:
        print(f"{Ansi.RED}Error: GitHub token not found. Set GITHUB_TOKEN or use --token.{Ansi.RESET}", file=sys.stderr)
        return

    if config['config_file'] and os.path.exists(config['config_file']):
        if not yaml:
            print(f"{Ansi.RED}Error: --config-file requires PyYAML. Please run: pip install pyyaml{Ansi.RESET}", file=sys.stderr)
            return
        with open(config['config_file'], 'r') as f:
            file_config = yaml.safe_load(f)
        config = {**file_config, **{k: v for k, v in config.items() if v is not None}}
    
    output_filename = config.get('output', "findings.json")

    print(f"{Ansi.BOLD}🔑 keychains v3.0.0 - The Monster Update{Ansi.RESET}")
    print("─" * 40)
    dashboard = Dashboard(services=config['services'].split(','))
    
    total_found_leaks = []

    async with aiohttp.ClientSession() as session:
        scanner = Scanner(config, session, dashboard)
        validator = Validator(config, session, dashboard)
        reporter = Reporter(config, session, dashboard)

        start_time = time.time()
        end_time = start_time + config['duration'] * 60 if config['duration'] > 0 else float('inf')
        
        cycle = 0
        while time.time() < end_time:
            cycle += 1
            await dashboard.set_status(f"Starting scan cycle {cycle}...")
            
            potential_leaks = await scanner.run_scan()
            validated_leaks = await validator.validate_all(potential_leaks)
            await reporter.report_all(validated_leaks)
            
            total_found_leaks.extend([l for l in validated_leaks if l.get('validation_status') == 'Active'])
            
            if config['duration'] == 0: break
            
            await dashboard.set_status(f"Cycle {cycle} complete. Waiting 60s...")
            await asyncio.sleep(60)

    print("\n" + "─" * 40)
    print(f"{Ansi.BOLD}🔑 keychains v3.0.0 - Scan Complete{Ansi.RESET}")
    print("─" * 40)
    print(f"  Total Confirmed Leaks Found: {len(total_found_leaks)}")
    print(f"  Total GitHub Queries Made:   {dashboard.stats['queries_sent']}")
    print(f"  Total Items Processed:       {dashboard.stats['items_processed']}")
    print("─" * 40)

    if total_found_leaks:
        if output_filename:
            try:
                with open(output_filename, 'w') as f:
                    json.dump(total_found_leaks, f, indent=2)
                print(f"✅ Results saved to {output_filename}")
            except IOError as e:
                print(f"❌ Could not write to output file: {e}")

    scanner.save_cache()
    print("✅ Cache updated.")


# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="keychains v3.0.0: The Monster Update. A high-performance, interactive scanner for finding and managing exposed API keys on GitHub.", formatter_class=argparse.RawTextHelpFormatter)
    
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    scan_parser = subparsers.add_parser('scan', help='Scan GitHub for exposed API keys with an interactive dashboard.')
    scan_parser.add_argument('--token', type=str, help='GitHub Personal Access Token. Overrides GITHUB_TOKEN env var.')
    scan_parser.add_argument('--config-file', type=str, default='keychains_config.yml', help='Path to a YAML config file.')
    scan_parser.add_argument('--output', '-o', type=str, default='findings.json', help='File to save JSON results to.')
    scan_parser.add_argument('--services', '-s', type=str, default='all', help='Comma-separated services to scan for (e.g., OpenAI,GoogleAI).')
    scan_parser.add_argument('--workers', '-w', type=int, default=15, help='Max concurrent async workers.')
    scan_parser.add_argument('--no-forks', action='store_true', help='Exclude forked repositories.')
    scan_parser.add_argument('--duration', '-d', type=int, default=0, help='Continuous scan duration in minutes (0 for a single run).')
    scan_parser.add_argument('--validate', action='store_true', help='Validate found keys against service APIs.')
    scan_parser.add_argument('--report', action='store_true', help='Create a GitHub issue in the repository for valid leaks.')
    scan_parser.add_argument('--webhook-url', type=str, help='Send valid leak notifications to this Slack/Discord webhook URL.')
    scan_parser.add_argument('--proxy', type=str, help='HTTP/S proxy for validation requests (e.g., http://user:pass@127.0.0.1:8080).')
    scan_parser.add_argument('--ml-filter', action='store_true', help='Use a KeyGuardian ML model to filter false positives.')
    scan_parser.add_argument('--ml-model', type=str, default='keyguardian.onnx', help='Path to the ONNX model file.')
    scan_parser.add_argument('--ml-threshold', type=float, default=0.8, help='Confidence threshold (0.0-1.0) for the ML filter.')
    scan_parser.add_argument('--collect-data', type=str, help='File path to save key candidates for ML training (JSONL format). Requires --validate.')
    scan_parser.set_defaults(func=run_scan_orchestrator)
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        try:
            if asyncio.iscoroutinefunction(args.func):
                asyncio.run(args.func(args))
            else:
                args.func(args)
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            print(f"{Ansi.RED}An unexpected error occurred: {e}{Ansi.RESET}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    main()
