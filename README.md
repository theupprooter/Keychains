# Keychains: API Key Scanner & Rotator

Command-line tool for discovering and managing AI API keys in public GitHub repositories.

## Modes

### 1. Scan Mode (`scan`)

## Concurrent scanning of public repos for exposed API keys.

**Features**
- Real-time terminal dashboard
- Multi-threaded scanning
- Optional automated GitHub issue creation
- State management to avoid duplicates
- Continously listen for specified duration for new leaks
- Export collected data
- Advanced Scanning
- Filtered / Targeted scanning
- Validation and rotation
- what else do you need tf??


**Prerequisites**
- Python 3.7+
- GitHub account with `public_repo` PAT

**Setup**
GENERATE A GITHUB TOKEN BEFORE THIS AT: https://github.com/settings/personal-access-tokens/new
```bash
# macOS/Linux
export GITHUB_TOKEN="your_token_here"

# Windows (CMD)
set GITHUB_TOKEN="your_token_here"

pip install requests rich
```
Usage

# Scan all services

# use --help for more

```
keychains-public.py --help
```
```
python keychains-public.py scan
```

# Scan and create issues
```
python keychains-public.py scan --report --output findings.json
```

# Scan specific services
```
python keychains-public.py scan --services OpenAI,Cohere
```

# Run for specific duration (minutes)
```
python keychains-public.py scan -d 30 --output findings.json
```


---

2. Rotate Mode (rotate)

Fetches a validated API key from a JSON pool (findings.json) for authorized applications.

Workflow

# Populate key pool
```
python keychains-public.py scan --output findings.json
```

# Rotate key for service
```
export OPENAI_API_KEY=$(python keychains-public.py rotate --service OpenAI --key-file findings.json)
```

Arguments
```

--service <SERVICE>, -s <SERVICE>: Required service

--key-file <FILENAME>, -k <FILENAME>: Optional JSON key file (default findings.json)
```


---

Legal & Ethical

Authorized use only.

Do not use discovered keys for unauthorized access.

Author assumes no liability for misuse.
