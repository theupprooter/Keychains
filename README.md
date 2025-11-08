# Keychains: API Key Scanner & Rotator

A **command-line tool** for discovering and managing AI API keys in public GitHub repositories.

---

## Table of Contents

1. [Modes](#modes)  
   - [Scan Mode](#1-scan-mode-scan)  
   - [Rotate Mode](#2-rotate-mode-rotate)  
2. [Prerequisites](#prerequisites)  
3. [Setup](#setup)  
4. [Usage](#usage)  
5. [Legal & Ethical](#legal--ethical)  

---

## Modes

### 1. Scan Mode (`scan`)

Scan public GitHub repositories for exposed API keys **concurrently**.

**Note:**  
A basic scan will **not save** found API keys. Specify a save filename before scanning.  
For more details, refer to [Populate Key Pool](https://github.com/theupprooter/Keychains/blob/main/README.md#populate-key-pool).

#### Features

| Feature | Description |
|---------|-------------|
| Real-time dashboard | Visual progress and statistics in terminal |
| Multi-threaded scanning | Faster concurrent repository scanning |
| Automated issue creation | Optional GitHub issue creation to notify repo owners |
| State management | Avoid duplicate key detections |
| Continuous monitoring | Listen for new leaks over a specified duration |
| Export data | Save results to JSON for further processing |
| Advanced scanning | Filtered/targeted scans with validation and rotation |

---

### 2. Rotate Mode (`rotate`)

Fetch a validated API key from a JSON pool (e.g., `findings.json`) for authorized applications.

#### Workflow

1. **Populate key pool**
```bash
python keychains-public.py scan --output findings.json
```
2. Rotate key for a service

```bash

export OPENAI_API_KEY=$(python keychains-public.py rotate --service OpenAI --key-file findings.json)
```
Arguments

Argument	Alias	Description
```bash
--service <SERVICE>	-s <SERVICE>	Required. Target service name
--key-file <FILENAME>	-k <FILENAME>	Optional. JSON key file (default: findings.json)
```


---

Prerequisites

Python 3.7+

GitHub account with public_repo PAT



---

Setup

1. [Generate a GitHub token here.](https://github.com/settings/tokens)


2. Configure environment variable:



macOS/Linux
```bash
export GITHUB_TOKEN="your_token_here"
```
Windows (CMD)
```bash
set GITHUB_TOKEN="your_token_here"
```
3. Install dependencies:


```bash
pip install requests rich
```

---

Usage

Help
```bash
python keychains-public.py --help
```
Scan all services
```bash
python keychains-public.py scan
```
Scan and create report
```bash
python keychains-public.py scan --report --output findings.json
```
Scan specific services
```bash
python keychains-public.py scan --services OpenAI,Cohere
```
Run scan for specific duration (minutes)
```bash
python keychains-public.py scan -d 30 --output findings.json
```

---

Legal & Ethical

Authorized use only.

Do not use discovered keys for unauthorized access.

The author assumes no liability for misuse.
