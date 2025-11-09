# `keychains`: High-Performance AI Key Scanner

A professional, asynchronous command-line tool for discovering, validating, and reporting exposed API keys in public GitHub repositories. Version 3.0 introduces a powerful scanning engine and advanced filtering capabilities.

> **Disclaimer:** This tool is for educational and security research purposes only. Use it ethically and responsibly to help remediate exposed credentials. The author is not responsible for your actions.

---

## Key Features

*   **Dynamic Search Engine:** Generates thousands of unique search queries ("dorks") to maximize discovery.
*   **Asynchronous Core:** Utilizes `asyncio` and `aiohttp` for high-speed, concurrent scanning.
*   **Multi-Layered Filtering:** Combines heuristics, entropy analysis, and a state-of-the-art ML model to drastically reduce false positives.
*   **Key Validation & Reporting:** Verifies keys against service APIs and can automatically create GitHub issues or send webhook notifications.
*   **Configuration Flexibility:** Manage all settings via command-line arguments or a central `keychains_config.yml` file.
*   **Proxy Support:** Route validation traffic through an HTTP/S proxy to avoid rate-limiting.

---

## Installation

1.  **Prerequisites:**
    *   Python 3.7+
    *   A [GitHub Personal Access Token](https://github.com/settings/tokens) (classic) with `public_repo` scope is required for creating issues.

2.  **Set Environment Variable:**
    ```bash
    # macOS / Linux
    export GITHUB_TOKEN="your_github_pat_here"

    # Windows (Command Prompt)
    set GITHUB_TOKEN="your_github_pat_here"
    ```

3.  **Install Dependencies:**
    ```bash
    pip install aiohttp pyyaml
    ```

---

## Usage

The primary command is `scan`. All operations are managed through its flags.

**Common Examples:**

*   **Run a basic scan and save results:**
    ```bash
    python keychains-public-v2x.py scan -o findings.json
    ```

*   **Scan, validate keys, and report valid leaks via GitHub issues:**
    ```bash
    python keychains-public-v2x.py scan --validate --report -o findings.json
    ```

*   **Run a continuous 30-minute scan with webhook reporting:**
    ```bash
    python keychains-public-v2x.py scan -d 30 --validate --webhook-url "https://your.webhook/url"
    ```

*   **Use a configuration file for all settings:**
    ```bash
    python keychains-public-v2x.py scan --config-file keychains_config.yml
    ```

### Example `keychains_config.yml`
```yaml
# keychains_config.yml
token: "ghp_..." # Can be set here instead of env var
services: "OpenAI,GoogleAI"
workers: 20
no_forks: true
validate: true
report: true
webhook_url: "https://your.discord.webhook/..."
proxy: "http://user:pass@127.0.0.1:8080"
ml_filter: true
ml_threshold: 0.9
```

---

## Advanced: The `KeyGuardian` ML Filter

For maximum accuracy, `keychains` integrates `KeyGuardian`, a sophisticated machine learning pipeline built on a DeBERTa model.

**1. Install ML Dependencies:**
```bash
pip install onnxruntime numpy tokenizers transformers torch scikit-learn pandas optuna
```

**2. The Self-Learning Workflow:**

*   **Collect Data:** Run a scan with validation enabled to create a labeled dataset.
    ```bash
    # Scan for 2 hours, validating keys and saving training examples
    python keychains-public-v2x.py scan -d 120 --validate --collect-data training_data.jsonl
    ```
*   **Train Model:** Use the collected data to train a highly accurate `keyguardian.onnx` model.
    ```bash
    # Run hyperparameter search for the best results, then train
    python keyguardian.py --train --data-file training_data.jsonl --hyperparameter-search
    ```
*   **Scan with Your Custom Filter:** Use your trained model for superior accuracy.
    ```bash
    python keychains-public-v2x.py scan --validate --ml-filter --ml-threshold 0.9
    ```
