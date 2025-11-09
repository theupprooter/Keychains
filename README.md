# `keychains`: Key Scanner & Rotator

`keychains` is a professional-grade command-line tool for discovering and managing exposed AI API keys in public GitHub repositories. It features a real-time terminal dashboard, concurrent scanning, and a state-of-the-art, self-learning ML filter to maximize accuracy.

> ### **Disclaimer**
> This tool is provided for **educational and security research purposes only**. Its intended use is to help identify and remediate accidentally exposed API keys. By using this software, you agree to use it ethically and responsibly. The author is not responsible for your actions. **Do not use API keys that do not belong to you.**

---

## Quick Start

### 1. Prerequisites

-   Python 3.7+
-   A GitHub Personal Access Token (PAT) with `public_repo` scope.
    -   Generate one at [**github.com/settings/tokens**](https://github.com/settings/tokens) (classic).

### 2. Setup

**Set your GitHub Token as an environment variable:**
```bash
# macOS / Linux
export GITHUB_TOKEN="your_token_here"

# Windows (Command Prompt)
set GITHUB_TOKEN="your_token_here"
```

**Install core dependencies:**
```bash
pip install requests rich
```

### 3. Run a Scan
```bash
python keychains-public-v2x.py scan
```

---

## Core Features

### `scan` Command: Find Leaked Keys

The `scan` command is the core discovery engine. It searches GitHub for keys, presenting findings in a live dashboard.

#### **Common Usage**

-   **Basic Scan (all services):**
    ```bash
    python keychains-public-v2x.py scan
    ```

-   **Scan, Validate, and Report Leaks:**
    This command validates found keys, creates GitHub issues to alert owners, and saves results.
    ```bash
    python keychains-public-v2x.py scan --validate --report --output findings.json
    ```

-   **Scan for Specific Services:**
    ```bash
    python keychains-public-v2x.py scan --services OpenAI,Cohere
    ```

-   **Continuous Scanning:**
    Run the scanner continuously for a set duration (e.g., 30 minutes).
    ```bash
    python keychains-public-v2x.py scan -d 30
    ```

### `rotate` Command: Fetch a Working Key

The `rotate` command provides a single, validated API key from a pool of previously found keys. This is useful for rotating keys in other applications.

> **Warning:** This feature is for authorized use only. Using keys that are not yours violates provider terms of service and may be illegal.

#### **Usage Example**

Inject a validated key into your application's environment:

```bash
# 1. Populate your key file
python keychains-public-v2x.py scan --services OpenAI --output findings.json

# 2. Fetch a working key and export it
export OPENAI_API_KEY=$(python keychains-public-v2x.py rotate --service OpenAI --key-file findings.json)

# 3. Run your app
if [ -n "$OPENAI_API_KEY" ]; then
    echo "Key fetched. Starting app..."
    python my_app.py
else
    echo "Failed to fetch a working key."
fi
```

---

## Advanced: Self-Learning ML Filter

To minimize false positives, `keychains` includes a sophisticated, self-improving machine learning pipeline that fine-tunes a DeBERTa model on your collected data.

### 1. Install ML Dependencies
```bash
pip install onnxruntime numpy tokenizers transformers torch scikit-learn pandas optuna
```

### 2. The Self-Learning Workflow

**Step 1: Collect High-Quality Data**
Run a scan with validation and data collection enabled. This automatically creates a labeled dataset from live results.
```bash
# Run for an extended period (e.g., 2 hours) to build a rich dataset
python keychains-public-v2x.py scan -d 120 --validate --collect-data training_data.jsonl
```

**Step 2: Train a State-of-the-Art Model**
This script runs a full MLOps pipeline, using automated hyperparameter tuning (Optuna) and cross-validation to build the most accurate model from your data.
```bash
# First time: run a hyperparameter search to find the best settings
python keyguardian.py --train --data-file training_data.jsonl --hyperparameter-search

# Subsequent runs on new data can use the optimized parameters
python keyguardian.py --train --data-file training_data.jsonl
```
This generates a highly optimized `keyguardian.onnx` model file.

**Step 3: Scan with Your Custom-Trained Filter**
Enable the ML filter to leverage your custom model for superior accuracy.
```bash
python keychains-public-v2x.py scan --validate --ml-filter --ml-threshold 0.9
```
You can repeat this cycle to continuously improve your model's performance.

---
