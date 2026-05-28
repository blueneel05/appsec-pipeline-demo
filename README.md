# 🛡️ AppSec Pipeline Demo

> Automated CI/CD security pipeline integrating **Checkmarx One SAST** — scan, report, and notify on every build.

---

## Overview

This project demonstrates a fully automated application security pipeline built around **Checkmarx One**. On every build, the pipeline:

1. Pulls the latest source code from a Git repository
2. Triggers a **SAST scan** via the Checkmarx One CLI
3. Waits for scan completion and retrieves the structured JSON report
4. Parses results and summarizes findings by **severity** and **vulnerability type**
5. Sends a formatted **HTML email report** to a configurable recipients list

---

## Pipeline Flow

```
┌─────────────┐    ┌──────────────┐    ┌──────────────────┐    ┌─────────────────┐    ┌──────────────┐
│  Git Clone  │───▶│  cx CLI Scan │───▶│  JSON Report     │───▶│  Parse Summary  │───▶│  Email Alert │
│  (source)   │    │  (CxOne API) │    │  (auto-generated)│    │  Sev + Vuln     │    │  (HTML)      │
└─────────────┘    └──────────────┘    └──────────────────┘    └─────────────────┘    └──────────────┘
```

---

## Features

- ✅ **Cross-platform** — works on macOS, Windows, and Linux
- ✅ **Zero hardcoded secrets** — all config via `config.yaml`
- ✅ **HTML email reports** with severity breakdown and top vulnerability table
- ✅ **Plain-text fallback** for email clients that don't render HTML
- ✅ **YAML-based config** — easy to adapt to any environment or project
- ✅ **Smart CLI detection** — auto-resolves `cx` binary from PATH or config

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.8+ | `python3 --version` |
| Git | Any | Must be in PATH |
| Checkmarx cx CLI | Latest | [Download here](https://docs.checkmarx.com/en/34965-68620-checkmarx-one-cli-tool.html) |
| Checkmarx One account | — | API Key required |

---

## Quick Start

```bash
# 1. Clone this repo
git clone https://github.com/<your-username>/appsec-pipeline-demo.git
cd appsec-pipeline-demo

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy and fill in config
cp config.example.yaml config.yaml
# Edit config.yaml with your CxOne API key, repo URL, and email settings

# 4. Run the pipeline
python cx_scan_pipeline.py
```

---

## Configuration

Copy `config.example.yaml` to `config.yaml` and fill in your values:

```yaml
repository:
  url: "https://github.com/your-org/your-repo.git"

checkmarx:
  server_url: "https://eu.ast.checkmarx.net"
  api_key:    "YOUR_API_KEY"
  project_name: "my-project"
  group:      "your-group"

email:
  sender:     "scanner@yourdomain.com"
  recipients:
    - "security@yourdomain.com"
  smtp_host:  "smtp.gmail.com"
  smtp_port:  587
  username:   "you@gmail.com"
  password:   "your-app-password"
```

> ⚠️ **Never commit `config.yaml`** — it is listed in `.gitignore`.

---

## Project Structure

```
appsec-pipeline-demo/
├── cx_scan_pipeline.py         # Main pipeline script
├── config.example.yaml         # Config template (safe to commit)
├── config.yaml                 # Your local config (gitignored)
├── requirements.txt            # Python dependencies
├── sample_vulnerable_code/
│   └── vulnerable_app.py       # Demo target for scanning
├── reports/                    # Scan JSON output (gitignored)
└── README.md
```

---

## Email Report Preview

The pipeline generates and sends a structured HTML email containing:

- **Total findings count**
- **Results by severity** — Critical / High / Medium / Low / Info with visual bar chart
- **Top 10 vulnerabilities** by occurrence count
- **Direct link** to full results in Checkmarx One

---

## Sample Vulnerable Code

The `sample_vulnerable_code/vulnerable_app.py` file contains intentional vulnerabilities for demonstration scanning, including:

| Vulnerability | CWE |
|---|---|
| SQL Injection | CWE-89 |
| Command Injection | CWE-78 |
| Path Traversal | CWE-22 |
| Hardcoded Credentials | CWE-798 |
| Insecure Deserialization | CWE-502 |
| Cross-Site Scripting (XSS) | CWE-79 |

> This file is for **testing and demonstration purposes only**.

---

## License

MIT
