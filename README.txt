================================================================================
  Checkmarx One CI/CD Pipeline Script
  Professional Services Engineer — Technical Assignment (Exercise 1)
  Author: Nilkamal
================================================================================

OVERVIEW
--------
This script automates the following CI/CD workflow:
  1. Pull source code from a Git repository
  2. Initiate a Checkmarx One SAST scan using the cx CLI
  3. Wait for scan completion and retrieve the JSON report
  4. Parse the report to produce a summary (by severity + by vulnerability)
  5. Send an HTML-formatted summary email to a configurable recipients list

PLATFORM SUPPORT
----------------
  - macOS (tested on macOS 13+)
  - Windows 10/11
  - Linux (Ubuntu 20.04+)
  Cross-platform by design: no OS-specific libraries used.

FILES
-----
  cx_scan_pipeline.py           Main pipeline script
  config.yaml                   Configuration file (edit before running)
  requirements.txt              Python dependencies
  sample_vulnerable_code/       Sample vulnerable app for demo scanning
  README.txt                    This file

PREREQUISITES
-------------
  1. Python 3.8 or higher
       macOS/Linux : python3 --version
       Windows     : python --version

  2. Git (must be in PATH)
       https://git-scm.com/downloads

  3. Checkmarx cx CLI
       Download from:
       https://docs.checkmarx.com/en/34965-68620-checkmarx-one-cli-tool.html

       macOS (Homebrew):
         brew install checkmarx/tap/cx

       Linux:
         curl -L https://github.com/Checkmarx/ast-cli/releases/latest/download/cx_linux_amd64.tar.gz | tar xz
         sudo mv cx /usr/local/bin/

       Windows:
         Download cx.exe from the releases page and add to PATH.

       Verify: cx version

INSTALLATION
------------
  1. Install Python dependencies:
       pip install -r requirements.txt
       (or: pip3 install -r requirements.txt on macOS/Linux)

  2. Edit config.yaml with your values:
       - repository.url        → your GitHub repo URL
       - checkmarx.api_key     → your CxOne API key
       - checkmarx.group       → your assigned group in CxOne
       - email.recipients      → list of email addresses to notify
       - email.smtp_*          → your SMTP server details

HOW TO GENERATE A CxOne API KEY
--------------------------------
  1. Log in to https://eu.ast.checkmarx.net
  2. Navigate to: Access Management → API Keys
  3. Click "Generate API Key"
  4. Copy the key into config.yaml under checkmarx.api_key

EMAIL CONFIGURATION (Gmail Example)
-------------------------------------
  For Gmail, use an App Password (not your account password):
  1. Enable 2-Factor Authentication on your Google account
  2. Go to: https://myaccount.google.com/apppasswords
  3. Generate an App Password for "Mail"
  4. Paste it into config.yaml under email.password

  smtp_host: smtp.gmail.com
  smtp_port: 587

  Other providers:
    Outlook/Office365 : smtp.office365.com, port 587
    SendGrid          : smtp.sendgrid.net, port 587
    Amazon SES        : email-smtp.<region>.amazonaws.com, port 587

USAGE
-----
  Basic (uses config.yaml in current directory):
    python cx_scan_pipeline.py

  With a custom config file:
    python cx_scan_pipeline.py --config /path/to/my_config.yaml

  Help:
    python cx_scan_pipeline.py --help

OUTPUT
------
  - Reports are saved as JSON files in the configured report_dir (default: ./reports/)
    Named: cx_results_YYYYMMDD_HHMMSS.json

  - An HTML email is sent to all configured recipients with:
    • Total finding count
    • Findings grouped by severity (Critical / High / Medium / Low / Info)
    • Top 10 vulnerabilities by occurrence count
    • A link to view full results in Checkmarx One

TROUBLESHOOTING
---------------
  "cx CLI not found"
    → Ensure cx is installed and in your PATH. Run: which cx (Mac/Linux)
    → Or set the full path in config.yaml under checkmarx.cx_cli_path

  "Git operation failed"
    → Ensure git is installed and the repository URL is accessible

  "Failed to send email"
    → Verify SMTP credentials and that your mail server allows SMTP relay
    → For Gmail, ensure you are using an App Password, not your login password

  "No JSON report found after scan"
    → Check that the cx CLI version supports --report-format json
    → Try running the cx scan command manually to verify credentials and group name

================================================================================
