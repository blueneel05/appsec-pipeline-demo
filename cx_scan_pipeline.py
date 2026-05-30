#!/usr/bin/env python3
"""
Checkmarx One CI/CD Pipeline Script
=====================================
Author  : Nilkamal
Purpose : Pull source code → Run CxOne SAST scan → Parse JSON report → Send HTML email summary
Platform: Cross-platform (macOS / Windows / Linux)

Usage:
    python cx_scan_pipeline.py [--config config.yaml]

Requirements:
    pip install requests pyyaml
    cx CLI must be installed and accessible (see README.txt)
"""

import argparse
import json
import os
import platform
import shutil
import smtplib
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import yaml


# ─────────────────────────────────────────────
# 1.  CONFIG LOADER
# ─────────────────────────────────────────────

def load_config(config_path: str) -> dict:
    """Load YAML configuration file."""
    config_file = Path(config_path)
    if not config_file.exists():
        print(f"[ERROR] Config file not found: {config_path}")
        sys.exit(1)
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
    print(f"[INFO]  Config loaded from: {config_path}")
    return config


# ─────────────────────────────────────────────
# 2.  SOURCE CODE PULL
# ─────────────────────────────────────────────

def pull_source_code(repo_url: str, target_dir: str) -> str:
    """Clone or update the target repository."""
    target = Path(target_dir)

    if target.exists():
        print(f"[INFO]  Repo already exists at {target_dir}. Pulling latest changes...")
        result = subprocess.run(
            ["git", "-C", str(target), "pull"],
            capture_output=True, text=True
        )
    else:
        print(f"[INFO]  Cloning repository: {repo_url}")
        result = subprocess.run(
            ["git", "clone", repo_url, str(target)],
            capture_output=True, text=True
        )

    if result.returncode != 0:
        print(f"[ERROR] Git operation failed:\n{result.stderr}")
        sys.exit(1)

    print(f"[OK]    Source code ready at: {target_dir}")
    return str(target)


# ─────────────────────────────────────────────
# 3.  DETECT CX CLI PATH (CROSS-PLATFORM)
# ─────────────────────────────────────────────

def resolve_cx_cli(cx_cli_path: str) -> str:
    """
    Resolve the cx CLI binary path.
    Falls back to PATH lookup if the configured path is not found.
    Handles .exe suffix automatically on Windows.
    """
    system = platform.system()
    binary_name = "cx.exe" if system == "Windows" else "cx"

    # If a specific path is given, use it
    if cx_cli_path and cx_cli_path != "auto":
        cli = Path(cx_cli_path)
        if cli.exists():
            return str(cli)
        print(f"[WARN]  cx CLI not found at {cx_cli_path}. Trying PATH...")

    # Fallback: search PATH
    found = shutil.which(binary_name) or shutil.which("cx")
    if found:
        print(f"[INFO]  cx CLI found at: {found}")
        return found

    print("[ERROR] cx CLI not found. Please install it and add to PATH.")
    print("        Download: https://docs.checkmarx.com/en/34965-68620-checkmarx-one-cli-tool.html")
    sys.exit(1)


# ─────────────────────────────────────────────
# 4.  RUN CHECKMARX SCAN
# ─────────────────────────────────────────────

def run_cx_scan(cx_cli: str, config: dict, source_dir: str, report_dir: str) -> str:
    """
    Trigger a Checkmarx One SAST scan via CLI and wait for completion.
    Returns the path to the generated JSON report.
    """
    cx_cfg   = config["checkmarx"]
    report_path = Path(report_dir)
    report_path.mkdir(parents=True, exist_ok=True)

    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = str(report_path / f"cx_results_{timestamp}.json")

    cmd = [
        cx_cli, "scan", "create",
        "--project-name",  cx_cfg["project_name"],
        "--branch",        cx_cfg.get("branch", "main"),
        #"--group",         cx_cfg["group"], -- group name was not available in the dashboard, so removed it from the scan command. It can be set in the CxOne UI when creating the project.
        "-s",              source_dir,
        "--scan-types",    "sast",
        "--report-format", "json",
        "--output-path",   str(report_path),
        "--output-name",   f"cx_results_{timestamp}",
        "--async",         "false",          # wait until scan completes
        "--base-uri",      cx_cfg["server_url"],
        "--apikey",        cx_cfg["api_key"],
    ]

    print(f"\n[INFO]  Initiating Checkmarx One scan...")
    print(f"        Project : {cx_cfg['project_name']}")
    # print(f"        Group   : {cx_cfg['group']}")
    print(f"        Branch  : {cx_cfg.get('branch', 'main')}")
    print(f"        Server  : {cx_cfg['server_url']}\n")

    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)

    elapsed = round(time.time() - start_time, 1)
    print(f"[INFO]  Scan completed in {elapsed}s (exit code: {result.returncode})")

    if result.returncode != 0:
        print(f"[ERROR] Scan failed:\n{result.stderr}")
        sys.exit(1)

    # cx CLI writes <name>.json into output-path
    expected = report_path / f"cx_results_{timestamp}.json"
    if not expected.exists():
        # Search for any json report produced
        candidates = list(report_path.glob("*.json"))
        if not candidates:
            print("[ERROR] No JSON report found after scan.")
            sys.exit(1)
        expected = max(candidates, key=lambda p: p.stat().st_mtime)

    print(f"[OK]    Report saved to: {expected}")
    return str(expected)


# ─────────────────────────────────────────────
# 5.  PARSE JSON REPORT
# ─────────────────────────────────────────────

def parse_report(report_path: str) -> dict:
    """
    Parse the Checkmarx JSON report and extract:
      - results_by_severity  : { Critical/High/Medium/Low/Info : count }
      - results_by_vuln      : { VulnerabilityName : count }
      - total                : int
      - scan_id              : str
      - scan_date            : str
    """
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results_by_severity: dict = defaultdict(int)
    results_by_vuln: dict     = defaultdict(int)

    # CxOne JSON report structure: data["results"] is a list of finding objects
    results = data.get("results", [])

    for finding in results:
        severity = finding.get("severity", "Unknown").capitalize()
        vuln_name = finding.get("queryName") or finding.get("type") or finding.get("vulnerabilityDetails", {}).get("cveName", "Unknown")
        results_by_severity[severity] += 1
        results_by_vuln[vuln_name]    += 1

    # Sort severity in standard order
    severity_order = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
    sorted_severity = {
        s: results_by_severity[s]
        for s in severity_order
        if s in results_by_severity
    }

    # Sort vulns by count descending
    sorted_vulns = dict(
        sorted(results_by_vuln.items(), key=lambda x: x[1], reverse=True)
    )

    summary = {
        "results_by_severity": sorted_severity,
        "results_by_vuln":     sorted_vulns,
        "total":               len(results),
        "scan_id":             data.get("scanId", "N/A"),
        "scan_date":           data.get("scanDate") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "project_name":        data.get("projectName", "N/A"),
    }

    print(f"\n[INFO]  Scan Summary:")
    print(f"        Total Findings : {summary['total']}")
    for sev, cnt in sorted_severity.items():
        print(f"        {sev:<12}: {cnt}")

    return summary


# ─────────────────────────────────────────────
# 6.  BUILD HTML EMAIL
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    "Critical": "#7B2FBE",
    "High":     "#D93025",
    "Medium":   "#F4A118",
    "Low":      "#2196F3",
    "Info":     "#4CAF50",
    "Unknown":  "#9E9E9E",
}

def build_html_email(summary: dict, config: dict) -> str:
    """Render a professional HTML email from the scan summary."""

    project   = summary["project_name"]
    scan_id   = summary["scan_id"]
    scan_date = summary["scan_date"]
    total     = summary["total"]
    server    = config["checkmarx"]["server_url"]

    # ── Severity badges
    severity_rows = ""
    for sev, cnt in summary["results_by_severity"].items():
        color = SEVERITY_COLORS.get(sev, "#9E9E9E")
        bar_width = min(int((cnt / max(total, 1)) * 240), 240)
        severity_rows += f"""
        <tr>
          <td style="padding:8px 12px; font-weight:600; color:{color}; width:90px;">{sev}</td>
          <td style="padding:8px 12px;">
            <div style="background:#f0f0f0; border-radius:4px; height:18px; width:260px;">
              <div style="background:{color}; width:{bar_width}px; height:18px; border-radius:4px;"></div>
            </div>
          </td>
          <td style="padding:8px 12px; font-weight:700; color:{color};">{cnt}</td>
        </tr>"""

    # ── Top 10 vulnerabilities table
    vuln_rows = ""
    for i, (vuln, cnt) in enumerate(list(summary["results_by_vuln"].items())[:10], 1):
        bg = "#fafafa" if i % 2 == 0 else "#ffffff"
        vuln_rows += f"""
        <tr style="background:{bg};">
          <td style="padding:8px 14px; color:#555;">{i}</td>
          <td style="padding:8px 14px; font-family:monospace; color:#333;">{vuln}</td>
          <td style="padding:8px 14px; font-weight:600; color:#333; text-align:center;">{cnt}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Checkmarx Scan Report</title></head>
<body style="margin:0; padding:0; background:#f4f6f9; font-family: 'Segoe UI', Arial, sans-serif;">

<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9; padding:30px 0;">
<tr><td align="center">
<table width="680" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:10px;
       box-shadow:0 2px 12px rgba(0,0,0,0.10); overflow:hidden;">

  <!-- HEADER -->
  <tr>
    <td style="background:linear-gradient(135deg,#003F5C 0%,#005F8E 100%);
               padding:30px 36px; text-align:left;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td>
            <div style="font-size:22px; font-weight:800; color:#ffffff; letter-spacing:0.5px;">
              &#x1F6E1; Checkmarx One
            </div>
            <div style="font-size:13px; color:#a8d4f0; margin-top:4px;">
              SAST Scan Report — Automated Pipeline
            </div>
          </td>
          <td align="right">
            <div style="background:rgba(255,255,255,0.15); border-radius:6px;
                        padding:8px 16px; display:inline-block;">
              <div style="font-size:11px; color:#c8e6f7;">TOTAL FINDINGS</div>
              <div style="font-size:32px; font-weight:900; color:#ffffff;">{total}</div>
            </div>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- SCAN META -->
  <tr>
    <td style="background:#f8fafd; padding:14px 36px; border-bottom:1px solid #e8ecf0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="font-size:12px; color:#666;">
            <strong style="color:#333;">Project:</strong>&nbsp; {project}
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <strong style="color:#333;">Scan ID:</strong>&nbsp; <code style="font-size:11px;">{scan_id}</code>
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <strong style="color:#333;">Date:</strong>&nbsp; {scan_date}
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- SEVERITY SECTION -->
  <tr>
    <td style="padding:28px 36px 10px;">
      <div style="font-size:16px; font-weight:700; color:#1a1a2e; margin-bottom:16px;
                  border-left:4px solid #005F8E; padding-left:10px;">
        Results by Severity
      </div>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse; border:1px solid #e8ecf0; border-radius:6px; overflow:hidden;">
        <thead>
          <tr style="background:#f0f4f8;">
            <th style="padding:10px 12px; text-align:left; font-size:12px;
                       color:#555; font-weight:600;">SEVERITY</th>
            <th style="padding:10px 12px; text-align:left; font-size:12px;
                       color:#555; font-weight:600;">DISTRIBUTION</th>
            <th style="padding:10px 12px; text-align:left; font-size:12px;
                       color:#555; font-weight:600;">COUNT</th>
          </tr>
        </thead>
        <tbody>{severity_rows}
        </tbody>
      </table>
    </td>
  </tr>

  <!-- VULNERABILITIES SECTION -->
  <tr>
    <td style="padding:28px 36px 10px;">
      <div style="font-size:16px; font-weight:700; color:#1a1a2e; margin-bottom:16px;
                  border-left:4px solid #D93025; padding-left:10px;">
        Top Vulnerabilities Detected
      </div>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse; border:1px solid #e8ecf0; border-radius:6px; overflow:hidden;">
        <thead>
          <tr style="background:#f0f4f8;">
            <th style="padding:10px 14px; text-align:left; font-size:12px; color:#555; width:36px;">#</th>
            <th style="padding:10px 14px; text-align:left; font-size:12px; color:#555;">VULNERABILITY</th>
            <th style="padding:10px 14px; text-align:center; font-size:12px; color:#555;">OCCURRENCES</th>
          </tr>
        </thead>
        <tbody>{vuln_rows}
        </tbody>
      </table>
    </td>
  </tr>

  <!-- CTA BUTTON -->
  <tr>
    <td style="padding:24px 36px;">
      <a href="{server}" style="display:inline-block; background:#005F8E; color:#ffffff;
         text-decoration:none; padding:12px 28px; border-radius:6px;
         font-weight:600; font-size:14px; letter-spacing:0.3px;">
        &#x1F517; View Full Results in Checkmarx One
      </a>
    </td>
  </tr>

  <!-- FOOTER -->
  <tr>
    <td style="background:#f8fafd; border-top:1px solid #e8ecf0;
               padding:16px 36px; text-align:center;">
      <p style="margin:0; font-size:11px; color:#999;">
        This is an automated report generated by the Checkmarx CI/CD Pipeline Script.<br>
        Do not reply to this email. For support, contact your AppSec team.
      </p>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    return html


# ─────────────────────────────────────────────
# 7.  SEND EMAIL
# ─────────────────────────────────────────────

def send_email(summary: dict, html_body: str, config: dict) -> None:
    """Send the HTML report email via SMTP."""
    email_cfg   = config["email"]
    recipients  = email_cfg["recipients"]
    sender      = email_cfg["sender"]
    project     = summary["project_name"]
    total       = summary["total"]

    # Build severity badge for subject line
    critical = summary["results_by_severity"].get("Critical", 0)
    high     = summary["results_by_severity"].get("High", 0)
    subject  = (
        f"[Checkmarx] Scan Report | {project} | "
        f"{total} Findings | C:{critical} H:{high}"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = sender
    msg["To"]      = ", ".join(recipients)

    # Plain-text fallback
    plain_lines = [f"Checkmarx One Scan Report — {project}", "=" * 48,
                   f"Total Findings : {total}", ""]
    for sev, cnt in summary["results_by_severity"].items():
        plain_lines.append(f"  {sev:<12}: {cnt}")
    plain_lines += ["", "Top Vulnerabilities:"]
    for vuln, cnt in list(summary["results_by_vuln"].items())[:10]:
        plain_lines.append(f"  {vuln}: {cnt}")

    msg.attach(MIMEText("\n".join(plain_lines), "plain"))
    msg.attach(MIMEText(html_body, "html"))

    smtp_host = email_cfg["smtp_host"]
    smtp_port = int(email_cfg.get("smtp_port", 587))
    username  = email_cfg.get("username", "")
    password  = email_cfg.get("password", "")

    try:
        print(f"\n[INFO]  Connecting to SMTP: {smtp_host}:{smtp_port}")
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.ehlo()
            if smtp_port != 25:
                server.starttls()
                server.ehlo()
            if username and password:
                server.login(username, password)
            server.sendmail(sender, recipients, msg.as_string())
        print(f"[OK]    Email sent to: {', '.join(recipients)}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")
        raise


# ─────────────────────────────────────────────
# 8.  MAIN ORCHESTRATOR
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Checkmarx One CI/CD Pipeline — Pull → Scan → Report → Email"
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to YAML config file (default: config.yaml)"
    )
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  Checkmarx One CI/CD Pipeline")
    print(f"  Platform : {platform.system()} {platform.release()}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    # Load config
    config = load_config(args.config)

    # Step 1: Pull source code
    source_dir = pull_source_code(
        repo_url   = config["repository"]["url"],
        target_dir = config["repository"].get("local_path", "source_code")
    )

    # Step 2: Resolve cx CLI
    cx_cli = resolve_cx_cli(config["checkmarx"].get("cx_cli_path", "auto"))

    # Step 3: Run scan
    report_file = run_cx_scan(
        cx_cli     = cx_cli,
        config     = config,
        source_dir = source_dir,
        report_dir = config.get("report_dir", "reports")
    )

    # Step 4: Parse report
    summary = parse_report(report_file)

    # Step 5: Build + send HTML email
    html_body = build_html_email(summary, config)
    send_email(summary, html_body, config)

    print("\n" + "=" * 60)
    print("  Pipeline completed successfully.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
