"""
vulnerable_app.py
─────────────────────────────────────────────────────────────
Sample intentionally vulnerable Python application.
FOR DEMONSTRATION / SECURITY TESTING PURPOSES ONLY.
This file is used as scan input for the Checkmarx Assignment.
─────────────────────────────────────────────────────────────
Contains intentional vulnerabilities including:
  - SQL Injection
  - Command Injection
  - Path Traversal
  - Hardcoded Credentials
  - Insecure Deserialization
  - XSS (reflected)
"""

import os
import pickle
import sqlite3
import subprocess


# ── Hardcoded Credentials (CWE-798) ───────────────────────────
DB_PASSWORD = "admin123"
SECRET_KEY  = "hardcoded-secret-key-do-not-use"


def get_user(username: str):
    """SQL Injection vulnerability (CWE-89)"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: user input directly concatenated into SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


def read_file(filename: str) -> str:
    """Path Traversal vulnerability (CWE-22)"""
    # VULNERABLE: no sanitization of filename input
    base_dir = "/var/www/files/"
    file_path = base_dir + filename
    with open(file_path, "r") as f:
        return f.read()


def run_command(user_input: str) -> str:
    """Command Injection vulnerability (CWE-78)"""
    # VULNERABLE: user input passed directly to shell
    result = subprocess.check_output("ping -c 1 " + user_input, shell=True)
    return result.decode()


def render_page(user_name: str) -> str:
    """Cross-Site Scripting / XSS vulnerability (CWE-79)"""
    # VULNERABLE: unsanitized user input reflected into HTML
    return f"<html><body><h1>Welcome {user_name}</h1></body></html>"


def load_user_data(data: bytes):
    """Insecure Deserialization vulnerability (CWE-502)"""
    # VULNERABLE: deserializing untrusted data
    return pickle.loads(data)


def authenticate(username: str, password: str) -> bool:
    """Broken Authentication (CWE-287)"""
    # VULNERABLE: comparing against hardcoded credentials
    if username == "admin" and password == DB_PASSWORD:
        return True
    return False
