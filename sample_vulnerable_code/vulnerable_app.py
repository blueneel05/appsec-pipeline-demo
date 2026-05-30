"""
vulnerable_app.py
-----------------
Intentionally vulnerable Python web application.
FOR SECURITY TESTING AND DEMONSTRATION PURPOSES ONLY.
Used as scan target for Checkmarx One SAST exercise.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess
from flask import Flask, request, redirect, make_response

app = Flask(__name__)

# CWE-798: Hardcoded credentials
SECRET_KEY   = "hardcoded-secret-key-abc123"
DB_PASSWORD  = "admin123"
ADMIN_TOKEN  = "supersecrettoken99"
DATABASE     = "users.db"


# ── CWE-89: SQL Injection ──────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # VULNERABLE: direct string concatenation into SQL
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        return "Login successful"
    return "Login failed", 401


# ── CWE-89: SQL Injection (second variant) ────────────────────
@app.route("/user", methods=["GET"])
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # VULNERABLE: format string injection
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    result = cursor.fetchall()
    conn.close()
    return str(result)


# ── CWE-78: OS Command Injection ──────────────────────────────
@app.route("/ping", methods=["GET"])
def ping():
    host = request.args.get("host")
    # VULNERABLE: user input passed directly to shell
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output.decode()


# ── CWE-78: Command Injection (second variant) ────────────────
@app.route("/file_info", methods=["GET"])
def file_info():
    filename = request.args.get("filename")
    # VULNERABLE: os.system with unsanitized input
    os.system("ls -la " + filename)
    return "Done"


# ── CWE-22: Path Traversal ────────────────────────────────────
@app.route("/download", methods=["GET"])
def download():
    filename = request.args.get("file")
    # VULNERABLE: no path sanitization
    base_path = "/var/www/uploads/"
    full_path = base_path + filename
    with open(full_path, "rb") as f:
        data = f.read()
    return data


# ── CWE-22: Path Traversal (second variant) ───────────────────
@app.route("/read", methods=["GET"])
def read_file():
    path = request.args.get("path")
    # VULNERABLE: arbitrary file read
    with open(path, "r") as f:
        return f.read()


# ── CWE-79: Reflected XSS ─────────────────────────────────────
@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "")
    # VULNERABLE: unsanitized input reflected into HTML response
    html = "<html><body><h1>Search results for: " + query + "</h1></body></html>"
    return html


# ── CWE-79: XSS in error page ─────────────────────────────────
@app.route("/profile", methods=["GET"])
def profile():
    username = request.args.get("username")
    # VULNERABLE: user input embedded directly in HTML
    response = make_response(
        "<html><body><p>Welcome, " + username + "! Your profile page.</p></body></html>"
    )
    return response


# ── CWE-502: Insecure Deserialization ─────────────────────────
@app.route("/load_session", methods=["POST"])
def load_session():
    # VULNERABLE: deserializing untrusted user data with pickle
    session_data = request.get_data()
    user_obj = pickle.loads(session_data)
    return str(user_obj)


# ── CWE-327: Weak Cryptography ────────────────────────────────
@app.route("/reset_password", methods=["POST"])
def reset_password():
    password = request.form.get("password")
    # VULNERABLE: MD5 is cryptographically broken for passwords
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect(DATABASE)
    username = request.form.get("username")
    conn.execute("UPDATE users SET password='" + hashed + "' WHERE username='" + username + "'")
    conn.commit()
    conn.close()
    return "Password updated"


# ── CWE-601: Open Redirect ────────────────────────────────────
@app.route("/redirect", methods=["GET"])
def open_redirect():
    url = request.args.get("next")
    # VULNERABLE: redirecting to user-controlled URL without validation
    return redirect(url)


# ── CWE-200: Sensitive Data Exposure ──────────────────────────
@app.route("/debug", methods=["GET"])
def debug():
    token = request.args.get("token")
    if token == ADMIN_TOKEN:
        # VULNERABLE: exposing environment variables and internal config
        return str({
            "env": dict(os.environ),
            "db_password": DB_PASSWORD,
            "secret_key": SECRET_KEY,
        })
    return "Unauthorized", 403


if __name__ == "__main__":
    # VULNERABLE: debug=True exposes interactive debugger in production
    app.run(debug=True, host="0.0.0.0", port=5000)
