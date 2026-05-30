import sqlite3
import subprocess
import os

def get_user_data(user_input):
    conn = sqlite3.connect("app.db")
    # SQL Injection - direct concatenation
    result = conn.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
    return result.fetchall()

def run_report(report_name):
    # Command Injection
    os.system("generate_report.sh " + report_name)

def read_config(config_name):
    # Path Traversal
    with open("/etc/app/" + config_name) as f:
        return f.read()