#!/usr/bin/env python3
# -------------------------------------------------------------
# WARNING: Intentionally Vulnerable Python Application new file
# -------------------------------------------------------------
# Purpose: This file is provided solely for static analysis (SAST) testing.
# DO NOT deploy, run in production, or expose publicly.
# Many patterns below are insecure by design to trigger scanners.
# -------------------------------------------------------------

import os
import subprocess
import sqlite3
import pickle
import hashlib
import random
import string
import logging
import tempfile

# Third-party modules referenced for scanning purposes (not required to run this creator script)
import requests  # noqa: F401
import yaml      # noqa: F401
from flask import Flask, request, redirect, make_response  # noqa: F401
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Hardcoded secrets (vulnerability: hardcoded credentials) ---
API_KEY = "supersecretapikey123"  # VULN: hardcoded secret
DB_PASSWORD = "P@ssw0rd!"         # VULN: hardcoded secret

app = Flask(__name__)
app.config["DEBUG"] = True  # VULN: debug mode enabled
app.secret_key = "insecuresecret"  # VULN: weak secret key

# 1) Command Injection via shell=True
@app.route('/run')
def run_cmd():
    cmd = request.args.get('cmd', '')
    # VULN: untrusted input executed in shell
    output = subprocess.check_output(cmd, shell=True)
    return output

# 2) SQL Injection via string concatenation
def get_user(username):
    conn = sqlite3.connect('app.db')
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"  # VULN: unsanitized input
    cur.execute(query)  # VULN: SQL injection
    rows = cur.fetchall()
    conn.close()
    return rows

@app.route('/user')
def user():
    u = request.args.get('u', '')
    data = get_user(u)
    return str(data)

# 3) Path Traversal reading arbitrary files
@app.route('/read')
def read_file():
    path = request.args.get('path', '')
    # VULN: joins user-provided path; allows ../../etc/passwd
    with open(os.path.join('uploads', path), 'r') as f:
        return f.read()

# 4) Insecure Deserialization (pickle)
@app.route('/load')
def load():
    blob = request.args.get('blob', '')
    # VULN: loading attacker-controlled data
    try:
        obj = pickle.loads(bytes(blob, 'utf-8'))  # will raise if not valid pickle; still intentionally unsafe
    except Exception:
        obj = "deserialization error (still unsafe pattern)"
    return str(obj)

# 5) Weak Crypto (MD5)
def make_hash(data):
    # VULN: insecure hash function
    return hashlib.md5(data.encode()).hexdigest()

# 6) Predictable Tokens (random module)
def generate_token(n=16):
    # VULN: not cryptographically secure
    return ''.join(random.choice(string.ascii_letters) for _ in range(n))

# 7) SSRF + TLS verification disabled
@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    # VULN: requests to arbitrary URL, verify=False disables TLS verification
    r = requests.get(url, verify=False)  # noqa: S501 (bandit), VULN
    return r.text

# 8) Open Redirect
@app.route('/go')
def go():
    target = request.args.get('next', '/')
    # VULN: redirects to untrusted URL
    return redirect(target)

# 9) Reflected XSS
@app.route('/echo')
def echo():
    msg = request.args.get('msg', '')
    # VULN: unescaped HTML output
    return f"<html><body>Message: {msg}</body></html>"

# 10) Unsafe YAML load
@app.route('/yaml')
def load_yaml():
    doc = request.args.get('doc', '')
    # VULN: yaml.load with full Loader executes arbitrary objects
    data = yaml.load(doc, Loader=yaml.Loader)
    return str(data)

# 11) Insecure temp file creation / permissions
@app.route('/save')
def save():
    content = request.args.get('content', '')
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(content.encode())
    tmp.close()
    os.chmod(tmp.name, 0o777)  # VULN: world-writable
    return tmp.name

# 12) Eval Injection
@app.route('/calc')
def calc():
    expr = request.args.get('expr', '1+1')
    # VULN: evaluates untrusted input
    return str(eval(expr))

# 13) Sensitive Logging of credentials
@app.route('/login', methods=['POST'])
def login():
    user = request.form.get('user', '')
    pwd = request.form.get('pwd', '')
    # VULN: logs credentials
    logging.warning(f"Login attempt: user={user} password={pwd}")
    return "ok"

# 14) Broad Exception Catch (information hiding)
@app.route('/unsafe')
def unsafe():
    try:
        return str(1/0)
    except Exception as e:  # VULN: overly broad, hides root cause
        return "error"

# 15) Insecure Cookie settings (no HttpOnly, Secure false)
@app.route('/setcookie')
def setcookie():
    resp = make_response('ok')
    resp.set_cookie('session', generate_token(), secure=False, httponly=False, samesite='None')  # VULN
    return resp

# 16) Overly-permissive file write (directory traversal)
@app.route('/write')
def write_file():
    filename = request.args.get('file', 'note.txt')
    data = request.args.get('data', '')
    # VULN: allows writing anywhere under server's FS
    with open(filename, 'w') as f:
        f.write(data)
    return f"wrote {len(data)} bytes to {filename}"

# 17) World-readable secrets file
@app.route('/dump-secrets')
def dump_secrets():
    # VULN: writes secrets to disk with 0777 perms
    path = 'secrets.txt'
    with open(path, 'w') as f:
        f.write(f"API_KEY={API_KEY}\nDB_PASSWORD={DB_PASSWORD}\n")
    os.chmod(path, 0o777)
    return path

if __name__ == "__main__":
    # VULN: binds to all interfaces, debug enabled
    app.run(host="0.0.0.0", port=5000, debug=True)
