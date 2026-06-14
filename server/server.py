#!/usr/bin/env python3
"""
CTF Challenge: Operation Firewall Breach
Vulnerable Server - DO NOT MODIFY (participants work on defender.py and rules/)
"""

import http.server
import socketserver
import json
import sqlite3
import os
import sys
import hashlib
import time
import logging
import threading
import base64
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename="server/server.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

# ─── Shared Defense State ────────────────────────────────────────────────────
# Participants populate this by running their defender
DEFENSE_STATE_FILE = "defender/defense_state.json"

def load_defense_state():
    if os.path.exists(DEFENSE_STATE_FILE):
        with open(DEFENSE_STATE_FILE) as f:
            return json.load(f)
    return {}

# ─── Database ────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("server/users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        role TEXT
    )""")
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'sup3rs3cr3t!', 'admin')")
    c.execute("INSERT INTO users VALUES (2, 'alice', 'alice123', 'user')")
    c.execute("INSERT INTO users VALUES (3, 'bob', 'bobpass', 'user')")
    conn.commit()
    conn.close()

init_db()

# ─── Attack Tracking ─────────────────────────────────────────────────────────
attack_log = []
blocked_attacks = set()

ATTACK_VECTORS = {
    "sqli":          {"label": "SQL Injection",         "severity": "CRITICAL", "blocked": False},
    "xss":           {"label": "Cross-Site Scripting",  "severity": "HIGH",     "blocked": False},
    "path_traversal":{"label": "Path Traversal",        "severity": "HIGH",     "blocked": False},
    "brute_force":   {"label": "Brute Force Login",     "severity": "MEDIUM",   "blocked": False},
    "log_injection": {"label": "Log Injection",         "severity": "MEDIUM",   "blocked": False},
}

def record_attack(vector, path, payload, blocked=False):
    entry = {
        "time": datetime.now().isoformat(),
        "vector": vector,
        "path": path,
        "payload": payload[:200],
        "blocked": blocked,
    }
    attack_log.append(entry)
    status = "BLOCKED ✓" if blocked else "HIT ✗"
    logging.warning(f"[{vector.upper()}] {status} | path={path} | payload={payload[:80]}")
    if blocked:
        ATTACK_VECTORS[vector]["blocked"] = True
        blocked_attacks.add(vector)

def all_attacks_blocked():
    return all(v["blocked"] for v in ATTACK_VECTORS.values())

# ─── Request Handler ──────────────────────────────────────────────────────────
class VulnerableHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # suppress default

    def send_json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, code, html):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

    def check_defense(self, vector, path, payload):
        """Ask the defender proxy whether this should be blocked."""
        state = load_defense_state()
        rules = state.get("rules", {})
        return rules.get(vector, False)

    # ── Routes ──────────────────────────────────────────────────────────────

    def handle_login(self):
        body = self.read_body()
        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]

        # Brute-force detection
        ip = self.client_address[0]
        if self.check_defense("brute_force", "/login", f"user={username}"):
            record_attack("brute_force", "/login", f"user={username},pass={password}", blocked=True)
            self.send_json(429, {"error": "Too many requests. Blocked by WAF."})
            return

        # SQL Injection vulnerable endpoint
        sqli_payload = f"' OR '1'='1"
        if sqli_payload.replace(" ", "") in password.replace(" ", "") or "--" in password or "UNION" in password.upper():
            if self.check_defense("sqli", "/login", password):
                record_attack("sqli", "/login", password, blocked=True)
                self.send_json(403, {"error": "SQL injection detected and blocked."})
                return
            else:
                record_attack("sqli", "/login", password, blocked=False)
                # Simulate successful SQLi
                self.send_json(200, {
                    "success": True,
                    "message": "Logged in as admin via SQL injection!",
                    "flag_hint": "You found SQLi but the flag needs more..."
                })
                return

        # Normal login
        conn = sqlite3.connect("server/users.db")
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
        row = c.fetchone()
        conn.close()
        if row:
            self.send_json(200, {"success": True, "role": row[0]})
        else:
            self.send_json(401, {"error": "Invalid credentials"})

    def handle_search(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        query = params.get("q", [""])[0]

        # XSS check
        xss_markers = ["<script", "javascript:", "onerror=", "onload=", "<img", "alert("]
        is_xss = any(m.lower() in query.lower() for m in xss_markers)
        if is_xss:
            if self.check_defense("xss", "/search", query):
                record_attack("xss", "/search", query, blocked=True)
                self.send_html(403, "<h1>403 - XSS Blocked by WAF</h1>")
                return
            else:
                record_attack("xss", "/search", query, blocked=False)
                # Reflect XSS unsanitized
                html = f"""<html><body>
                <h2>Search Results for: {query}</h2>
                <p>No results found. (XSS executed!)</p>
                </body></html>"""
                self.send_html(200, html)
                return

        self.send_html(200, f"<html><body><h2>Search: {query}</h2><p>No results.</p></body></html>")

    def handle_file(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        filename = params.get("name", [""])[0]
        filename = unquote(filename)

        # Path traversal check
        traversal_markers = ["../", "..\\", "%2e%2e", "etc/passwd", "etc/shadow", "flag"]
        is_traversal = any(m.lower() in filename.lower() for m in traversal_markers)
        if is_traversal:
            if self.check_defense("path_traversal", "/file", filename):
                record_attack("path_traversal", "/file", filename, blocked=True)
                self.send_json(403, {"error": "Path traversal blocked by WAF."})
                return
            else:
                record_attack("path_traversal", "/file", filename, blocked=False)
                self.send_json(200, {
                    "warning": "Path traversal not blocked!",
                    "attempted_path": filename,
                    "hint": "You can read arbitrary files... if the flag wasn't encrypted."
                })
                return

        safe_path = os.path.join("server/public", os.path.basename(filename))
        if os.path.exists(safe_path):
            with open(safe_path) as f:
                self.send_json(200, {"content": f.read()})
        else:
            self.send_json(404, {"error": "File not found"})

    def handle_log_endpoint(self):
        body = self.read_body()
        params = parse_qs(body)
        msg = params.get("msg", [""])[0]

        # Log injection check
        injection_markers = ["\n", "\r", "INFO", "ERROR", "WARNING", "CRITICAL", "|", "admin", "flag"]
        is_injection = any(m in msg for m in injection_markers)
        if is_injection:
            if self.check_defense("log_injection", "/log", msg):
                record_attack("log_injection", "/log", msg, blocked=True)
                self.send_json(403, {"error": "Log injection blocked."})
                return
            else:
                record_attack("log_injection", "/log", msg, blocked=False)
                # Write injected content straight to log
                logging.warning(f"USER LOG: {msg}")
                self.send_json(200, {"logged": True, "warning": "Log injection succeeded!"})
                return

        logging.info(f"USER LOG: {msg}")
        self.send_json(200, {"logged": True})

    def handle_status(self):
        """Public status endpoint showing attack/defense state."""
        state = {
            "attacks": ATTACK_VECTORS,
            "blocked_count": len(blocked_attacks),
            "total_vectors": len(ATTACK_VECTORS),
            "all_blocked": all_attacks_blocked(),
            "recent_log": attack_log[-10:],
        }
        self.send_json(200, state)

    def handle_flag(self):
        """Only reveals flag hint when all attacks blocked."""
        if all_attacks_blocked():
            # Trigger flag decryption
            from flag_system.flag_manager import get_flag
            flag = get_flag()
            self.send_json(200, {
                "success": True,
                "message": "All attack vectors neutralized! You are a true defender.",
                "flag": flag,
            })
        else:
            remaining = [k for k, v in ATTACK_VECTORS.items() if not v["blocked"]]
            self.send_json(403, {
                "error": "Flag locked. Not all attacks have been blocked.",
                "remaining_vectors": remaining,
            })

    # ── Dispatch ─────────────────────────────────────────────────────────────

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/status":
            self.handle_status()
        elif path == "/search":
            self.handle_search()
        elif path == "/file":
            self.handle_file()
        elif path == "/flag":
            self.handle_flag()
        else:
            self.send_json(404, {"error": "Not found", "endpoints": ["/status", "/search", "/file", "/log", "/login", "/flag"]})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/login":
            self.handle_login()
        elif path == "/log":
            self.handle_log_endpoint()
        else:
            self.send_json(404, {"error": "Not found"})


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    os.makedirs("server/public", exist_ok=True)
    with open("server/public/readme.txt", "w") as f:
        f.write("Welcome to the CTF server. Nothing interesting here.\n")

    PORT = 8888
    with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
        httpd.allow_reuse_address = True
        print(f"\n{'='*55}")
        print(f"  [SERVER] Vulnerable server running on port {PORT}")
        print(f"  [SERVER] Endpoints: /status /search /file /login /log /flag")
        print(f"{'='*55}\n")
        httpd.serve_forever()
