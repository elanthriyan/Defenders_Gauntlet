#!/usr/bin/env python3
"""
CTF Challenge: Operation Firewall Breach
DEFENDER — Your job is to implement all 5 defense rules below.

Run modes:
  python defender/defender.py validate   → test your rules
  python defender/defender.py flag       → get the flag (after passing validate)
  python defender/defender.py status     → show current defense state
"""

import json
import os
import re
import html
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from urllib.parse import unquote, parse_qs
from datetime import datetime


# ════════════════════════════════════════════════════════════════════
#  BASE CLASS — do not modify
# ════════════════════════════════════════════════════════════════════

class DefenseRule(ABC):
    @abstractmethod
    def should_block(self, path, payload, headers, ip, timestamp):
        """
        Return True to block the request, False to allow it.

        Args:
            path      (str)   : Request path e.g. "/login", "/search"
            payload   (str)   : The raw input string to inspect
            headers   (dict)  : HTTP headers
            ip        (str)   : Client IP address
            timestamp (float) : time.time() of the request
        """
        raise NotImplementedError

    def reset(self):
        """Called between test cases. Override if your rule has state."""
        pass


# ════════════════════════════════════════════════════════════════════
#  RULE 1 — SQL INJECTION
# ════════════════════════════════════════════════════════════════════

class SQLInjectionDefense(DefenseRule):
    """
    Block SQL injection attempts on POST /login.

    Payloads arrive in the `password` field and may be URL-encoded.
    You must detect them generically — no hardcoding specific strings.

    Patterns to detect:
      • SQL comment sequences:  --   #   /*   */
      • Boolean tautologies:    OR 1=1   OR 'x'='x   AND 1=1
      • UNION-based injection:  UNION SELECT ...
      • Stacked queries:        '; DROP TABLE users;--
      • Dangerous functions:    SLEEP(), BENCHMARK(), LOAD_FILE()

    Tips:
      • Always URL-decode the payload first (double-decode to catch %2527 etc.)
        Use: unquote(unquote(payload))
      • Compile your regexes with re.IGNORECASE
      • Use \b word boundaries to avoid false positives on normal words

    Must BLOCK:  ' OR '1'='1   |   admin'--   |   ' UNION SELECT * FROM users--
    Must ALLOW:  mypassword123  |   P@ssw0rd!  |   O'Brien
    """

    def should_block(self, path, payload, headers, ip, timestamp):
        # TODO: Implement SQL injection detection
        # Hint: decode first, then run regex checks
        return False


# ════════════════════════════════════════════════════════════════════
#  RULE 2 — CROSS-SITE SCRIPTING (XSS)
# ════════════════════════════════════════════════════════════════════

class XSSDefense(DefenseRule):
    """
    Block XSS payloads on GET /search?q=<payload>.

    Attackers inject HTML/JS into the query string, which gets
    reflected back into the page unsanitized.

    Patterns to detect:
      • Dangerous HTML tags:    <script>  <iframe>  <svg>  <img>  <object>
      • Inline event handlers:  onerror=  onload=   onclick=  (any on\w+=)
      • Protocol handlers:      javascript:   vbscript:   data:
      • HTML entity encoding:   &#x3C;script&#x3E; → decoded is <script>

    Tips:
      • Normalize before checking:
          html.unescape(unquote(unquote(payload))).lower()
      • This handles both URL-encoding AND HTML-entity encoding in one step
      • Match tag openings with:  <\s*(script|svg|img|...)
      • Match event handlers with:  \bon\w+\s*=

    Must BLOCK:  <script>alert(1)</script>   |   <img src=x onerror=alert(1)>
                 javascript:alert(1)          |   %3Cscript%3Ealert(1)%3C%2Fscript%3E
    Must ALLOW:  hello world   |   price < 100   |   C++ programming
    """

    def should_block(self, path, payload, headers, ip, timestamp):
        # TODO: Implement XSS detection
        # Hint: normalize (unescape + url-decode + lowercase), then regex match
        return False


# ════════════════════════════════════════════════════════════════════
#  RULE 3 — PATH TRAVERSAL
# ════════════════════════════════════════════════════════════════════

class PathTraversalDefense(DefenseRule):
    """
    Block path traversal attempts on GET /file?name=<payload>.

    Attackers use sequences like ../../ to escape the web root
    and read sensitive files like /etc/passwd or the flag.

    Approach:
      1. Check for null bytes (\x00 or %00) — used to truncate paths
      2. Double URL-decode the payload
      3. Normalize with os.path.normpath()
      4. Build the full absolute path with os.path.join(BASE_DIR, normalized)
      5. Block if the result does NOT start with BASE_DIR
      6. Also block if raw payload matches traversal patterns

    BASE_DIR should be the absolute path to "server/public"

    Encoding tricks to handle:
      • ../          standard
      • ..%2F        URL-encoded slash
      • %2e%2e%2f    fully URL-encoded
      • ....//       double-dot slash bypass
      • ..\          Windows-style

    Must BLOCK:  ../../../etc/passwd   |   ..%2F..%2Fetc%2Fshadow
                 %2e%2e%2fetc%2fpasswd  |   file\x00.txt
    Must ALLOW:  readme.txt   |   report_2024.pdf   |   image.png
    """

    BASE_DIR = os.path.abspath("server/public")

    def should_block(self, path, payload, headers, ip, timestamp):
        # TODO: Implement path traversal detection
        # Hint: null byte check → double decode → normpath → abspath → startswith check
        return False


# ════════════════════════════════════════════════════════════════════
#  RULE 4 — BRUTE FORCE LOGIN
# ════════════════════════════════════════════════════════════════════

class BruteForceDefense(DefenseRule):
    """
    Block brute force login attempts on POST /login using rate limiting.

    You must implement SLIDING WINDOW rate limiting — no string matching.
    Track three independent counters:

      Per-IP limit:
        > 3 login attempts from the same IP within 30 seconds → block that IP
        Apply exponential backoff lockout: 60s * 2^(violations-1)

      Per-username limit:
        > 3 attempts for the same username within 60 seconds → block that user
        Apply exponential backoff lockout on the username too

      Global limit:
        > 20 total login attempts within 10 seconds → block everyone

    The payload arrives as a URL-encoded body: "username=admin&password=xyz"
    Extract username with: parse_qs(payload).get("username", ["unknown"])[0]

    State: use defaultdict(deque) to store timestamps per IP and per username.
    Prune old entries by removing timestamps older than your window on each call.

    Must BLOCK:  5+ attempts from same IP in 30s
    Must ALLOW:  First attempt from a new IP always passes
    """

    # Tunable thresholds
    IP_LIMIT      = 3
    IP_WINDOW     = 30   # seconds
    USER_LIMIT    = 3
    USER_WINDOW   = 60   # seconds
    GLOBAL_LIMIT  = 20
    GLOBAL_WINDOW = 10   # seconds
    LOCKOUT_BASE  = 60   # seconds (doubles on each violation)

    def __init__(self):
        # TODO: Initialize your data structures here
        # Hint: defaultdict(deque) for ip_log and user_log, plain deque for global_log
        # Also need dicts for ip_lockouts and user_lockouts
        pass

    def reset(self):
        """Called between test runs — reinitialize all state."""
        self.__init__()

    def should_block(self, path, payload, headers, ip, timestamp):
        # TODO: Implement sliding window rate limiting
        # Steps:
        #   1. Check if IP or username is currently locked out
        #   2. Prune + check global window
        #   3. Prune + check per-IP window → lock out if over limit
        #   4. Prune + check per-username window → lock out if over limit
        #   5. If not blocked, record this attempt in all three logs
        return False


# ════════════════════════════════════════════════════════════════════
#  RULE 5 — LOG INJECTION
# ════════════════════════════════════════════════════════════════════

class LogInjectionDefense(DefenseRule):
    """
    Block log injection attempts on POST /log.

    Attackers inject newlines and fake log entries to forge audit trails,
    or use ANSI escape codes to corrupt terminal output.

    Patterns to detect and block:
      • Newline characters:     \n  \r  (used to inject fake log lines)
      • ANSI escape sequences:  \x1b[31m  etc. (corrupt terminal display)
      • Null bytes:             \x00  (truncate log entries)
      • Control characters:     \x00-\x08, \x0b-\x1f, \x7f-\x9f
      • Fake log format:        "INFO 2024-01-01 ..."  "ERROR 2024-..." etc.
                                (timestamp-prefixed log-level keywords)

    Approach:
      1. Block immediately if \n or \r found in payload
      2. Block if ANSI escape or \x00 found
      3. Sanitize: strip ANSI, strip control chars, replace newlines
         Block if len(payload) - len(sanitized) > 2  (too much was stripped)
      4. Block if payload matches a log-format pattern:
         (INFO|ERROR|WARNING|CRITICAL|DEBUG) followed by a date

    Must BLOCK:  "hello\nCRITICAL: system compromised"
                 "test\rERROR [AUTH] admin changed"
                 "hello\x1b[31mRED TEXT"
    Must ALLOW:  "Server restarted successfully"
                 "Processing 142 records"
                 "Request completed in 250ms"
    """

    def sanitize(self, payload):
        """
        Return a cleaned version of payload with dangerous chars removed.
        Use this to measure how much was stripped (for the diff check).
        """
        # TODO: Strip ANSI sequences, control characters, newlines
        return payload.strip()

    def should_block(self, path, payload, headers, ip, timestamp):
        # TODO: Implement log injection detection
        # Hint: newline check → ANSI/null check → sanitize diff check → log format check
        return False


# ════════════════════════════════════════════════════════════════════
#  DEFENSE ENGINE — do not modify
# ════════════════════════════════════════════════════════════════════

class DefenseEngine:
    VECTOR_MAP = {
        "sqli":           SQLInjectionDefense,
        "xss":            XSSDefense,
        "path_traversal": PathTraversalDefense,
        "brute_force":    BruteForceDefense,
        "log_injection":  LogInjectionDefense,
    }

    def __init__(self):
        self.rules = {name: cls() for name, cls in self.VECTOR_MAP.items()}
        try:
            with open("defender/defense_state.json") as f:
                saved = json.load(f)
            self.state = saved.get("rules", {name: False for name in self.VECTOR_MAP})
            self._activated_at = saved.get("activated_at", time.time())
        except:
            self.state = {name: False for name in self.VECTOR_MAP}
            self._activated_at = time.time()

    def _save_state(self):
        os.makedirs("defender", exist_ok=True)
        with open("defender/defense_state.json", "w") as f:
            json.dump({
                "rules": self.state,
                "activated_at": self._activated_at,
                "timestamp": datetime.now().isoformat(),
            }, f, indent=2)

    def _run_all_tests(self):
        tests = {
            "sqli": [
                ("/login", "' OR '1'='1"),
                ("/login", "admin'--"),
                ("/login", "' UNION SELECT * FROM users--"),
                ("/login", "'; DROP TABLE users;--"),
                ("/login", "1; SLEEP(5)--"),
            ],
            "xss": [
                ("/search", "<script>alert(1)</script>"),
                ("/search", "<img src=x onerror=alert(1)>"),
                ("/search", "javascript:alert(1)"),
                ("/search", "<svg onload=alert('xss')>"),
            ],
            "path_traversal": [
                ("/file", "../../../etc/passwd"),
                ("/file", "..%2F..%2Fetc%2Fshadow"),
                ("/file", "../flag_system/flag.enc"),
            ],
            "brute_force": [
                *[("/login", f"username=admin&password=attempt{i}") for i in range(5)],
            ],
            "log_injection": [
                ("/log", "hello\nCRITICAL: system compromised"),
                ("/log", "test\rERROR [AUTH] admin password changed"),
                ("/log", "msg\x00truncated"),
            ],
        }
        for vector, cases in tests.items():
            rule = self.rules[vector]
            all_blocked = all(
                rule.should_block(path, payload, {}, "1.2.3.4", time.time())
                for path, payload in cases
            )
            if all_blocked:
                self.state[vector] = True
        self._save_state()

    def status(self):
        print("\n" + "═" * 55)
        print("  DEFENSE STATUS")
        print("═" * 55)
        for name, active in self.state.items():
            icon = "✓ ACTIVE" if active else "✗ INACTIVE"
            print(f"  {name:<20} {icon}")
        print("═" * 55)
        remaining = [n for n, a in self.state.items() if not a]
        if not remaining:
            print("  🏆 ALL DEFENSES ACTIVE!")
        else:
            print(f"  ⚠  Remaining: {remaining}")
        print()


# ════════════════════════════════════════════════════════════════════
#  VALIDATOR — do not modify
# ════════════════════════════════════════════════════════════════════

def run_validator():
    engine = DefenseEngine()

    tests = {
        "sqli": {
            "must_block": [
                ("/login", "' OR '1'='1"),
                ("/login", "admin'--"),
                ("/login", "' UNION SELECT * FROM users--"),
                ("/login", "'; DROP TABLE users;--"),
                ("/login", "' OR 1=1#"),
                ("/login", "%27%20OR%20%271%27%3D%271"),
                ("/login", "1; SLEEP(5)--"),
            ],
            "must_allow": [
                ("/login", "mypassword123"),
                ("/login", "P@ssw0rd!"),
                ("/login", "correct-horse-battery-staple"),
                ("/login", "O'Brien"),
            ],
        },
        "xss": {
            "must_block": [
                ("/search", "<script>alert(1)</script>"),
                ("/search", "<img src=x onerror=alert(1)>"),
                ("/search", "javascript:alert(1)"),
                ("/search", "<svg onload=alert('xss')>"),
                ("/search", "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
                ("/search", "<ScRiPt>alert(1)</sCrIpT>"),
                ("/search", "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"),
            ],
            "must_allow": [
                ("/login", "hello world"),
                ("/login", "price < 100 and > 50"),
                ("/login", "C++ programming"),
                ("/login", "AT&T wireless plans"),
            ],
        },
        "path_traversal": {
            "must_block": [
                ("/file", "../../../etc/passwd"),
                ("/file", "..%2F..%2Fetc%2Fshadow"),
                ("/file", "....//....//etc/passwd"),
                ("/file", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
                ("/file", "../flag_system/flag.enc"),
                ("/file", "..\\..\\windows\\system32"),
                ("/file", "file\x00.txt"),
            ],
            "must_allow": [
                ("/file", "readme.txt"),
                ("/file", "report_2024.pdf"),
                ("/file", "image.png"),
                ("/file", "data-export.csv"),
            ],
        },
        "brute_force": {
            "must_block": [
                *[("/login", f"username=admin&password=attempt{i}", {"ip": "10.0.0.1"}) for i in range(5)],
            ],
            "must_allow": [
                ("/login", "username=alice&password=correctpass", {"ip": "10.0.0.2"}),
            ],
        },
        "log_injection": {
            "must_block": [
                ("/log", "hello\nCRITICAL: system compromised"),
                ("/log", "test\rERROR [AUTH] admin password changed"),
                ("/log", "msg\x00truncated"),
                ("/log", "hello\x1b[31mRED TEXT injection"),
                ("/log", "normal\nINFO 2024-01-01 fake log entry"),
            ],
            "must_allow": [
                ("/log", "Server restarted successfully"),
                ("/log", "User clicked button #3"),
                ("/log", "Processing 142 records"),
                ("/log", "Request completed in 250ms"),
            ],
        },
    }

    print("\n" + "═" * 60)
    print("  RUNNING DEFENSE VALIDATOR")
    print("═" * 60)

    total_pass = total_fail = 0
    vector_results = {}

    for vector, cases in tests.items():
        print(f"\n  [{vector.upper()}]")
        v_pass = v_fail = 0
        rule = engine.rules[vector]

        for case in cases.get("must_block", []):
            path, payload = case[0], case[1]
            headers = dict(case[2]) if len(case) > 2 else {}
            ip = headers.pop("ip", "1.2.3.4")
            result = rule.should_block(path, payload, headers, ip, time.time())
            if result:
                print(f"    ✓ BLOCKED (correct): {payload[:50]}")
                v_pass += 1
            else:
                print(f"    ✗ ALLOWED (should block): {payload[:50]}")
                v_fail += 1

        rule.reset()

        for case in cases.get("must_allow", []):
            path, payload = case[0], case[1]
            headers = dict(case[2]) if len(case) > 2 else {}
            ip = headers.pop("ip", "9.9.9.9")
            result = rule.should_block(path, payload, headers, ip, time.time())
            if not result:
                print(f"    ✓ ALLOWED (correct): {payload[:50]}")
                v_pass += 1
            else:
                print(f"    ✗ BLOCKED (false positive): {payload[:50]}")
                v_fail += 1

        total_pass += v_pass
        total_fail += v_fail
        pct = int(v_pass / (v_pass + v_fail) * 100) if (v_pass + v_fail) else 0
        print(f"    Score: {v_pass}/{v_pass+v_fail} ({pct}%)")
        vector_results[vector] = (v_fail == 0)

    print("\n" + "═" * 60)
    total = total_pass + total_fail
    pct = int(total_pass / total * 100) if total else 0
    print(f"  TOTAL: {total_pass}/{total} tests passed ({pct}%)")

    all_passed = total_fail == 0
    if all_passed:
        print("  🏆 ALL TESTS PASSED!")
        state = {
            "rules": {v: True for v in DefenseEngine.VECTOR_MAP},
            "activated_at": time.time() - 60,
            "timestamp": datetime.now().isoformat(),
        }
        os.makedirs("defender", exist_ok=True)
        with open("defender/defense_state.json", "w") as f:
            json.dump(state, f, indent=2)
        print("  ✓ Defense state updated. Run with 'flag' to get your flag.")
    else:
        print(f"  ⚠  {total_fail} tests failing. Fix your rules.")
    print("═" * 60 + "\n")
    return all_passed


# ════════════════════════════════════════════════════════════════════
#  FLAG — do not modify
# ════════════════════════════════════════════════════════════════════

def check_flag():
    import sys
    sys.path.insert(0, ".")
    engine = DefenseEngine()
    engine._run_all_tests()
    from flag_system.flag_manager import get_flag
    flag = get_flag()
    if flag.startswith("CTF{"):
        print(f"\n  🏆🏆🏆  FLAG: {flag}  🏆🏆🏆\n")
    else:
        print(f"\n  ✗ Not yet: {flag}\n")
        print("  → Run 'validate' first to check your rules.")
    return flag


# ════════════════════════════════════════════════════════════════════
#  ENTRY POINT — do not modify
# ════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "validate":
        run_validator()
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "flag":
        check_flag()
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "status":
        DefenseEngine().status()
        sys.exit(0)

    print("\n  [DEFENDER] Run with: validate | flag | status\n")
    DefenseEngine().status()