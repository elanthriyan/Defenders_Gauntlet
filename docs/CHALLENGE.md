# 🛡️ Operation: Firewall Breach
### CTF Challenge — Defender Track

---

## Briefing

An attacker has compromised your network perimeter and is **continuously firing 5 categories of web attacks** at your organization's server.

Your job: **Implement a Web Application Firewall (WAF)** that blocks every attack vector.

When all 5 vectors are neutralized, the encrypted flag file will decrypt and reveal your prize.

---

## Rules

| Rule | Detail |
|------|--------|
| **Files you CAN edit** | `defender/defender.py` only |
| **Files you CANNOT edit** | `server/server.py`, `attacker/attacker.py`, `flag_system/flag_manager.py` |
| **No hardcoding payloads** | You cannot write `if "' OR" in payload`. Use generic detection logic |
| **No external WAF tools** | Implement the logic yourself in Python |
| **Brute force = rate limiting** | Must use sliding window counters, not string matching |
| **False positives matter** | Blocking legitimate traffic will fail the validator |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     YOUR ENVIRONMENT                         │
│                                                              │
│  ┌──────────────┐   HTTP    ┌───────────────────────────┐  │
│  │   ATTACKER   │ ────────▶ │   VULNERABLE SERVER       │  │
│  │ (automated)  │           │   port 8888               │  │
│  └──────────────┘           │                           │  │
│                             │  reads defense_state.json │  │
│  ┌──────────────┐   writes  │  on every request         │  │
│  │   DEFENDER   │ ────────▶ └───────────────────────────┘  │
│  │  (you edit)  │                                           │
│  └──────────────┘                                           │
│         │                                                    │
│         ▼                                                    │
│  defender/defense_state.json                                 │
│  { "rules": { "sqli": true, "xss": false, ... } }           │
│                                                              │
│  flag_system/flag.enc  ← AES-256 encrypted, key derived     │
│                           from correct defense state         │
└─────────────────────────────────────────────────────────────┘
```

---

## The 5 Attack Vectors

### 1. 🗄️ SQL Injection (CRITICAL)
**Endpoint:** `POST /login`  
**What it does:** Manipulates SQL queries to bypass authentication or exfiltrate data.  
**Your task:** Detect SQL metacharacters and keywords using regex. Handle URL-encoded variants.

**Example payloads you must block:**
- `' OR '1'='1`
- `admin'--`
- `' UNION SELECT username,password FROM users--`

---

### 2. 🌐 Cross-Site Scripting (HIGH)
**Endpoint:** `GET /search?q=<payload>`  
**What it does:** Injects client-side scripts that execute in victims' browsers.  
**Your task:** Detect script tags, event handlers, and protocol handlers. Handle encoding variants.

**Example payloads you must block:**
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `%3Cscript%3Ealert(1)%3C%2Fscript%3E` (URL-encoded)

---

### 3. 📂 Path Traversal (HIGH)
**Endpoint:** `GET /file?name=<payload>`  
**What it does:** Escapes the web root to read sensitive system files.  
**Your task:** Normalize the path and reject anything that escapes the allowed directory.

**Example payloads you must block:**
- `../../../etc/passwd`
- `..%2F..%2Fetc%2Fshadow`
- `%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- `file\x00.txt` (null byte injection)

---

### 4. 🔐 Brute Force Login (MEDIUM)
**Endpoint:** `POST /login`  
**What it does:** Tries thousands of password combinations to crack accounts.  
**Your task:** Implement sliding-window rate limiting per IP AND per username.

**You must track:**
- > 5 attempts from same IP within 30 seconds → block
- > 3 attempts for same username within 60 seconds → block  
- > 20 total attempts within 10 seconds → block all logins

---

### 5. 📋 Log Injection (MEDIUM)
**Endpoint:** `POST /log`  
**What it does:** Injects newlines and fake log entries to forge audit trails.  
**Your task:** Strip control characters and detect log-format spoofing.

**Example payloads you must block:**
- `hello\nCRITICAL: admin password changed`
- `test\x1b[31mRED ANSI injection`
- `msg\x00null byte truncation`

---

## How to Solve

### Step 1 — Read the code
Open `defender/defender.py` and read all 5 `DefenseRule` subclasses and their docstrings.

### Step 2 — Implement each rule
Fill in `should_block()` for each class. The docstrings give detailed hints.

### Step 3 — Run the validator
```bash
python defender/defender.py validate
```
You must pass ALL test cases with zero failures.

### Step 4 — Run live
Start all three terminals:
```bash
# Terminal 1
python server/server.py

# Terminal 2  
python attacker/attacker.py

# Terminal 3
python defender/defender.py
```

Watch the attacker's terminal — blocked attacks show `✓ BLOCKED`.

### Step 5 — Get the flag
When all vectors are blocked for 30+ seconds:
```bash
python defender/defender.py flag
```

Or via HTTP:
```bash
curl http://localhost:8888/flag
```

---

## Hints (use only if stuck)

<details>
<summary>SQL Injection hint</summary>

Use a compiled regex that checks for:
- Comment sequences: `--`, `#`, `/*`
- Boolean tautologies: patterns like `OR 1=1`, `OR 'x'='x`
- UNION keyword followed by SELECT
- Stacked queries: semicolons before SQL keywords
- URL-decode the payload first with `urllib.parse.unquote()`

</details>

<details>
<summary>XSS hint</summary>

Normalize first: `html.unescape(urllib.parse.unquote(payload)).lower()`

Then check for:
- Tag names: `script`, `iframe`, `object`, `embed`, `svg`, `img`, `a`
- Event attributes: anything matching `on\w+=`
- Protocol handlers: `javascript:`, `vbscript:`, `data:`

</details>

<details>
<summary>Path Traversal hint</summary>

```python
import os, urllib.parse
decoded = urllib.parse.unquote(urllib.parse.unquote(payload))  # double-decode
normalized = os.path.normpath(decoded)
base = os.path.abspath("server/public")
full = os.path.abspath(os.path.join(base, normalized))
return not full.startswith(base) or '\x00' in payload
```

</details>

<details>
<summary>Brute Force hint</summary>

Use `collections.deque` or a list to store `(timestamp, ip, username)` tuples.
On each call, filter out entries older than your window.
Count remaining entries matching the IP or username.

</details>

<details>
<summary>Log Injection hint</summary>

```python
import re
# Remove control chars (keep printable ASCII + common whitespace)
cleaned = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f\x1b]', '', payload)
# Remove ANSI escape codes
cleaned = re.sub(r'\x1b\[[0-9;]*m', '', cleaned)
# Strip newlines entirely
cleaned = cleaned.replace('\n', '').replace('\r', '')
```

Block if `len(payload) - len(cleaned) > 2` or if log-format keywords appear.

</details>

---

## Flag Format

```
CTF{...}
```

Good luck, Defender. 🛡️
