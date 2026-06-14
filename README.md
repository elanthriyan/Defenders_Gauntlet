# 🛡️ Operation: Firewall Breach — CTF Challenge

## Quick Start

```bash
# 1. Setup (run once)
python setup.py

# 2. Three terminals:
python server/server.py        # Terminal 1
python attacker/attacker.py    # Terminal 2
python defender/defender.py    # Terminal 3 (edit this!)

# 3. Test your defenses
python defender/defender.py validate

# 4. Get the flag
python defender/defender.py flag
```

## File Structure

```
ctf-challenge/
├── setup.py                        ← Run first
├── server/
│   └── server.py                   ← Vulnerable server (DO NOT EDIT)
├── attacker/
│   └── attacker.py                 ← Auto-attack engine (DO NOT EDIT)
├── defender/
│   ├── defender.py                 ← YOUR CHALLENGE — implement 5 rules
│   └── defense_state.json          ← Auto-generated state file
├── flag_system/
│   ├── flag_manager.py             ← Encryption engine (DO NOT EDIT)
│   ├── flag.enc                    ← AES-256 encrypted flag
│   └── flag.meta                   ← Flag metadata
└── docs/
    └── CHALLENGE.md                ← Full challenge guide + hints
```

## The Challenge

The attacker fires **5 attack vectors automatically**:
- SQL Injection → `/login`
- XSS → `/search`
- Path Traversal → `/file`
- Brute Force → `/login`
- Log Injection → `/log`

You implement `DefenseRule` subclasses in `defender/defender.py`.  
Block all 5 → flag decrypts → you win.

**Read `docs/CHALLENGE.md` for full details and hints.**
