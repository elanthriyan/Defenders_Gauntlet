#!/usr/bin/env python3
"""
CTF Challenge: Operation Firewall Breach
Flag Manager — AES-256 encrypted flag.
The flag is ONLY decryptable when the correct defense hash is present.
Participants cannot read the flag without properly implementing all defenses.
"""

import os
import json
import hashlib
import base64
import time

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

DEFENSE_STATE_FILE = "defender/defense_state.json"
FLAG_ENC_FILE      = "flag_system/flag.enc"
FLAG_META_FILE     = "flag_system/flag.meta"

# ─── Key Derivation ───────────────────────────────────────────────────────────

EXPECTED_DEFENSE_VECTORS = sorted([
    "sqli",
    "xss",
    "path_traversal",
    "brute_force",
    "log_injection",
])

# Pepper — baked into the binary so it can't be extracted from flag.meta alone
_PEPPER = "0p3r4t10n_F1r3w4ll_Br34ch_CTF_2025"

def _derive_key(defense_vectors_blocked: list) -> bytes:
    canonical = "|".join(sorted(defense_vectors_blocked))
    material  = f"{canonical}:{_PEPPER}"
    return hashlib.pbkdf2_hmac(
        "sha256",
        material.encode(),
        b"firewall_breach_salt_v1",
        iterations=200_000,
        dklen=32,
    )

def _derive_iv(key: bytes) -> bytes:
    return hashlib.sha256(key + b"_iv").digest()[:16]

# ─── Decryption (called at runtime when all attacks blocked) ──────────────────

def get_flag() -> str:
    """
    Attempt to decrypt the flag.
    Only succeeds if defender/defense_state.json has all 5 vectors marked blocked.
    """
    if not HAS_CRYPTO:
        return "ERROR: pycryptodome not installed. Run: pip install pycryptodome"

    if not os.path.exists(FLAG_ENC_FILE):
        return "ERROR: Flag file not found. Run setup.py first."

    if not os.path.exists(DEFENSE_STATE_FILE):
        return "ERROR: No defense state found. Run your defender first."

    with open(DEFENSE_STATE_FILE) as f:
        state = json.load(f)

    rules = state.get("rules", {})
    blocked_vectors = [v for v, blocked in rules.items() if blocked]

    if sorted(blocked_vectors) != EXPECTED_DEFENSE_VECTORS:
        missing = set(EXPECTED_DEFENSE_VECTORS) - set(blocked_vectors)
        return f"LOCKED: Unblocked vectors: {list(missing)}"

    activated_at = state.get("activated_at", 0)
    if time.time() - activated_at < 30:
        return "LOCKED: Defenses must be active for at least 30 seconds before flag releases."

    key = _derive_key(blocked_vectors)
    iv  = _derive_iv(key)

    with open(FLAG_ENC_FILE) as f:
        ct = base64.b64decode(f.read().strip())

    try:
        cipher   = AES.new(key, AES.MODE_CBC, iv)
        flag_raw = unpad(cipher.decrypt(ct), AES.block_size).decode()
    except Exception:
        return "DECRYPTION FAILED: Defense state was incorrect or tampered."

    import hmac as hmaclib
    with open(FLAG_META_FILE) as f:
        meta = json.load(f)

    expected_mac = hmaclib.new(key, flag_raw.encode(), hashlib.sha256).hexdigest()
    if not hmaclib.compare_digest(expected_mac, meta["mac"]):
        return "INTEGRITY CHECK FAILED: Flag may have been tampered with."

    return flag_raw