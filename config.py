"""
config.py - Central configuration for the Mini ZTNA Gateway.

Purpose: keeps every tunable value (secrets, token lifetime, lockout rules,
device posture weights) in ONE place so other modules never hard-code them.

NOTE: The default secret keys below are for LOCAL DEVELOPMENT ONLY.
In a real deployment they would come from environment variables or a vault.
"""

import os

# Folder that contains this file; used to build an absolute path to the database.
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# SQLite database file (created automatically on first run).
DATABASE_PATH = os.path.join(BASE_DIR, "ztna.db")

# Flask uses this key to sign the session cookie.
SECRET_KEY = os.environ.get("ZTNA_FLASK_SECRET", "dev-only-flask-secret-change-me")

# This key signs the ZTNA access tokens with HMAC-SHA256.
# It is deliberately DIFFERENT from the Flask key (separation of keys).
TOKEN_SECRET_KEY = os.environ.get("ZTNA_TOKEN_SECRET", "dev-only-token-signing-key-change-me")

# ---- Default values for the 'settings' table (editable later in System Settings) ----
TOKEN_LIFETIME_MINUTES = 30      # How long an access token stays valid
MAX_FAILED_LOGINS = 5            # Failed logins before the account is locked
LOCKOUT_MINUTES = 15             # How long the lock lasts
DEFAULT_MIN_POSTURE_SCORE = 50   # Fallback minimum device score

# ---- Device posture scoring ----
# Each security control a device has adds its weight. Total = 100.
POSTURE_WEIGHTS = {
    "os_patched": 30,      # Operating system fully updated
    "antivirus_on": 25,    # Antivirus / EDR running
    "disk_encrypted": 25,  # Full-disk encryption (e.g. BitLocker)
    "firewall_on": 20,     # Host firewall enabled
}

# Score thresholds that map a number to a trust label.
TRUSTED_THRESHOLD = 80    # score >= 80  -> "trusted"
AT_RISK_THRESHOLD = 50    # score >= 50  -> "at_risk", below -> "untrusted"