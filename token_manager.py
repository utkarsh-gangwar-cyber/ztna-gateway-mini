"""
token_manager.py - Creates and verifies HMAC-SHA256 signed access tokens.

Token format (similar in spirit to a JWT, but simpler to explain):

    <payload_b64>.<signature_b64>

    payload   = JSON: {"sub", "uid", "role", "device_id", "jti", "iat", "exp"}
    signature = HMAC-SHA256(secret_key, payload_b64)

Why this is secure:
  * Only the server knows the secret key, so nobody can forge a valid signature.
  * Changing even one character of the payload invalidates the signature (integrity).
  * 'exp' makes the token expire (time-limited trust).
  * Each token is also stored in the 'tokens' table so it can be revoked on logout.

We use only standard primitives: hmac, hashlib, secrets, base64. No custom crypto.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone

import config
from database import execute, get_setting, query_all, query_one, utc_now


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _b64url_encode(raw_bytes):
    """Bytes -> URL-safe text without '=' padding."""
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")


def _b64url_decode(text):
    """URL-safe text -> bytes (restores the missing '=' padding first)."""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign(payload_b64):
    """Compute the HMAC-SHA256 signature of the encoded payload."""
    digest = hmac.new(
        config.TOKEN_SECRET_KEY.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)


def _epoch_to_text(epoch_seconds):
    """Convert epoch seconds to the same 'YYYY-MM-DD HH:MM:SS' format the DB uses."""
    return datetime.fromtimestamp(epoch_seconds, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------
def create_token(user_id, username, role, device_id, lifetime_minutes=None):
    """
    Issue a signed token and record it in the database.

    `lifetime_minutes` is normally read from Settings. The Security Lab passes a
    NEGATIVE number to deliberately create an already-expired token.
    """
    if lifetime_minutes is None:
        lifetime_minutes = int(get_setting("token_lifetime_minutes", config.TOKEN_LIFETIME_MINUTES))

    issued_at = int(time.time())
    expires_at = issued_at + int(lifetime_minutes * 60)
    jti = secrets.token_hex(16)  # random, unguessable token id

    payload = {
        "sub": username,
        "uid": user_id,
        "role": role,
        "device_id": device_id,
        "jti": jti,
        "iat": issued_at,
        "exp": expires_at,
    }
    # sort_keys + compact separators = identical JSON text every time
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload_b64 = _b64url_encode(payload_json.encode("utf-8"))
    token = payload_b64 + "." + _sign(payload_b64)

    # Server-side record: enables revocation and "active sessions" counting.
    execute(
        "INSERT INTO tokens (jti, user_id, device_id, issued_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (jti, user_id, device_id, _epoch_to_text(issued_at), _epoch_to_text(expires_at)),
    )
    return token


def verify_token(token):
    """
    Check a token and return a dictionary:
        {"valid": True/False, "reason": "<explanation>", "payload": dict or None}

    Order of checks (cheapest and most important first):
      1. Format  2. Signature  3. Payload readable  4. Expiry  5. Server record / revoked
    The signature is verified BEFORE the payload is trusted for anything.
    """
    # 1. Basic format check: "<payload>.<signature>"
    if not token or not isinstance(token, str):
        return {"valid": False, "reason": "No token presented", "payload": None}
    parts = token.split(".")
    if len(parts) != 2:
        return {"valid": False, "reason": "Malformed token", "payload": None}
    payload_b64, received_signature = parts

    # 2. Integrity: recompute the signature and compare in CONSTANT time.
    #    (hmac.compare_digest avoids timing attacks that normal '==' would allow.)
    try:
        expected_signature = _sign(payload_b64)
    except ValueError:  # e.g. non-ASCII characters in the payload part
        return {"valid": False, "reason": "Malformed token", "payload": None}
    if not hmac.compare_digest(expected_signature.encode("utf-8"),
                               received_signature.encode("utf-8")):
        return {"valid": False,
                "reason": "Token signature mismatch (token was modified)",
                "payload": None}

    # 3. Signature is good, so it is now safe to read the payload.
    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        expires_at = int(payload["exp"])
        jti = payload["jti"]
    except (ValueError, KeyError, TypeError):
        return {"valid": False, "reason": "Token payload unreadable", "payload": None}

    # 4. Expiry check.
    if int(time.time()) >= expires_at:
        return {"valid": False, "reason": "Token expired", "payload": payload}

    # 5. Server-side record: must exist and must not be revoked.
    record = query_one("SELECT revoked FROM tokens WHERE jti = ?", (jti,))
    if record is None:
        return {"valid": False, "reason": "Token not recognised by the server", "payload": payload}
    if record["revoked"]:
        return {"valid": False, "reason": "Token has been revoked (user logged out)", "payload": payload}

    return {"valid": True, "reason": "Token is valid", "payload": payload}


def tamper_token(token, new_role="admin"):
    """
    FOR THE SECURITY LAB ONLY: simulate an attacker editing the payload
    (e.g. changing their role to admin) while keeping the OLD signature.
    verify_token() must reject the result.
    """
    payload_b64, old_signature = token.split(".")
    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    payload["role"] = new_role
    new_payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    forged_payload_b64 = _b64url_encode(new_payload_json.encode("utf-8"))
    return forged_payload_b64 + "." + old_signature


def revoke_token(jti):
    """Mark one token as revoked (used by logout)."""
    execute("UPDATE tokens SET revoked = 1 WHERE jti = ?", (jti,))


def revoke_user_tokens(user_id):
    """Revoke every token of a user (used when an admin disables an account)."""
    execute("UPDATE tokens SET revoked = 1 WHERE user_id = ?", (user_id,))


def count_active_sessions():
    """Number of tokens that are neither revoked nor expired (for the dashboard)."""
    row = query_one(
        "SELECT COUNT(*) AS total FROM tokens WHERE revoked = 0 AND expires_at > ?",
        (utc_now(),),
    )
    return row["total"]


# ---------------------------------------------------------------------------
# Quick self-test: run `python token_manager.py`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from database import init_db
    init_db()

    good = create_token(1, "admin", "admin", 1)
    print("1. Valid token  ->", verify_token(good)["reason"])

    forged = tamper_token(good, "admin")
    print("2. Tampered     ->", verify_token(forged)["reason"])

    expired = create_token(1, "admin", "admin", 1, lifetime_minutes=-1)
    print("3. Expired      ->", verify_token(expired)["reason"])

    revoke_token(verify_token(good)["payload"]["jti"])
    print("4. Revoked      ->", verify_token(good)["reason"])