"""
auth.py - Identity verification: login, logout and user management.

This module answers "WHO are you?". It does NOT decide what you may access;
that is the job of policy_engine.py.

Security features:
  * Passwords are stored only as Werkzeug hashes (salted and slow to brute-force).
  * Failed attempts are counted; the account locks after N failures.
  * Login errors are generic ("Invalid username or password") so an attacker
    cannot learn which usernames exist. For unknown usernames we still run a
    dummy hash check so the response time looks the same.
  * On success a signed access token is issued (see token_manager.py).
"""

import re
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

import audit_logger
import config
import token_manager
from database import execute, get_setting, query_one, utc_now

VALID_ROLES = ("admin", "analyst", "user")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")

# Used to spend the same time on unknown usernames as on real ones.
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing-only")


def _login_failure(message):
    """Standard shape for a failed login result."""
    return {"success": False, "message": message, "token": None, "user": None}


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------
def authenticate(username, password, device_id, ip_address):
    """
    Verify credentials and, if correct, issue an access token.

    Returns {"success": bool, "message": str, "token": str|None, "user": dict|None}
    """
    username = (username or "").strip()
    password = password or ""
    shown_name = username[:50] or "(blank)"      # cap length before logging
    generic_message = "Invalid username or password"

    user = query_one("SELECT * FROM users WHERE username = ?", (username,))

    # 1. Unknown username -> generic failure (after a dummy hash check for timing).
    if user is None:
        check_password_hash(_DUMMY_HASH, password)
        audit_logger.log_security_event(
            "LOGIN_FAILED", "warning", shown_name,
            f"Login attempt for unknown username from {ip_address}")
        return _login_failure(generic_message)

    # 2. Locked account -> refuse without even checking the password.
    if user["locked_until"] and user["locked_until"] > utc_now():
        audit_logger.log_security_event(
            "LOGIN_BLOCKED_LOCKED", "warning", user["username"],
            f"Login attempt while account locked until {user['locked_until']} UTC ({ip_address})")
        return _login_failure("Account temporarily locked due to repeated failed logins. Try again later.")

    # 3. Wrong password -> count the failure, lock if the limit is reached.
    if not check_password_hash(user["password_hash"], password):
        max_failed = int(get_setting("max_failed_logins", config.MAX_FAILED_LOGINS))
        attempts = user["failed_attempts"] + 1

        if attempts >= max_failed:
            lock_minutes = int(get_setting("lockout_minutes", config.LOCKOUT_MINUTES))
            lock_until = (datetime.now(timezone.utc) + timedelta(minutes=lock_minutes)
                          ).strftime("%Y-%m-%d %H:%M:%S")
            execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                    (lock_until, user["id"]))
            audit_logger.log_security_event(
                "ACCOUNT_LOCKED", "critical", user["username"],
                f"{max_failed} failed logins from {ip_address}; locked for {lock_minutes} minutes")
        else:
            execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user["id"]))
            audit_logger.log_security_event(
                "LOGIN_FAILED", "warning", user["username"],
                f"Wrong password from {ip_address} (attempt {attempts} of {max_failed})")
        return _login_failure(generic_message)

    # 4. Password is correct, but the account may have been disabled by an admin.
    if not user["is_active"]:
        audit_logger.log_security_event(
            "LOGIN_BLOCKED_DISABLED", "warning", user["username"],
            f"Correct password but account is disabled ({ip_address})")
        return _login_failure("This account is disabled. Contact the administrator.")

    # 5. The chosen (simulated) device must be a registered device.
    device = query_one("SELECT id FROM devices WHERE id = ?", (device_id,))
    if device is None:
        return _login_failure("Selected device is not registered.")

    # 6. Success: reset counters, record login time, issue the token.
    execute("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
            (utc_now(), user["id"]))
    token = token_manager.create_token(user["id"], user["username"], user["role"], device["id"])
    audit_logger.log_security_event(
        "LOGIN_SUCCESS", "info", user["username"], f"Login from {ip_address}")

    safe_user = {key: user[key] for key in user.keys() if key != "password_hash"}
    return {"success": True, "message": "Login successful", "token": token, "user": safe_user}


def logout(token, ip_address="unknown"):
    """Revoke the token so it can never be used again, even before it expires."""
    result = token_manager.verify_token(token)
    payload = result["payload"]          # present for valid, expired or revoked tokens
    if payload and "jti" in payload:
        token_manager.revoke_token(payload["jti"])
        audit_logger.log_security_event(
            "LOGOUT", "info", payload.get("sub"), f"Token revoked at logout ({ip_address})")


# ---------------------------------------------------------------------------
# User management (used by the User Management page, admin only)
# ---------------------------------------------------------------------------
def _validate_new_password(password):
    """Return an error message, or None if the password is acceptable."""
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain at least one letter and one digit."
    return None


def create_user(username, password, full_name, role, created_by="system"):
    """Create a user. Returns (ok: bool, message: str)."""
    username = (username or "").strip()
    full_name = (full_name or "").strip()

    if not USERNAME_PATTERN.match(username):
        return False, "Username must be 3-30 characters: letters, digits, '_', '.', '-'."
    if not full_name:
        return False, "Full name is required."
    if role not in VALID_ROLES:
        return False, "Invalid role."
    password_error = _validate_new_password(password or "")
    if password_error:
        return False, password_error
    if query_one("SELECT id FROM users WHERE username = ?", (username,)):
        return False, "That username already exists."

    execute(
        "INSERT INTO users (username, password_hash, full_name, role, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, generate_password_hash(password), full_name, role, utc_now()),
    )
    audit_logger.log_security_event(
        "USER_CREATED", "info", created_by, f"Created user '{username}' with role '{role}'")
    return True, f"User '{username}' created."


def update_user_role(user_id, new_role, acting_user_id, acting_username):
    """Change a user's role. Admins cannot change their own role."""
    if new_role not in VALID_ROLES:
        return False, "Invalid role."
    if user_id == acting_user_id:
        return False, "You cannot change your own role."
    target = query_one("SELECT username, role FROM users WHERE id = ?", (user_id,))
    if target is None:
        return False, "User not found."

    execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    audit_logger.log_security_event(
        "ROLE_CHANGED", "warning", acting_username,
        f"Changed '{target['username']}' from '{target['role']}' to '{new_role}'")
    return True, f"'{target['username']}' is now '{new_role}'."


def set_user_active(user_id, active, acting_user_id, acting_username):
    """Enable or disable an account. Disabling also revokes all of the user's tokens."""
    if user_id == acting_user_id:
        return False, "You cannot disable your own account."
    target = query_one("SELECT username FROM users WHERE id = ?", (user_id,))
    if target is None:
        return False, "User not found."

    execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if active else 0, user_id))
    if not active:
        token_manager.revoke_user_tokens(user_id)    # kick them out immediately
    state = "enabled" if active else "disabled"
    audit_logger.log_security_event(
        "USER_ENABLED" if active else "USER_DISABLED", "warning", acting_username,
        f"Account '{target['username']}' {state}")
    return True, f"'{target['username']}' {state}."


def unlock_user(user_id, acting_username):
    """Clear a lockout so the user can try logging in again."""
    target = query_one("SELECT username FROM users WHERE id = ?", (user_id,))
    if target is None:
        return False, "User not found."
    execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
    audit_logger.log_security_event(
        "USER_UNLOCKED", "info", acting_username, f"Unlocked account '{target['username']}'")
    return True, f"'{target['username']}' unlocked."


# ---------------------------------------------------------------------------
# Quick self-test: run `python auth.py`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from database import init_db
    init_db()
    print("Wrong password :", authenticate("admin", "wrong", 1, "127.0.0.1")["message"])
    print("Unknown user   :", authenticate("ghost", "x", 1, "127.0.0.1")["message"])
    good = authenticate("admin", "Admin@12345", 1, "127.0.0.1")
    print("Correct login  :", good["message"], "| role =", good["user"]["role"])