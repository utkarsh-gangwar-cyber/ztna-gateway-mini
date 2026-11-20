"""
policy_engine.py - The Zero Trust brain: PDP and PEP.

  PDP (Policy Decision Point)   -> evaluate_access()
      Pure decision logic. Takes a token + resource, runs the checks, and returns
      a decision with a human-readable reason. It never touches HTTP.

  PEP (Policy Enforcement Point) -> enforce_access()
      Calls the PDP, writes the audit log and security event, and returns the
      decision. The Flask decorator in app.py is a thin wrapper around this
      function that then allows the page or shows a 403 page.

Checks, in order. The first failure stops evaluation (fail-fast, default deny):
  1. Authentication      - was a token presented?
  2. Token integrity     - valid HMAC signature, not expired, not revoked?
  3. Account status      - does the user still exist and is the account active?
  4. Resource policy     - is there an ACTIVE policy for this resource?
  5. Role authorization  - is the user's CURRENT role listed in the policy?
  6. Device posture      - is the device's CURRENT score >= the policy minimum?

Important Zero Trust detail: role and device score are read from the DATABASE on
every request, not from the token. So changing a role or a device's posture takes
effect immediately, and a forged "role" claim inside a token is never trusted.
"""

import re

import audit_logger
import token_manager
from auth import VALID_ROLES
from database import (calculate_posture_score, execute, query_all, query_one,
                      trust_level_for_score, utc_now)


# ---------------------------------------------------------------------------
# PDP: the decision
# ---------------------------------------------------------------------------
def evaluate_access(token, resource_identifier):
    """
    Decide whether `token` may access the resource (matched by path or name).

    Returns a dictionary:
        granted      True / False
        reason       explanation shown to the user and stored in the log
        failed_code  None if granted, otherwise e.g. 'ROLE_DENIED'
        checks       list of {"check", "passed", "detail"} - used by the Security Lab
        username, user_id, role, resource (dict|None), device (dict|None)
    """
    decision = {
        "granted": False, "reason": "", "failed_code": None, "checks": [],
        "username": "anonymous", "user_id": None, "role": None,
        "resource": None, "device": None, "token_reason": None,
    }

    def passed(name, detail):
        decision["checks"].append({"check": name, "passed": True, "detail": detail})

    def deny(name, code, reason):
        """Record the failed check and finish with a DENY decision."""
        decision["checks"].append({"check": name, "passed": False, "detail": reason})
        decision["failed_code"] = code
        decision["reason"] = reason
        return decision

    # Look the resource up first (needed for logging even if later checks fail).
    resource = query_one("SELECT * FROM resources WHERE path = ? OR name = ?",
                         (resource_identifier, resource_identifier))
    decision["resource"] = dict(resource) if resource else None

    # --- Check 1: authentication ---
    if not token:
        return deny("Authentication", "NO_TOKEN",
                    "Authentication required: no access token presented")
    passed("Authentication", "Access token presented")

    # --- Check 2: token integrity, expiry, revocation ---
    verification = token_manager.verify_token(token)
    decision["token_reason"] = verification["reason"]
    if not verification["valid"]:
        payload = verification["payload"]
        # A payload exists only when the signature was good (e.g. expired token),
        # so its username can be trusted. For a bad signature we trust nothing.
        decision["username"] = payload.get("sub", "unknown") if payload else "unknown"
        return deny("Token integrity", "TOKEN_INVALID",
                    f"Token rejected: {verification['reason']}")
    payload = verification["payload"]
    passed("Token integrity", "Signature valid, token not expired or revoked")

    # --- Check 3: is the account still active? (read from DB, not the token) ---
    user = query_one("SELECT * FROM users WHERE id = ?", (payload["uid"],))
    if user is None or not user["is_active"]:
        decision["username"] = payload.get("sub", "unknown")
        return deny("Account status", "USER_INACTIVE",
                    "Account does not exist or has been disabled")
    decision.update(username=user["username"], user_id=user["id"], role=user["role"])
    passed("Account status", f"Account '{user['username']}' is active")

    # --- Check 4: an active policy must exist (default deny) ---
    if resource is None:
        return deny("Resource policy", "RESOURCE_UNKNOWN",
                    f"Unknown resource '{str(resource_identifier)[:60]}': default deny")
    policy = query_one("SELECT * FROM access_policies WHERE resource_id = ?", (resource["id"],))
    if policy is None or not policy["is_active"]:
        return deny("Resource policy", "NO_POLICY",
                    "No active access policy for this resource: default deny")
    passed("Resource policy", f"Active policy found for '{resource['name']}'")

    # --- Check 5: role authorization (uses the CURRENT role from the database) ---
    allowed_roles = [r.strip() for r in policy["allowed_roles"].split(",") if r.strip()]
    if user["role"] not in allowed_roles:
        return deny("Role authorization", "ROLE_DENIED",
                    f"Role '{user['role']}' is not permitted "
                    f"(allowed roles: {', '.join(allowed_roles)})")
    detail = f"Role '{user['role']}' is allowed"
    if payload.get("role") != user["role"]:
        detail += f" (token claimed '{payload.get('role')}'; current database role used)"
    passed("Role authorization", detail)

    # --- Check 6: device posture (uses the CURRENT score from the database) ---
    device = query_one("SELECT * FROM devices WHERE id = ?", (payload.get("device_id"),))
    if device is None:
        return deny("Device posture", "DEVICE_UNKNOWN",
                    "Device is not registered: untrusted by default")
    decision["device"] = dict(device)
    if device["posture_score"] < policy["min_posture_score"]:
        return deny("Device posture", "DEVICE_DENIED",
                    f"Device posture too low: score {device['posture_score']} < required "
                    f"{policy['min_posture_score']} (device '{device['name']}', "
                    f"trust level {device['trust_level']})")
    passed("Device posture",
           f"Device score {device['posture_score']} >= required {policy['min_posture_score']}")

    # --- All checks passed ---
    decision["granted"] = True
    decision["reason"] = (f"Access granted: all checks passed "
                          f"(role '{user['role']}', device score {device['posture_score']})")
    return decision


# ---------------------------------------------------------------------------
# PEP: enforce the decision and record it
# ---------------------------------------------------------------------------
def _event_for_denial(decision):
    """Map a denial to (event_type, severity) for the security events table."""
    code = decision["failed_code"]
    if code == "TOKEN_INVALID":
        # Match on the wording produced by token_manager.verify_token().
        text = (decision["token_reason"] or "").lower()
        if "modified" in text or "signature" in text:
            return "TOKEN_TAMPERED", "critical"
        if "expired" in text:
            return "TOKEN_EXPIRED", "warning"
        if "revoked" in text:
            return "REVOKED_TOKEN_USED", "warning"
        return "TOKEN_INVALID", "warning"
    return {
        "NO_TOKEN": ("UNAUTHENTICATED_ACCESS", "warning"),
        "USER_INACTIVE": ("DISABLED_ACCOUNT_ACCESS", "warning"),
        "RESOURCE_UNKNOWN": ("UNKNOWN_RESOURCE", "warning"),
        "NO_POLICY": ("NO_POLICY_DENY", "warning"),
        "ROLE_DENIED": ("ROLE_VIOLATION", "warning"),
        "DEVICE_UNKNOWN": ("DEVICE_REJECTED", "warning"),
        "DEVICE_DENIED": ("DEVICE_REJECTED", "warning"),
    }.get(code, ("ACCESS_DENIED", "warning"))


def enforce_access(token, resource_identifier, ip_address):
    """
    PEP core: ask the PDP, log the outcome, return the decision.
    The Flask route then either serves the resource or shows the denial page.
    """
    decision = evaluate_access(token, resource_identifier)
    resource = decision["resource"]
    resource_name = resource["name"] if resource else str(resource_identifier)[:100]

    audit_logger.log_access(
        decision["user_id"], decision["username"], decision["role"],
        resource["id"] if resource else None, resource_name,
        "GRANTED" if decision["granted"] else "DENIED",
        decision["reason"], ip_address)

    if not decision["granted"]:
        event_type, severity = _event_for_denial(decision)
        audit_logger.log_security_event(
            event_type, severity, decision["username"],
            f"{resource_name}: {decision['reason']} (from {ip_address})")
    return decision


# ---------------------------------------------------------------------------
# Device posture management (Device Posture page)
# ---------------------------------------------------------------------------
def create_device(name, os_name, os_patched, antivirus_on, disk_encrypted, firewall_on,
                  acting_username="system"):
    """Register a simulated device. Returns (ok, message, device_id)."""
    name, os_name = (name or "").strip(), (os_name or "").strip()
    if not name or not os_name:
        return False, "Device name and OS are required.", None
    score = calculate_posture_score(os_patched, antivirus_on, disk_encrypted, firewall_on)
    device_id = execute(
        "INSERT INTO devices (name, os_name, os_patched, antivirus_on, disk_encrypted, "
        "firewall_on, posture_score, trust_level, last_checked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (name, os_name, int(os_patched), int(antivirus_on), int(disk_encrypted),
         int(firewall_on), score, trust_level_for_score(score), utc_now()))
    audit_logger.log_security_event(
        "DEVICE_REGISTERED", "info", acting_username, f"Device '{name}' registered, score {score}")
    return True, f"Device '{name}' registered with score {score}.", device_id


def update_device_posture(device_id, os_patched, antivirus_on, disk_encrypted, firewall_on,
                          acting_username="system"):
    """Change a device's security flags; the score and trust level are recalculated."""
    device = query_one("SELECT name FROM devices WHERE id = ?", (device_id,))
    if device is None:
        return False, "Device not found."
    score = calculate_posture_score(os_patched, antivirus_on, disk_encrypted, firewall_on)
    level = trust_level_for_score(score)
    execute(
        "UPDATE devices SET os_patched = ?, antivirus_on = ?, disk_encrypted = ?, "
        "firewall_on = ?, posture_score = ?, trust_level = ?, last_checked = ? WHERE id = ?",
        (int(os_patched), int(antivirus_on), int(disk_encrypted), int(firewall_on),
         score, level, utc_now(), device_id))
    audit_logger.log_security_event(
        "DEVICE_POSTURE_UPDATED", "info", acting_username,
        f"Device '{device['name']}' now score {score} ({level})")
    return True, f"'{device['name']}' updated: score {score} ({level})."


# ---------------------------------------------------------------------------
# Policy management (Security Policies page)
# ---------------------------------------------------------------------------
def create_resource(name, description, sensitivity, acting_username="system"):
    """Create a protected resource. The path is generated from the name."""
    name = (name or "").strip()
    if not name:
        return False, "Resource name is required.", None
    if sensitivity not in ("low", "medium", "high"):
        return False, "Sensitivity must be low, medium or high.", None
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not slug:
        return False, "Resource name must contain letters or digits.", None
    path = f"/resources/{slug}"
    if query_one("SELECT id FROM resources WHERE name = ? OR path = ?", (name, path)):
        return False, "A resource with that name already exists.", None

    resource_id = execute(
        "INSERT INTO resources (name, path, description, sensitivity) VALUES (?, ?, ?, ?)",
        (name, path, (description or "").strip(), sensitivity))
    audit_logger.log_security_event(
        "RESOURCE_CREATED", "info", acting_username, f"Resource '{name}' created")
    return True, f"Resource '{name}' created.", resource_id


def save_policy(resource_id, allowed_roles, min_posture_score, is_active,
                acting_username="system"):
    """Create or update the single policy of a resource. Returns (ok, message)."""
    resource = query_one("SELECT name FROM resources WHERE id = ?", (resource_id,))
    if resource is None:
        return False, "Resource not found."
    roles = [r for r in allowed_roles if r in VALID_ROLES]
    if not roles:
        return False, "Select at least one valid role."
    try:
        min_score = int(min_posture_score)
    except (TypeError, ValueError):
        return False, "Minimum posture score must be a number."
    if not 0 <= min_score <= 100:
        return False, "Minimum posture score must be between 0 and 100."

    execute(
        "INSERT INTO access_policies (resource_id, allowed_roles, min_posture_score, is_active, updated_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(resource_id) DO UPDATE SET allowed_roles = excluded.allowed_roles, "
        "min_posture_score = excluded.min_posture_score, is_active = excluded.is_active, "
        "updated_at = excluded.updated_at",
        (resource_id, ",".join(roles), min_score, 1 if is_active else 0, utc_now()))
    audit_logger.log_security_event(
        "POLICY_UPDATED", "warning", acting_username,
        f"Policy for '{resource['name']}': roles={','.join(roles)}, "
        f"min score={min_score}, active={bool(is_active)}")
    return True, f"Policy for '{resource['name']}' saved."


def list_policies():
    """All resources joined with their policy (None fields if no policy yet)."""
    return query_all(
        "SELECT r.id AS resource_id, r.name, r.path, r.sensitivity, r.description, "
        "p.id AS policy_id, p.allowed_roles, p.min_posture_score, p.is_active, p.updated_at "
        "FROM resources r LEFT JOIN access_policies p ON p.resource_id = r.id "
        "ORDER BY r.id")


# ---------------------------------------------------------------------------
# Quick self-test: run `python policy_engine.py`
# (needs a fresh database: python database.py --reset)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from database import init_db
    init_db()

    # Seeded ids: users admin=1, analyst=2, user=3; devices laptop=1, tablet=2, unknown=3
    admin_token = token_manager.create_token(1, "admin", "admin", 1)
    user_token = token_manager.create_token(3, "user", "user", 1)
    weak_device_token = token_manager.create_token(1, "admin", "admin", 3)

    scenarios = [
        ("Admin on trusted laptop -> Admin Dashboard", admin_token, "Admin Dashboard"),
        ("Normal user -> Admin Dashboard",             user_token, "Admin Dashboard"),
        ("Normal user -> General Documents",           user_token, "General Documents"),
        ("Admin on unknown device -> Admin Dashboard", weak_device_token, "Admin Dashboard"),
        ("Tampered token (user claims admin)",         token_manager.tamper_token(user_token), "Admin Dashboard"),
        ("No token",                                   None, "Admin Dashboard"),
    ]
    for label, token, resource in scenarios:
        result = enforce_access(token, resource, "127.0.0.1")
        verdict = "GRANTED" if result["granted"] else "DENIED "
        print(f"{verdict} | {label}\n          {result['reason']}")