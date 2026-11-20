"""
security_lab.py - The Security Testing Lab: six local, simulated scenarios.

Every scenario runs through the REAL policy engine (PEP -> PDP), so the audit
logs, security events and dashboard statistics change exactly as they would
for genuine traffic. Nothing here touches the network; it only uses the local
test accounts and simulated devices created in database.py.

Each scenario returns a result dictionary with:
    expected / actual     what we predicted vs what the engine decided
    matched_expectation   True if they agree (False means policies or devices
                          were edited, so the demo data no longer behaves as designed)
    reason                the engine's own explanation
    explanation           the Zero Trust concept this scenario demonstrates
    checks                step-by-step PDP checks (shown as a timeline in the UI)
    evidence              extra facts, e.g. original vs forged token claims

Safety design:
  * Tokens created for a test are REVOKED when the test ends, so the lab never
    inflates the "active sessions" counter.
  * The invalid-login scenario uses MADE-UP usernames, so it can never lock a
    real demo account.
  * Lab entries are tagged with "[lab]" in the IP address column.
"""

import base64
import json
import time

import audit_logger
import auth
import policy_engine
import token_manager
from database import query_one


class LabSetupError(Exception):
    """Raised when demo data needed by a scenario is missing."""


# ---------------------------------------------------------------------------
# Scenario catalogue (shown on the Security Lab page)
# ---------------------------------------------------------------------------
SCENARIOS = [
    {
        "id": "normal_access",
        "title": "Normal authorized access",
        "description": "The administrator, on the most trusted device, opens the Admin Dashboard.",
        "expected": "GRANTED",
        "explanation": ("All six checks pass: valid token, active account, active policy, permitted "
                        "role and a device score at or above the policy minimum. Zero Trust still "
                        "evaluated every check; nothing was assumed from the login."),
    },
    {
        "id": "role_violation",
        "title": "Unauthorized role accessing an admin resource",
        "description": "A normal user on a trusted device tries to open the Admin Dashboard.",
        "expected": "DENIED",
        "explanation": ("The token and the device are fine, but role-based access control fails: the "
                        "policy allows only the admin role. Being logged in is not enough; "
                        "authorization is checked on every request."),
    },
    {
        "id": "untrusted_device",
        "title": "Untrusted device attempting access",
        "description": "The administrator tries the Admin Dashboard from the lowest-scoring device.",
        "expected": "DENIED",
        "explanation": ("Identity and role are correct, but the device fails the posture requirement. "
                        "Zero Trust verifies the device as well as the user."),
    },
    {
        "id": "expired_token",
        "title": "Expired token rejection",
        "description": "An access token whose expiry time is already in the past is presented.",
        "expected": "DENIED",
        "explanation": ("Tokens are time-limited so that a stolen or leftover token stops working "
                        "quickly. The signature is genuine, but the 'exp' claim is in the past."),
    },
    {
        "id": "tampered_token",
        "title": "Modified (tampered) token rejection",
        "description": "An attacker edits a normal user's token to claim the 'admin' role.",
        "expected": "DENIED",
        "explanation": ("The attacker changed the payload but cannot recompute the HMAC-SHA256 "
                        "signature without the server's secret key, so verification fails and "
                        "the forged role claim is never trusted."),
    },
    {
        "id": "invalid_logins",
        "title": "Invalid login attempts",
        "description": "Three login attempts with made-up usernames and wrong passwords.",
        "expected": "REJECTED",
        "explanation": ("Every attempt fails with the same generic message, so an attacker cannot "
                        "learn which usernames exist. Each attempt is recorded as a LOGIN_FAILED "
                        "event. Made-up usernames are used so real accounts are never locked."),
    },
]
SCENARIO_BY_ID = {scenario["id"]: scenario for scenario in SCENARIOS}


def list_scenarios():
    """Scenario metadata for the Security Lab page."""
    return SCENARIOS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _peek_payload(token):
    """Decode a token's payload WITHOUT verifying it (lab display only)."""
    try:
        payload_b64 = token.split(".")[0]
        padding = "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8"))
    except (ValueError, IndexError):
        return {}


def _get_test_context():
    """Load the accounts, devices and resource the scenarios need."""
    admin = query_one("SELECT * FROM users WHERE username = 'admin'")
    normal_user = query_one("SELECT * FROM users WHERE username = 'user'")
    trusted_device = query_one("SELECT * FROM devices ORDER BY posture_score DESC, id LIMIT 1")
    weak_device = query_one("SELECT * FROM devices ORDER BY posture_score ASC, id LIMIT 1")
    resource = query_one("SELECT * FROM resources WHERE name = 'Admin Dashboard'")

    if not (admin and normal_user and trusted_device and weak_device and resource):
        raise LabSetupError("Demo data is missing. Run: python database.py --reset")
    return {"admin": admin, "normal_user": normal_user, "trusted_device": trusted_device,
            "weak_device": weak_device, "resource": resource}


def _issue(user, device, issued_jtis, lifetime_minutes=None):
    """Create a token for a test user and remember its id so it can be revoked later."""
    token = token_manager.create_token(user["id"], user["username"], user["role"],
                                       device["id"], lifetime_minutes)
    issued_jtis.append(_peek_payload(token).get("jti"))
    return token


def _pdp_outcome(decision):
    """Turn a PDP decision into the (actual, reason, checks) trio the lab reports."""
    return ("GRANTED" if decision["granted"] else "DENIED", decision["reason"], decision["checks"])


# ---------------------------------------------------------------------------
# The six scenarios. Each returns (actual, reason, checks, evidence)
# ---------------------------------------------------------------------------
def _scenario_normal_access(ctx, issued, ip):
    token = _issue(ctx["admin"], ctx["trusted_device"], issued)
    decision = policy_engine.enforce_access(token, ctx["resource"]["path"], ip)
    evidence = [f"User: admin (role: admin)",
                f"Device: {ctx['trusted_device']['name']} (score {ctx['trusted_device']['posture_score']})",
                f"Resource: {ctx['resource']['name']}"]
    return (*_pdp_outcome(decision), evidence)


def _scenario_role_violation(ctx, issued, ip):
    token = _issue(ctx["normal_user"], ctx["trusted_device"], issued)
    decision = policy_engine.enforce_access(token, ctx["resource"]["path"], ip)
    evidence = [f"User: user (role: user)",
                f"Device: {ctx['trusted_device']['name']} (score {ctx['trusted_device']['posture_score']})",
                f"Resource: {ctx['resource']['name']}"]
    return (*_pdp_outcome(decision), evidence)


def _scenario_untrusted_device(ctx, issued, ip):
    token = _issue(ctx["admin"], ctx["weak_device"], issued)
    decision = policy_engine.enforce_access(token, ctx["resource"]["path"], ip)
    evidence = [f"User: admin (role: admin)",
                f"Device: {ctx['weak_device']['name']} (score {ctx['weak_device']['posture_score']}, "
                f"trust level {ctx['weak_device']['trust_level']})",
                f"Resource: {ctx['resource']['name']}"]
    return (*_pdp_outcome(decision), evidence)


def _scenario_expired_token(ctx, issued, ip):
    # A NEGATIVE lifetime creates a token that is already expired.
    token = _issue(ctx["admin"], ctx["trusted_device"], issued, lifetime_minutes=-1)
    seconds_ago = int(time.time()) - _peek_payload(token).get("exp", 0)
    decision = policy_engine.enforce_access(token, ctx["resource"]["path"], ip)
    evidence = ["Token was signed correctly by the server",
                f"Its 'exp' claim is {seconds_ago} seconds in the past"]
    return (*_pdp_outcome(decision), evidence)


def _scenario_tampered_token(ctx, issued, ip):
    genuine = _issue(ctx["normal_user"], ctx["trusted_device"], issued)
    forged = token_manager.tamper_token(genuine, "admin")
    decision = policy_engine.enforce_access(forged, ctx["resource"]["path"], ip)
    evidence = [f"Original role claim: {_peek_payload(genuine).get('role')}",
                f"Forged role claim: {_peek_payload(forged).get('role')}",
                "The old signature was kept; the attacker cannot recompute it without the secret key"]
    return (*_pdp_outcome(decision), evidence)


def _scenario_invalid_logins(ctx, issued, ip):
    attempts = [("lab_attacker_1", "Password123"),
                ("lab_attacker_2", "letmein"),
                ("lab_attacker_3", "admin")]
    checks, all_rejected = [], True
    for username, password in attempts:
        result = auth.authenticate(username, password, ctx["trusted_device"]["id"], f"{ip} [lab]")
        all_rejected = all_rejected and not result["success"]
        checks.append({"check": f"Login attempt as '{username}'",
                       "passed": result["success"], "detail": result["message"]})
    actual = "REJECTED" if all_rejected else "GRANTED"
    reason = ("All 3 attempts rejected with the same generic message: "
              "'Invalid username or password'")
    evidence = ["Usernames used do not exist, so no real account can be locked",
                "Each attempt was stored as a LOGIN_FAILED security event"]
    return actual, reason, checks, evidence


SCENARIO_FUNCTIONS = {
    "normal_access": _scenario_normal_access,
    "role_violation": _scenario_role_violation,
    "untrusted_device": _scenario_untrusted_device,
    "expired_token": _scenario_expired_token,
    "tampered_token": _scenario_tampered_token,
    "invalid_logins": _scenario_invalid_logins,
}


# ---------------------------------------------------------------------------
# Public runners
# ---------------------------------------------------------------------------
def run_scenario(scenario_id, actor_username, ip_address):
    """Run one scenario. Returns a result dict, or None for an unknown id."""
    meta = SCENARIO_BY_ID.get(scenario_id)
    if meta is None:
        return None

    try:
        ctx = _get_test_context()
    except LabSetupError as error:
        return {"id": meta["id"], "title": meta["title"], "error": str(error)}

    issued_jtis = []
    lab_ip = f"{ip_address} [lab]"
    try:
        actual, reason, checks, evidence = SCENARIO_FUNCTIONS[scenario_id](ctx, issued_jtis, lab_ip)
    finally:
        # Always clean up: revoke every token created for this test.
        for jti in issued_jtis:
            if jti:
                token_manager.revoke_token(jti)

    matched = (actual == meta["expected"])
    audit_logger.log_security_event(
        "LAB_SCENARIO", "info", actor_username,
        f"{meta['title']}: expected {meta['expected']}, got {actual}")

    return {
        "id": meta["id"], "title": meta["title"], "description": meta["description"],
        "expected": meta["expected"], "actual": actual, "matched_expectation": matched,
        "reason": reason, "explanation": meta["explanation"],
        "checks": checks, "evidence": evidence,
    }


def run_all(actor_username, ip_address):
    """Run every scenario in order."""
    return [run_scenario(scenario["id"], actor_username, ip_address) for scenario in SCENARIOS]


# ---------------------------------------------------------------------------
# Quick self-test: run `python security_lab.py`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from database import init_db
    init_db()
    for outcome in run_all("self-test", "127.0.0.1"):
        if "error" in outcome:
            print("ERROR:", outcome["error"])
            continue
        status = "PASS" if outcome["matched_expectation"] else "UNEXPECTED"
        print(f"[{status}] {outcome['title']}")
        print(f"         expected {outcome['expected']}, got {outcome['actual']}")
        print(f"         {outcome['reason']}")