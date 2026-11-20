"""
test_ztna.py - Automated tests for the Mini ZTNA Gateway (35 test cases).

Run from the project folder:   python -m pytest -v

Mapping to the project's required test list:
    Valid login ................. test_valid_login
    Invalid login ............... test_invalid_login_*  (+ lockout test)
    Unauthorized resource access  test_unauthorized_role_denied_admin_resource
    Valid token ................. test_valid_token
    Expired token ............... test_expired_token_rejected
    Modified token .............. test_modified_token_rejected
    Device posture rejection .... test_device_posture_rejection (+ change test)
    Role-based enforcement ...... test_role_matrix (9 cases)
"""

import pytest

import audit_logger
import auth
import database
import policy_engine
import security_lab
import token_manager

# Demo credentials (development-only passwords from database.py)
ADMIN = ("admin", "Admin@12345")
ANALYST = ("analyst", "Analyst@12345")
USER = ("user", "User@12345")

# Seeded device ids
LAPTOP, TABLET, UNKNOWN = 1, 2, 3
IP = "127.0.0.1"


def login_token(credentials, device_id=LAPTOP):
    """Log in through auth.py and return the access token (fails the test if login fails)."""
    result = auth.authenticate(credentials[0], credentials[1], device_id, IP)
    assert result["success"], result["message"]
    return result["token"]


# ===========================================================================
# 1. Authentication
# ===========================================================================
def test_valid_login():
    result = auth.authenticate(*ADMIN, LAPTOP, IP)
    assert result["success"] is True
    assert result["user"]["role"] == "admin"
    assert "password_hash" not in result["user"]            # hash never leaves auth.py
    assert token_manager.verify_token(result["token"])["valid"]


def test_invalid_login_wrong_password():
    result = auth.authenticate("admin", "WrongPassword1", LAPTOP, IP)
    assert result["success"] is False
    assert result["token"] is None
    assert result["message"] == "Invalid username or password"


def test_invalid_login_unknown_user_gives_same_message():
    """An attacker must not be able to tell 'no such user' from 'wrong password'."""
    unknown = auth.authenticate("ghost_user", "whatever", LAPTOP, IP)
    wrong_pw = auth.authenticate("admin", "whatever", LAPTOP, IP)
    assert unknown["message"] == wrong_pw["message"] == "Invalid username or password"


def test_account_locks_after_repeated_failures():
    for _ in range(5):
        auth.authenticate("user", "wrong-password", LAPTOP, IP)
    result = auth.authenticate(*USER, LAPTOP, IP)             # correct password, but locked
    assert result["success"] is False
    assert "locked" in result["message"].lower()


def test_password_is_stored_hashed():
    row = database.query_one("SELECT password_hash FROM users WHERE username = 'admin'")
    assert ADMIN[1] not in row["password_hash"]
    assert row["password_hash"].startswith(("scrypt:", "pbkdf2:"))


# ===========================================================================
# 2. Tokens (HMAC-SHA256)
# ===========================================================================
def test_valid_token():
    token = login_token(ADMIN)
    result = token_manager.verify_token(token)
    assert result["valid"] is True
    assert result["payload"]["sub"] == "admin"
    assert result["payload"]["role"] == "admin"


def test_expired_token_rejected():
    token = token_manager.create_token(1, "admin", "admin", LAPTOP, lifetime_minutes=-1)
    result = token_manager.verify_token(token)
    assert result["valid"] is False
    assert result["reason"] == "Token expired"


def test_modified_token_rejected():
    """Editing the payload (role -> admin) while keeping the old signature must fail."""
    genuine = login_token(USER)
    forged = token_manager.tamper_token(genuine, "admin")
    assert forged != genuine
    result = token_manager.verify_token(forged)
    assert result["valid"] is False
    assert "signature" in result["reason"].lower()


def test_revoked_token_rejected():
    token = login_token(ADMIN)
    jti = token_manager.verify_token(token)["payload"]["jti"]
    token_manager.revoke_token(jti)
    result = token_manager.verify_token(token)
    assert result["valid"] is False
    assert "revoked" in result["reason"].lower()


@pytest.mark.parametrize("garbage", [None, "", "abc", "a.b.c", "....", 12345])
def test_malformed_tokens_rejected(garbage):
    assert token_manager.verify_token(garbage)["valid"] is False


# ===========================================================================
# 3. Policy engine (PDP) and enforcement (PEP)
# ===========================================================================
def test_unauthorized_role_denied_admin_resource():
    token = login_token(USER)
    decision = policy_engine.enforce_access(token, "Admin Dashboard", IP)
    assert decision["granted"] is False
    assert decision["failed_code"] == "ROLE_DENIED"
    assert "not permitted" in decision["reason"]


@pytest.mark.parametrize("credentials, resource, expected", [
    (ADMIN,   "Admin Dashboard",   True),
    (ADMIN,   "Security Reports",  True),
    (ADMIN,   "General Documents", True),
    (ANALYST, "Admin Dashboard",   False),
    (ANALYST, "Security Reports",  True),
    (ANALYST, "General Documents", True),
    (USER,    "Admin Dashboard",   False),
    (USER,    "Security Reports",  False),
    (USER,    "General Documents", True),
])
def test_role_matrix(credentials, resource, expected):
    """Role-based policy enforcement for every role/resource pair (trusted device)."""
    token = login_token(credentials)
    decision = policy_engine.enforce_access(token, resource, IP)
    assert decision["granted"] is expected


def test_device_posture_rejection():
    # Correct admin, but on the lowest-scoring device (score 20 < 80)
    unknown_token = login_token(ADMIN, UNKNOWN)
    decision = policy_engine.enforce_access(unknown_token, "Admin Dashboard", IP)
    assert decision["granted"] is False
    assert decision["failed_code"] == "DEVICE_DENIED"
    assert "20" in decision["reason"]

    # The mid-level tablet (score 55) passes General Documents (min 50) but not Security Reports (min 70)
    tablet_token = login_token(ADMIN, TABLET)
    assert policy_engine.enforce_access(tablet_token, "General Documents", IP)["granted"] is True
    blocked = policy_engine.enforce_access(tablet_token, "Security Reports", IP)
    assert blocked["granted"] is False and blocked["failed_code"] == "DEVICE_DENIED"


def test_device_posture_change_applies_immediately():
    """Zero Trust: the SAME token is judged against the device's CURRENT score."""
    token = login_token(ADMIN, LAPTOP)
    assert policy_engine.enforce_access(token, "Admin Dashboard", IP)["granted"] is True

    # Switch off OS patching: score 100 -> 70, below the 80 required for Admin Dashboard
    policy_engine.update_device_posture(LAPTOP, False, True, True, True)
    assert policy_engine.enforce_access(token, "Admin Dashboard", IP)["failed_code"] == "DEVICE_DENIED"

    policy_engine.update_device_posture(LAPTOP, True, True, True, True)     # restore
    assert policy_engine.enforce_access(token, "Admin Dashboard", IP)["granted"] is True


def test_default_deny_without_active_policy():
    ok, _, resource_id = policy_engine.create_resource("Test Vault", "demo", "low")
    assert ok
    token = login_token(ADMIN)

    # A brand-new resource has no policy: denied even for the admin
    decision = policy_engine.enforce_access(token, "/resources/test-vault", IP)
    assert decision["granted"] is False and decision["failed_code"] == "NO_POLICY"

    # With an active policy it becomes accessible
    policy_engine.save_policy(resource_id, ["admin"], 50, True)
    assert policy_engine.enforce_access(token, "/resources/test-vault", IP)["granted"] is True

    # An inactive policy denies again
    policy_engine.save_policy(resource_id, ["admin"], 50, False)
    assert policy_engine.enforce_access(token, "/resources/test-vault", IP)["failed_code"] == "NO_POLICY"


def test_role_change_applies_immediately():
    """The role comes from the database on every request, not from the token."""
    token = login_token(USER)
    assert policy_engine.enforce_access(token, "Admin Dashboard", IP)["granted"] is False

    ok, _ = auth.update_user_role(3, "admin", 1, "admin")        # admin promotes 'user'
    assert ok
    decision = policy_engine.enforce_access(token, "Admin Dashboard", IP)
    assert decision["granted"] is True and decision["role"] == "admin"


def test_every_decision_is_audit_logged():
    token = login_token(USER)
    policy_engine.enforce_access(token, "General Documents", "10.0.0.5")   # granted
    policy_engine.enforce_access(token, "Admin Dashboard", "10.0.0.5")     # denied

    counts = audit_logger.get_access_counts()
    assert counts == {"total": 2, "granted": 1, "denied": 1}

    denied_rows = audit_logger.search_access_logs(decision="DENIED")
    assert len(denied_rows) == 1
    assert denied_rows[0]["username"] == "user"
    assert denied_rows[0]["ip_address"] == "10.0.0.5"
    assert denied_rows[0]["resource_name"] == "Admin Dashboard"
    assert denied_rows[0]["reason"]                                       # reason is never empty


def test_tampered_token_is_logged_as_critical_event():
    forged = token_manager.tamper_token(login_token(USER), "admin")
    decision = policy_engine.enforce_access(forged, "Admin Dashboard", IP)
    assert decision["granted"] is False

    event = database.query_one("SELECT * FROM security_events WHERE event_type = 'TOKEN_TAMPERED'")
    assert event is not None and event["severity"] == "critical"


# ===========================================================================
# 4. Security Testing Lab
# ===========================================================================
def test_all_lab_scenarios_behave_as_expected():
    results = security_lab.run_all("tester", IP)
    assert len(results) == 6
    for result in results:
        assert "error" not in result, result
        assert result["matched_expectation"], f"{result['title']}: got {result['actual']}"


def test_lab_leaves_no_active_sessions():
    """Lab tokens are revoked after each run so the dashboard counter is not inflated."""
    security_lab.run_all("tester", IP)
    assert token_manager.count_active_sessions() == 0


# ===========================================================================
# 5. Web application (Flask test client = fake browser)
# ===========================================================================
def start_csrf(client):
    """Give the fake browser a CSRF token, as a real login page would."""
    with client.session_transaction() as sess:
        sess["_csrf"] = "test-csrf-token"
    return "test-csrf-token"


def current_csrf(client):
    with client.session_transaction() as sess:
        return sess.get("_csrf")


def web_login(client, credentials, device_id=LAPTOP):
    return client.post("/login", data={
        "username": credentials[0], "password": credentials[1],
        "device_id": device_id, "csrf_token": start_csrf(client)})


def test_login_page_loads(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Sign in" in response.data


def test_admin_login_then_dashboard(client):
    assert web_login(client, ADMIN).status_code == 302          # redirect after success
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert b"Security Dashboard" in response.data


def test_post_without_csrf_token_is_rejected(client):
    response = client.post("/login", data={
        "username": "admin", "password": "Admin@12345", "device_id": LAPTOP})
    assert response.status_code == 302                          # bounced back to the login page
    with client.session_transaction() as sess:
        assert "token" not in sess                              # and no session was created


def test_normal_user_cannot_open_dashboard(client):
    web_login(client, USER)
    assert client.get("/dashboard").status_code == 403


def test_resource_route_enforces_policy(client):
    web_login(client, USER)
    assert client.get("/resources/admin-dashboard").status_code == 403
    assert client.get("/resources/general-documents").status_code == 200
    assert len(audit_logger.search_access_logs(decision="DENIED")) >= 1


def test_logout_revokes_token(client):
    web_login(client, ADMIN)
    client.get("/dashboard")                                    # page render creates a fresh CSRF token
    with client.session_transaction() as sess:
        token = sess["token"]
    assert token_manager.verify_token(token)["valid"]

    response = client.post("/logout", data={"csrf_token": current_csrf(client)})
    assert response.status_code == 302
    assert token_manager.verify_token(token)["valid"] is False  # revoked on the server
    assert client.get("/dashboard").status_code == 302          # and the session is gone


def test_api_requires_login(client):
    response = client.get("/api/dashboard-stats")
    assert response.status_code == 401
    assert response.get_json()["ok"] is False