"""
app.py - The Flask application: routes, page guard, and JSON endpoints.

How it connects to the rest of the project:
  * auth.py            -> login/logout and user management
  * token_manager.py   -> token verification (used by the page guard)
  * policy_engine.py   -> PEP/PDP for protected RESOURCES, plus policy and device admin
  * audit_logger.py    -> access logs, security events, dashboard statistics
  * security_lab.py    -> the six simulated test scenarios

Two kinds of protection are used here:
  1. @login_required(...)  - the page guard for the management console. It verifies
     the signed token on EVERY request, reloads the user from the database, and
     checks the user's role.
  2. policy_engine.enforce_access() - the full PEP/PDP check (6 checks plus audit
     logging) for the protected resources under /resources/<name>.

Extra security measures in this file:
  * CSRF token on every POST (form field or X-CSRF-Token header)
  * Logout is a POST request (a plain link could be triggered by another site)
  * Session cookie: HttpOnly + SameSite=Lax; session is cleared at login (anti-fixation)
  * Security headers and "no-store" caching so logged-out pages are not shown via Back
  * Generic error pages that never reveal stack traces
  * CSV export neutralises spreadsheet formulas (CSV injection)
"""

import csv
import hmac
import io
import os
import platform
import secrets
from functools import wraps
from importlib import metadata

from flask import (Flask, Response, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)

import audit_logger
import auth
import config
import policy_engine
import security_lab
import token_manager
from database import get_setting, init_db, query_all, query_one, set_setting, utc_now

ADMIN_ONLY = ("admin",)
STAFF_ROLES = ("admin", "analyst")       # roles that may see the security console

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,        # JavaScript cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",       # cookie is not sent on cross-site POSTs
    TEMPLATES_AUTO_RELOAD=True,
    MAX_CONTENT_LENGTH=64 * 1024,        # reject huge request bodies
)

init_db()   # create tables and demo data on first run


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def client_ip():
    """IP address of the caller (always 127.0.0.1 when running locally)."""
    return request.remote_addr or "unknown"


def is_api_request():
    """API endpoints answer with JSON instead of redirects or HTML pages."""
    return request.path.startswith("/api/")


def json_result(ok, message, status=None, **extra):
    """Standard JSON reply: {"ok": bool, "message": str, ...extra fields}."""
    body = {"ok": ok, "message": message}
    body.update(extra)
    response = jsonify(body)
    response.status_code = status or (200 if ok else 400)
    return response


def read_json():
    """Request body as a dictionary (empty dict if missing or malformed)."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def get_text(data, key, max_len=100, strip=True):
    """Safely read a string field; anything that is not a string becomes ''."""
    value = data.get(key)
    if not isinstance(value, str):
        return ""
    return (value.strip() if strip else value)[:max_len]


def to_int(value):
    """Convert to int, or return None if that is not possible."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_bool(value):
    """Interpret True / 'true' / '1' / 'on' as True; everything else is False."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "on", "yes")


def landing_page_for(role):
    """Where each role lands after login."""
    return "access_requests" if role == "user" else "dashboard"


def rows_to_dicts(rows):
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# CSRF protection and per-request setup
# ---------------------------------------------------------------------------
def get_csrf_token():
    """Return this session's CSRF token (created on first use)."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@app.before_request
def prepare_request():
    """Runs before every request: set defaults and verify CSRF on state-changing calls."""
    g.user = None
    g.token_payload = None

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(sent.encode("utf-8"), expected.encode("utf-8")):
            if is_api_request():
                return json_result(False, "Invalid or missing CSRF token. Reload the page.", 400)
            flash("Your form expired. Please try again.", "warning")
            return redirect(url_for("login"))


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.context_processor
def inject_template_globals():
    """Variables available in EVERY template."""
    payload = g.get("token_payload")
    return {
        "csrf_token": get_csrf_token,                       # use {{ csrf_token() }}
        "current_user": g.get("user"),
        "session_expires_epoch": payload["exp"] if payload else None,
        "STAFF_ROLES": STAFF_ROLES,
    }


# ---------------------------------------------------------------------------
# The page guard
# ---------------------------------------------------------------------------
def load_session_user():
    """
    Verify the session's token and load the user from the database.
    Returns (user_dict, None) on success or (None, message) on failure.
    """
    token = session.get("token")
    if not token:
        return None, "Please log in to continue."

    verification = token_manager.verify_token(token)
    if not verification["valid"]:
        return None, f"Session ended: {verification['reason']}."

    payload = verification["payload"]
    user = query_one("SELECT * FROM users WHERE id = ?", (payload["uid"],))
    if user is None or not user["is_active"]:
        return None, "Your account is not active."

    g.token_payload = payload
    return {key: user[key] for key in user.keys() if key != "password_hash"}, None


def login_required(*allowed_roles):
    """
    Decorator for console pages and API endpoints.
    No arguments  -> any logged-in user.
    With roles    -> only those roles (the role is read from the DATABASE every time).
    """
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user, problem = load_session_user()
            if user is None:
                session.clear()
                if is_api_request():
                    return json_result(False, problem, 401)
                flash(problem, "warning")
                return redirect(url_for("login"))

            g.user = user
            if allowed_roles and user["role"] not in allowed_roles:
                audit_logger.log_security_event(
                    "PAGE_ACCESS_DENIED", "warning", user["username"],
                    f"Role '{user['role']}' tried to open {request.path} "
                    f"(requires: {', '.join(allowed_roles)}) from {client_ip()}")
                if is_api_request():
                    return json_result(False, "Permission denied for your role.", 403)
                return render_template(
                    "denied.html", title="Access denied", decision=None, status_code=403,
                    reason=f"Your role '{user['role']}' is not permitted to open this page."), 403
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Login and logout
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    user, _ = load_session_user()
    if user is None:
        return redirect(url_for("login"))
    return redirect(url_for(landing_page_for(user["role"])))


@app.route("/login", methods=["GET", "POST"])
def login():
    devices = rows_to_dicts(query_all(
        "SELECT id, name, os_name, posture_score, trust_level FROM devices ORDER BY id"))

    if request.method == "GET":
        user, _ = load_session_user()
        if user is not None:
            return redirect(url_for(landing_page_for(user["role"])))
        return render_template("login.html", devices=devices, username="")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    device_id = to_int(request.form.get("device_id")) or 0

    result = auth.authenticate(username, password, device_id, client_ip())
    if not result["success"]:
        flash(result["message"], "danger")
        return render_template("login.html", devices=devices, username=username[:50]), 401

    # Success: revoke any older token from this browser, then start a fresh session.
    old_token = session.get("token")
    if old_token:
        auth.logout(old_token, client_ip())
    session.clear()                      # anti session-fixation
    session["token"] = result["token"]
    flash(f"Welcome back, {result['user']['full_name']}.", "success")
    return redirect(url_for(landing_page_for(result["user"]["role"])))


@app.route("/logout", methods=["POST"])
def logout():
    token = session.get("token")
    if token:
        auth.logout(token, client_ip())  # revokes the token on the server
    session.clear()
    flash("You have been logged out securely.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
def get_device_trust_counts():
    counts = {"trusted": 0, "at_risk": 0, "untrusted": 0}
    for row in query_all("SELECT trust_level, COUNT(*) AS total FROM devices GROUP BY trust_level"):
        counts[row["trust_level"]] = row["total"]
    return counts


def build_dashboard_data():
    """Everything the dashboard shows. Used by the page AND the live-refresh API."""
    access_counts = audit_logger.get_access_counts()
    return {
        "stats": {
            "total_users": query_one("SELECT COUNT(*) AS n FROM users")["n"],
            "active_sessions": token_manager.count_active_sessions(),
            "total_requests": access_counts["total"],
            "granted": access_counts["granted"],
            "denied": access_counts["denied"],
        },
        "activity": audit_logger.get_activity_last_days(7),
        "device_trust": get_device_trust_counts(),
        "recent_events": rows_to_dicts(audit_logger.get_recent_events(8)),
        "recent_requests": rows_to_dicts(audit_logger.get_recent_access(8)),
        "generated_at": utc_now(),
    }


@app.route("/dashboard")
@login_required(*STAFF_ROLES)
def dashboard():
    return render_template("dashboard.html", data=build_dashboard_data())


@app.route("/api/dashboard-stats")
@login_required(*STAFF_ROLES)
def api_dashboard_stats():
    return jsonify(build_dashboard_data())


# ---------------------------------------------------------------------------
# Access requests and protected resources
# ---------------------------------------------------------------------------
# Fictional demo content shown when access is GRANTED.
RESOURCE_DEMO_CONTENT = {
    "Admin Dashboard": {
        "headline": "Administrative control panel",
        "items": ["System status: all services operational",
                  "Pending account reviews: 2",
                  "Last configuration backup: completed"],
    },
    "Security Reports": {
        "headline": "Security analysis reports",
        "items": ["Incident IR-014: phishing campaign, contained",
                  "Weekly vulnerability scan: 3 medium, 0 critical findings",
                  "Firewall rule review: scheduled"],
    },
    "General Documents": {
        "headline": "Company-wide documents",
        "items": ["Employee handbook v4.2", "IT acceptable use policy", "Holiday calendar"],
    },
}
DEFAULT_RESOURCE_CONTENT = {"headline": "Protected resource",
                            "items": ["No demo content has been defined for this resource."]}


@app.route("/access-requests")
@login_required()
def access_requests():
    can_see_all = g.user["role"] in STAFF_ROLES
    if can_see_all:
        requests_list = audit_logger.get_recent_access(100)
    else:
        requests_list = query_all(
            "SELECT * FROM access_logs WHERE user_id = ? ORDER BY id DESC LIMIT 100",
            (g.user["id"],))

    device = query_one("SELECT * FROM devices WHERE id = ?", (g.token_payload.get("device_id"),))
    return render_template(
        "access_requests.html",
        resources=rows_to_dicts(policy_engine.list_policies()),
        access_requests=rows_to_dicts(requests_list),
        my_device=dict(device) if device else None,
        can_see_all=can_see_all)


@app.route("/resources/<slug>")
def view_resource(slug):
    """
    A protected resource. This route has NO page guard on purpose: the PEP
    (enforce_access) performs all six checks itself and logs the result, even
    for anonymous or expired-token requests.
    """
    g.user, _ = load_session_user()
    decision = policy_engine.enforce_access(session.get("token"), f"/resources/{slug}", client_ip())

    if decision["granted"]:
        resource = decision["resource"]
        content = RESOURCE_DEMO_CONTENT.get(resource["name"], DEFAULT_RESOURCE_CONTENT)
        return render_template("resource_view.html", resource=resource,
                               content=content, decision=decision)

    # Not logged in / session problem -> back to the login page.
    if decision["failed_code"] in ("NO_TOKEN", "TOKEN_INVALID", "USER_INACTIVE"):
        session.clear()
        flash(decision["reason"], "warning")
        return redirect(url_for("login"))

    status = 404 if decision["failed_code"] == "RESOURCE_UNKNOWN" else 403
    return render_template("denied.html", title="Access denied", reason=decision["reason"],
                           decision=decision, status_code=status), status


@app.route("/api/access-request", methods=["POST"])
@login_required()
def api_access_request():
    """Access request simulation: the logged-in user asks for a resource."""
    resource_id = to_int(read_json().get("resource_id"))
    resource = (query_one("SELECT * FROM resources WHERE id = ?", (resource_id,))
                if resource_id is not None else None)
    identifier = resource["path"] if resource else "unknown-resource"

    decision = policy_engine.enforce_access(session.get("token"), identifier, client_ip())
    return jsonify({
        "ok": True,
        "granted": decision["granted"],
        "reason": decision["reason"],
        "checks": decision["checks"],
        "resource": resource["name"] if resource else None,
        "open_url": resource["path"] if (resource and decision["granted"]) else None,
    })


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------
@app.route("/users")
@login_required(*ADMIN_ONLY)
def users_page():
    now = utc_now()
    users = []
    for row in query_all(
            "SELECT id, username, full_name, role, is_active, failed_attempts, locked_until, "
            "created_at, last_login FROM users ORDER BY id"):
        user = dict(row)
        user["is_locked"] = bool(user["locked_until"] and user["locked_until"] > now)
        users.append(user)
    return render_template("users.html", users=users, roles=auth.VALID_ROLES)


@app.route("/api/users", methods=["POST"])
@login_required(*ADMIN_ONLY)
def api_create_user():
    data = read_json()
    ok, message = auth.create_user(
        get_text(data, "username", 30), get_text(data, "password", 128, strip=False),
        get_text(data, "full_name", 80), get_text(data, "role", 20), g.user["username"])
    return json_result(ok, message)


@app.route("/api/users/<int:user_id>/role", methods=["POST"])
@login_required(*ADMIN_ONLY)
def api_update_role(user_id):
    ok, message = auth.update_user_role(user_id, get_text(read_json(), "role", 20),
                                        g.user["id"], g.user["username"])
    return json_result(ok, message)


@app.route("/api/users/<int:user_id>/active", methods=["POST"])
@login_required(*ADMIN_ONLY)
def api_set_user_active(user_id):
    ok, message = auth.set_user_active(user_id, as_bool(read_json().get("active")),
                                       g.user["id"], g.user["username"])
    return json_result(ok, message)


@app.route("/api/users/<int:user_id>/unlock", methods=["POST"])
@login_required(*ADMIN_ONLY)
def api_unlock_user(user_id):
    ok, message = auth.unlock_user(user_id, g.user["username"])
    return json_result(ok, message)


# ---------------------------------------------------------------------------
# Security policies (view: admin + analyst, change: admin)
# ---------------------------------------------------------------------------
@app.route("/policies")
@login_required(*STAFF_ROLES)
def policies_page():
    policies = rows_to_dicts(policy_engine.list_policies())
    for policy in policies:
        policy["roles_list"] = policy["allowed_roles"].split(",") if policy["allowed_roles"] else []
    return render_template("policies.html", policies=policies, roles=auth.VALID_ROLES,
                           can_edit=(g.user["role"] == "admin"))


@app.route("/api/resources", methods=["POST"])
@login_required(*ADMIN_ONLY)
def api_create_resource():
    data = read_json()
    ok, message, resource_id = policy_engine.create_resource(
        get_text(data, "name", 60), get_text(data, "description", 200),
        get_text(data, "sensitivity", 10), g.user["username"])
    if ok:
        message += " It has no policy yet, so access is denied by default until you create one."
    return json_result(ok, message, resource_id=resource_id)


@app.route("/api/policies", methods=["POST"])
@login_required(*ADMIN_ONLY)
def api_save_policy():
    data = read_json()
    roles = data.get("allowed_roles")
    ok, message = policy_engine.save_policy(
        to_int(data.get("resource_id")), roles if isinstance(roles, list) else [],
        data.get("min_posture_score"), as_bool(data.get("is_active", True)), g.user["username"])
    return json_result(ok, message)


# ---------------------------------------------------------------------------
# Device posture (view: admin + analyst, change: admin)
# ---------------------------------------------------------------------------
@app.route("/devices")
@login_required(*STAFF_ROLES)
def devices_page():
    return render_template(
        "devices.html",
        devices=rows_to_dicts(query_all("SELECT * FROM devices ORDER BY id")),
        device_trust=get_device_trust_counts(),
        can_edit=(g.user["role"] == "admin"))


@app.route("/api/devices", methods=["POST"])
@login_required(*ADMIN_ONLY)
def api_create_device():
    data = read_json()
    ok, message, device_id = policy_engine.create_device(
        get_text(data, "name", 60), get_text(data, "os_name", 40),
        as_bool(data.get("os_patched")), as_bool(data.get("antivirus_on")),
        as_bool(data.get("disk_encrypted")), as_bool(data.get("firewall_on")),
        g.user["username"])
    return json_result(ok, message, device_id=device_id)


@app.route("/api/devices/<int:device_id>/posture", methods=["POST"])
@login_required(*ADMIN_ONLY)
def api_update_device(device_id):
    data = read_json()
    ok, message = policy_engine.update_device_posture(
        device_id, as_bool(data.get("os_patched")), as_bool(data.get("antivirus_on")),
        as_bool(data.get("disk_encrypted")), as_bool(data.get("firewall_on")),
        g.user["username"])
    return json_result(ok, message)


# ---------------------------------------------------------------------------
# Audit logs (admin + analyst): search, filter, export
# ---------------------------------------------------------------------------
LOG_FILTER_KEYS = ("search", "decision", "role", "resource", "date_from", "date_to")


def read_log_filters():
    """Read the filter fields from the query string (each capped at 100 characters)."""
    return {key: request.args.get(key, "").strip()[:100] for key in LOG_FILTER_KEYS}


@app.route("/audit-logs")
@login_required(*STAFF_ROLES)
def audit_logs():
    filters = read_log_filters()
    return render_template(
        "audit_logs.html",
        logs=rows_to_dicts(audit_logger.search_access_logs(**filters)),
        events=rows_to_dicts(query_all("SELECT * FROM security_events ORDER BY id DESC LIMIT 100")),
        filters=filters,
        resource_names=[row["name"] for row in query_all("SELECT name FROM resources ORDER BY name")],
        roles=auth.VALID_ROLES)


def csv_safe(value):
    """Prefix cells that start with =, +, -, @ so Excel cannot run them as formulas."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@app.route("/audit-logs/export")
@login_required(*STAFF_ROLES)
def export_audit_logs():
    logs = audit_logger.search_access_logs(**read_log_filters(), limit=1000)
    columns = ["id", "timestamp", "username", "role", "resource_name",
               "decision", "reason", "ip_address"]

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in logs:
        writer.writerow([csv_safe(row[column]) for column in columns])

    audit_logger.log_security_event("AUDIT_EXPORT", "info", g.user["username"],
                                    f"Exported {len(logs)} access log rows to CSV")
    return Response(buffer.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=access_logs.csv"})


# ---------------------------------------------------------------------------
# Security Testing Lab (admin + analyst)
# ---------------------------------------------------------------------------
@app.route("/security-lab")
@login_required(*STAFF_ROLES)
def security_lab_page():
    return render_template("security_lab.html", scenarios=security_lab.list_scenarios())


@app.route("/api/security-lab/run/<scenario_id>", methods=["POST"])
@login_required(*STAFF_ROLES)
def api_run_scenario(scenario_id):
    result = security_lab.run_scenario(scenario_id, g.user["username"], client_ip())
    if result is None:
        return json_result(False, "Unknown scenario.", 404)
    return jsonify({"ok": True, "result": result, "stats": build_dashboard_data()["stats"]})


@app.route("/api/security-lab/run-all", methods=["POST"])
@login_required(*STAFF_ROLES)
def api_run_all_scenarios():
    results = security_lab.run_all(g.user["username"], client_ip())
    return jsonify({"ok": True, "results": results, "stats": build_dashboard_data()["stats"]})


# ---------------------------------------------------------------------------
# System settings (admin only)
# ---------------------------------------------------------------------------
# key: (minimum, maximum, label)
SETTING_LIMITS = {
    "token_lifetime_minutes": (1, 1440, "Token lifetime (minutes)"),
    "max_failed_logins": (1, 20, "Failed logins before lockout"),
    "lockout_minutes": (1, 1440, "Lockout duration (minutes)"),
    "default_min_posture_score": (0, 100, "Default minimum posture score"),
}


@app.route("/settings")
@login_required(*ADMIN_ONLY)
def settings_page():
    try:
        flask_version = metadata.version("flask")
    except metadata.PackageNotFoundError:
        flask_version = "unknown"

    return render_template(
        "settings.html",
        settings={key: get_setting(key) for key in SETTING_LIMITS},
        limits={key: {"min": low, "max": high, "label": label}
                for key, (low, high, label) in SETTING_LIMITS.items()},
        system_info={
            "python_version": platform.python_version(),
            "flask_version": flask_version,
            "database_path": config.DATABASE_PATH,
            "using_default_keys": (config.SECRET_KEY.startswith("dev-only")
                                   or config.TOKEN_SECRET_KEY.startswith("dev-only")),
        })


@app.route("/api/settings", methods=["POST"])
@login_required(*ADMIN_ONLY)
def api_save_settings():
    data = read_json()
    clean = {}
    for key, (low, high, label) in SETTING_LIMITS.items():
        if key not in data:
            continue
        value = to_int(data[key])
        if value is None:
            return json_result(False, f"{label} must be a whole number.")
        if not low <= value <= high:
            return json_result(False, f"{label} must be between {low} and {high}.")
        clean[key] = value

    if not clean:
        return json_result(False, "No settings were provided.")
    for key, value in clean.items():
        set_setting(key, value)

    audit_logger.log_security_event(
        "SETTINGS_CHANGED", "warning", g.user["username"],
        ", ".join(f"{key}={value}" for key, value in clean.items()))
    return json_result(True, "Settings saved. A new token lifetime applies to new logins only.")


# ---------------------------------------------------------------------------
# Error pages (generic on purpose: never reveal internals)
# ---------------------------------------------------------------------------
def error_response(status, title, message):
    if is_api_request():
        return json_result(False, message, status)
    return render_template("denied.html", title=title, reason=message,
                           decision=None, status_code=status), status


@app.errorhandler(404)
def handle_not_found(error):
    return error_response(404, "Page not found", "The page you requested does not exist.")


@app.errorhandler(405)
def handle_method_not_allowed(error):
    return error_response(405, "Method not allowed", "This action is not allowed here.")


@app.errorhandler(413)
def handle_too_large(error):
    return error_response(413, "Request too large", "The request was too large.")


@app.errorhandler(500)
def handle_server_error(error):
    return error_response(500, "Server error", "Something went wrong. Please try again.")


# ---------------------------------------------------------------------------
# Start the development server
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if config.SECRET_KEY.startswith("dev-only") or config.TOKEN_SECRET_KEY.startswith("dev-only"):
        print("WARNING: using development-only secret keys. Fine for a local demo; "
              "set ZTNA_FLASK_SECRET and ZTNA_TOKEN_SECRET for anything else.")
    # Bound to 127.0.0.1 so only this laptop can reach it. debug stays OFF unless
    # you set ZTNA_DEBUG=1, because Flask's debugger allows remote code execution.
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("ZTNA_DEBUG") == "1")