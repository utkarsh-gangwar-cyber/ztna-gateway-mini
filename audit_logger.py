"""
audit_logger.py - Writes and reads the audit trail.

Two kinds of records:
  * access_logs     -> one row per access decision (GRANTED / DENIED) for a resource
  * security_events -> notable security happenings (failed login, tampered token, lockout...)

Why a separate module? Every other module (auth, policy engine, security lab)
logs through these functions, so the audit format stays consistent.

All SQL values are passed as '?' parameters (no string-built values), so the
search filters cannot be abused for SQL injection.
"""

from datetime import datetime, timedelta, timezone

from database import execute, query_all, query_one, utc_now


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
def log_access(user_id, username, role, resource_id, resource_name,
               decision, reason, ip_address):
    """Store one access decision. `decision` must be 'GRANTED' or 'DENIED'."""
    execute(
        "INSERT INTO access_logs (user_id, username, role, resource_id, resource_name, "
        "decision, reason, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, username, role, resource_id, resource_name,
         decision, reason, ip_address, utc_now()),
    )


def log_security_event(event_type, severity, username, details):
    """Store one security event. severity: 'info', 'warning' or 'critical'."""
    execute(
        "INSERT INTO security_events (event_type, severity, username, details, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        (event_type, severity, username, details, utc_now()),
    )


# ---------------------------------------------------------------------------
# Reading: search and filter (Audit Logs page)
# ---------------------------------------------------------------------------
def search_access_logs(search="", decision="", role="", resource="",
                       date_from="", date_to="", limit=500):
    """
    Return access logs, newest first, applying any filters that are provided.
      search    -> text matched against username, resource, reason and IP
      decision  -> 'GRANTED' or 'DENIED'
      role      -> 'admin' / 'analyst' / 'user'
      resource  -> exact resource name
      date_from / date_to -> 'YYYY-MM-DD' (inclusive)
    """
    sql = "SELECT * FROM access_logs WHERE 1=1"   # fixed fragments only
    params = []

    if search:
        like = f"%{search}%"
        sql += " AND (username LIKE ? OR resource_name LIKE ? OR reason LIKE ? OR ip_address LIKE ?)"
        params.extend([like, like, like, like])
    if decision in ("GRANTED", "DENIED"):
        sql += " AND decision = ?"
        params.append(decision)
    if role:
        sql += " AND role = ?"
        params.append(role)
    if resource:
        sql += " AND resource_name = ?"
        params.append(resource)
    if date_from:
        sql += " AND timestamp >= ?"
        params.append(date_from + " 00:00:00")
    if date_to:
        sql += " AND timestamp <= ?"
        params.append(date_to + " 23:59:59")

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 1000)))   # clamp to 1..1000
    return query_all(sql, tuple(params))


def get_recent_access(limit=10):
    """Latest access requests (dashboard table)."""
    return query_all("SELECT * FROM access_logs ORDER BY id DESC LIMIT ?", (limit,))


def get_recent_events(limit=10):
    """
    Latest security events (dashboard 'Recent Security Events').

    security_events has no resource/decision columns, but every access-related
    event is written by policy_engine right after its access_logs row, in the
    form "<resource name>: <reason> (from <ip>)". So each event is matched to
    its access_logs row (same user, within 2 seconds, details starting with
    that resource name) to expose `resource_name` and `decision` when known.
    Events with no matching access decision (logins, logouts...) get NULLs.
    Read-only: nothing is written and no existing table is changed.
    """
    return query_all(
        "SELECT e.*, "
        "  (SELECT a.resource_name FROM access_logs a "
        "    WHERE a.username = e.username "
        "      AND e.details LIKE a.resource_name || ': %' "
        "      AND ABS(strftime('%s', a.timestamp) - strftime('%s', e.timestamp)) <= 2 "
        "    ORDER BY a.id DESC LIMIT 1) AS resource_name, "
        "  (SELECT a.decision FROM access_logs a "
        "    WHERE a.username = e.username "
        "      AND e.details LIKE a.resource_name || ': %' "
        "      AND ABS(strftime('%s', a.timestamp) - strftime('%s', e.timestamp)) <= 2 "
        "    ORDER BY a.id DESC LIMIT 1) AS decision "
        "FROM security_events e ORDER BY e.id DESC LIMIT ?",
        (limit,),
    )


# ---------------------------------------------------------------------------
# Statistics for the dashboard
# ---------------------------------------------------------------------------
def get_access_counts():
    """Return {'total': n, 'granted': n, 'denied': n}."""
    row = query_one(
        "SELECT COUNT(*) AS total, "
        "COALESCE(SUM(decision = 'GRANTED'), 0) AS granted, "
        "COALESCE(SUM(decision = 'DENIED'), 0) AS denied "
        "FROM access_logs"
    )
    return {"total": row["total"], "granted": row["granted"], "denied": row["denied"]}


def get_activity_last_days(days=7):
    """
    Granted/denied counts per day for the last `days` days (oldest first).
    Days with no activity are filled with zeros so the chart has no gaps.
    """
    today = datetime.now(timezone.utc)
    start_day = (today - timedelta(days=days - 1)).strftime("%Y-%m-%d")

    rows = query_all(
        "SELECT substr(timestamp, 1, 10) AS day, decision, COUNT(*) AS total "
        "FROM access_logs WHERE substr(timestamp, 1, 10) >= ? "
        "GROUP BY day, decision",
        (start_day,),
    )
    counts = {(row["day"], row["decision"]): row["total"] for row in rows}

    activity = []
    for offset in range(days - 1, -1, -1):
        day = (today - timedelta(days=offset)).strftime("%Y-%m-%d")
        activity.append({
            "date": day,
            "granted": counts.get((day, "GRANTED"), 0),
            "denied": counts.get((day, "DENIED"), 0),
        })
    return activity