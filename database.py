"""
database.py - SQLite connection helpers, schema creation and demo data.

Purpose: everything that touches the database file lives here or uses the
small helper functions below (query_all, query_one, execute). All SQL uses
'?' placeholders (parameterized queries), which prevents SQL injection.

Run `python database.py` to create the database and seed demo data.
Run `python database.py --reset` to delete the database and rebuild it.
"""

import os
import sqlite3
import sys
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash

import config


# ---------------------------------------------------------------------------
# Small utility functions
# ---------------------------------------------------------------------------
def utc_now():
    """Current UTC time as 'YYYY-MM-DD HH:MM:SS'. This format sorts correctly as text."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def get_db():
    """Open a connection. Rows behave like dictionaries; foreign keys are enforced."""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite ignores foreign keys unless asked
    return conn


def query_all(sql, params=()):
    """Run a SELECT and return a list of rows."""
    conn = get_db()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def query_one(sql, params=()):
    """Run a SELECT and return the first row (or None)."""
    conn = get_db()
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def execute(sql, params=()):
    """Run INSERT / UPDATE / DELETE, commit, and return the new row id."""
    conn = get_db()
    try:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Settings helpers (key/value pairs shown on the System Settings page)
# ---------------------------------------------------------------------------
def get_setting(key, default=None):
    """Read one setting as text; return `default` if it does not exist."""
    row = query_one("SELECT value FROM settings WHERE key = ?", (key,))
    return row["value"] if row else default


def set_setting(key, value):
    """Create or update one setting."""
    execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


# ---------------------------------------------------------------------------
# Device posture helpers (reused later by policy_engine.py)
# ---------------------------------------------------------------------------
def calculate_posture_score(os_patched, antivirus_on, disk_encrypted, firewall_on):
    """Add up the weight of every security control the device has enabled."""
    checks = {
        "os_patched": os_patched,
        "antivirus_on": antivirus_on,
        "disk_encrypted": disk_encrypted,
        "firewall_on": firewall_on,
    }
    return sum(config.POSTURE_WEIGHTS[name] for name, enabled in checks.items() if enabled)


def trust_level_for_score(score):
    """Convert a numeric score into 'trusted', 'at_risk' or 'untrusted'."""
    if score >= config.TRUSTED_THRESHOLD:
        return "trusted"
    if score >= config.AT_RISK_THRESHOLD:
        return "at_risk"
    return "untrusted"


# ---------------------------------------------------------------------------
# Database schema
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT NOT NULL UNIQUE,
    password_hash    TEXT NOT NULL,              -- never the plain-text password
    full_name        TEXT NOT NULL,
    role             TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'user')),
    is_active        INTEGER NOT NULL DEFAULT 1,
    failed_attempts  INTEGER NOT NULL DEFAULT 0, -- consecutive failed logins
    locked_until     TEXT,                       -- NULL = not locked
    created_at       TEXT NOT NULL,
    last_login       TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    os_name         TEXT NOT NULL,
    os_patched      INTEGER NOT NULL DEFAULT 0,
    antivirus_on    INTEGER NOT NULL DEFAULT 0,
    disk_encrypted  INTEGER NOT NULL DEFAULT 0,
    firewall_on     INTEGER NOT NULL DEFAULT 0,
    posture_score   INTEGER NOT NULL DEFAULT 0,
    trust_level     TEXT NOT NULL DEFAULT 'untrusted'
                    CHECK (trust_level IN ('trusted', 'at_risk', 'untrusted')),
    last_checked    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resources (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    path         TEXT NOT NULL UNIQUE,
    description  TEXT,
    sensitivity  TEXT NOT NULL DEFAULT 'low'
                 CHECK (sensitivity IN ('low', 'medium', 'high'))
);

CREATE TABLE IF NOT EXISTS access_policies (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id        INTEGER NOT NULL UNIQUE,   -- one policy per resource
    allowed_roles      TEXT NOT NULL,             -- e.g. 'admin,analyst'
    min_posture_score  INTEGER NOT NULL DEFAULT 50,
    is_active          INTEGER NOT NULL DEFAULT 1,
    updated_at         TEXT NOT NULL,
    FOREIGN KEY (resource_id) REFERENCES resources (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    jti         TEXT NOT NULL UNIQUE,             -- unique token id (also inside the token)
    user_id     INTEGER NOT NULL,
    device_id   INTEGER,
    issued_at   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,       -- 1 after logout
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS access_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER,                       -- NULL if the user is unknown
    username       TEXT NOT NULL,
    role           TEXT,
    resource_id    INTEGER,
    resource_name  TEXT NOT NULL,
    decision       TEXT NOT NULL CHECK (decision IN ('GRANTED', 'DENIED')),
    reason         TEXT NOT NULL,
    ip_address     TEXT,
    timestamp      TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL,
    FOREIGN KEY (resource_id) REFERENCES resources (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL,                    -- e.g. LOGIN_FAILED, TOKEN_TAMPERED
    severity    TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    username    TEXT,
    details     TEXT,
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON access_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_decision  ON access_logs (decision);
CREATE INDEX IF NOT EXISTS idx_tokens_user    ON tokens (user_id);
"""


# ---------------------------------------------------------------------------
# Demo data (inserted only when the database is empty)
# ---------------------------------------------------------------------------
def seed_demo_data(conn):
    """Insert demo users, devices, resources, policies and settings."""
    now = utc_now()

    # --- Demo users. These passwords are for DEVELOPMENT/DEMO ONLY. ---
    demo_users = [
        ("admin",   "Admin@12345",   "System Administrator", "admin"),
        ("analyst", "Analyst@12345", "Security Analyst",     "analyst"),
        ("user",    "User@12345",    "Normal User",          "user"),
    ]
    for username, password, full_name, role in demo_users:
        conn.execute(
            "INSERT INTO users (username, password_hash, full_name, role, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, generate_password_hash(password), full_name, role, now),
        )

    # --- Simulated devices: one trusted, one at-risk, one untrusted. ---
    demo_devices = [
        # name,               os,              patched, av, disk, firewall
        ("Corporate Laptop",  "Windows 11",    1, 1, 1, 1),   # score 100
        ("Personal Tablet",   "Android 13",    1, 1, 0, 0),   # score 55
        ("Unknown Device",    "Unknown OS",    0, 0, 0, 1),   # score 20
    ]
    for name, os_name, patched, av, disk, fw in demo_devices:
        score = calculate_posture_score(patched, av, disk, fw)
        conn.execute(
            "INSERT INTO devices (name, os_name, os_patched, antivirus_on, disk_encrypted, "
            "firewall_on, posture_score, trust_level, last_checked) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, os_name, patched, av, disk, fw, score, trust_level_for_score(score), now),
        )

    # --- Protected resources. ---
    demo_resources = [
        ("Admin Dashboard", "/resources/admin-dashboard",
         "Administrative control panel for system management.", "high"),
        ("Security Reports", "/resources/security-reports",
         "Incident summaries and security analysis reports.", "medium"),
        ("General Documents", "/resources/general-documents",
         "Company-wide documents available to all staff.", "low"),
    ]
    for name, path, description, sensitivity in demo_resources:
        conn.execute(
            "INSERT INTO resources (name, path, description, sensitivity) VALUES (?, ?, ?, ?)",
            (name, path, description, sensitivity),
        )

    # --- Policies: which roles may open which resource, and the minimum device score. ---
    demo_policies = [
        ("Admin Dashboard",   "admin",                80),
        ("Security Reports",  "admin,analyst",        70),
        ("General Documents", "admin,analyst,user",   50),
    ]
    for resource_name, roles, min_score in demo_policies:
        resource_id = conn.execute(
            "SELECT id FROM resources WHERE name = ?", (resource_name,)
        ).fetchone()["id"]
        conn.execute(
            "INSERT INTO access_policies (resource_id, allowed_roles, min_posture_score, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (resource_id, roles, min_score, now),
        )

    # --- Default settings (editable later from the Settings page). ---
    default_settings = {
        "token_lifetime_minutes": config.TOKEN_LIFETIME_MINUTES,
        "max_failed_logins": config.MAX_FAILED_LOGINS,
        "lockout_minutes": config.LOCKOUT_MINUTES,
        "default_min_posture_score": config.DEFAULT_MIN_POSTURE_SCORE,
    }
    for key, value in default_settings.items():
        conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, str(value)))

    # --- One starting security event so the dashboard is not empty. ---
    conn.execute(
        "INSERT INTO security_events (event_type, severity, username, details, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        ("SYSTEM_INIT", "info", "system", "Database initialized with demo data.", now),
    )


def init_db():
    """Create tables if missing and seed demo data when there are no users yet."""
    conn = get_db()
    try:
        conn.executescript(SCHEMA)
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            seed_demo_data(conn)
            print("Demo data inserted.")
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    if "--reset" in sys.argv and os.path.exists(config.DATABASE_PATH):
        os.remove(config.DATABASE_PATH)
        print("Old database deleted.")
    init_db()
    print(f"Database ready at: {config.DATABASE_PATH}")