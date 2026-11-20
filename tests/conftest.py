"""
conftest.py - Shared test setup (pytest loads this file automatically).

Key idea: the tests NEVER touch your real ztna.db. Before any project module is
imported, we point config.DATABASE_PATH at a temporary file. Then, before every
single test, we delete that file and rebuild it with the standard demo data, so
each test starts from the same known state:

    users:   admin=1, analyst=2, user=3
    devices: Corporate Laptop=1 (score 100), Personal Tablet=2 (55), Unknown Device=3 (20)
    policies: Admin Dashboard (admin, min 80), Security Reports (admin+analyst, min 70),
              General Documents (all roles, min 50)
"""

import os
import sys
import tempfile

import pytest

# Make the project root importable (so "import auth" works from inside tests/).
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import config

# Redirect the database BEFORE importing app.py (app.py calls init_db() on import).
_TEST_DIR = tempfile.mkdtemp(prefix="ztna_tests_")
config.DATABASE_PATH = os.path.join(_TEST_DIR, "test_ztna.db")

import database          # noqa: E402  (import must come after the path change)
import app as ztna_app   # noqa: E402


@pytest.fixture(autouse=True)
def fresh_database():
    """Runs before EVERY test: delete the test database and rebuild it with demo data."""
    if os.path.exists(config.DATABASE_PATH):
        os.remove(config.DATABASE_PATH)
    database.init_db()
    yield


@pytest.fixture
def client():
    """A Flask test client (a fake browser that keeps cookies between requests)."""
    ztna_app.app.config["TESTING"] = True
    return ztna_app.app.test_client()