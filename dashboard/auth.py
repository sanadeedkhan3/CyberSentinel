"""
dashboard/auth.py
------------------
Authentication system for CyberSentinel.

Features:
- Secure password hashing (SHA-256 + salt)
- Session-based login with expiry
- Rate limiting (blocks brute force after 5 failed attempts)
- Account lockout with cooldown
- Audit log of all login attempts
- First-run setup (creates default admin on first launch)
"""

import os
import sys
import json
import time
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import session, redirect, url_for, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# ── Config ────────────────────────────────────────────────────────────────────

AUTH_DB_PATH   = os.path.join(os.path.dirname(__file__), '..', 'auth.db')
SESSION_HOURS  = 8           # auto-logout after 8 hours
MAX_ATTEMPTS   = 5           # lockout after 5 failed attempts
LOCKOUT_SECS   = 300         # 5 minute lockout
SECRET_KEY     = os.getenv("SECRET_KEY") or secrets.token_hex(32)

# Default admin — MUST be changed on first login
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "CyberSentinel2024!"


# ── Database setup ────────────────────────────────────────────────────────────

def get_auth_conn():
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db():
    """Create auth tables and default admin user if not present."""
    conn = get_auth_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            salt          TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'admin',
            created_at    REAL    NOT NULL,
            last_login    REAL,
            must_change_password INTEGER NOT NULL DEFAULT 1,
            is_active     INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL,
            ip_address TEXT    NOT NULL,
            success    INTEGER NOT NULL,
            timestamp  REAL    NOT NULL,
            user_agent TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT    PRIMARY KEY,
            username   TEXT    NOT NULL,
            created_at REAL    NOT NULL,
            expires_at REAL    NOT NULL,
            ip_address TEXT,
            last_active REAL
        )
    """)
    conn.commit()

    # Create default admin if no users exist
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        salt, pw_hash = hash_password(DEFAULT_PASSWORD)
        conn.execute("""
            INSERT INTO users (username, password_hash, salt, role, created_at, must_change_password)
            VALUES (?, ?, ?, 'admin', ?, 1)
        """, (DEFAULT_USERNAME, pw_hash, salt, time.time()))
        conn.commit()
        print(f"[AUTH] Default admin created. Username: {DEFAULT_USERNAME} | Password: {DEFAULT_PASSWORD}")
        print(f"[AUTH] ⚠  Change your password immediately after first login!")

    conn.close()


# ── Password utilities ────────────────────────────────────────────────────────

def hash_password(password: str, salt: str = None) -> tuple:
    """Hash a password with a random salt. Returns (salt, hash)."""
    if salt is None:
        salt = secrets.token_hex(32)
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations=260000   # OWASP recommended minimum
    ).hex()
    return salt, pw_hash


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash."""
    _, computed_hash = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


def validate_password_strength(password: str) -> list:
    """Return list of issues with a password. Empty list = strong enough."""
    issues = []
    if len(password) < 10:
        issues.append("At least 10 characters required")
    if not any(c.isupper() for c in password):
        issues.append("At least one uppercase letter required")
    if not any(c.islower() for c in password):
        issues.append("At least one lowercase letter required")
    if not any(c.isdigit() for c in password):
        issues.append("At least one number required")
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        issues.append("At least one special character required")
    return issues


# ── Rate limiting ─────────────────────────────────────────────────────────────

def is_locked_out(username: str, ip: str) -> tuple:
    """
    Check if a username or IP is locked out.
    Returns (is_locked, seconds_remaining).
    """
    conn = get_auth_conn()
    cutoff = time.time() - LOCKOUT_SECS

    # Count recent failures for this username OR ip
    failures = conn.execute("""
        SELECT COUNT(*) FROM login_attempts
        WHERE (username = ? OR ip_address = ?)
          AND success = 0
          AND timestamp > ?
    """, (username, ip, cutoff)).fetchone()[0]

    conn.close()

    if failures >= MAX_ATTEMPTS:
        # Find when the lockout expires
        conn = get_auth_conn()
        last_fail = conn.execute("""
            SELECT MAX(timestamp) FROM login_attempts
            WHERE (username = ? OR ip_address = ?) AND success = 0
        """, (username, ip)).fetchone()[0]
        conn.close()
        remaining = int((last_fail + LOCKOUT_SECS) - time.time())
        return True, max(0, remaining)

    return False, 0


def log_attempt(username: str, ip: str, success: bool, user_agent: str = ""):
    """Record a login attempt in the audit log."""
    conn = get_auth_conn()
    conn.execute("""
        INSERT INTO login_attempts (username, ip_address, success, timestamp, user_agent)
        VALUES (?, ?, ?, ?, ?)
    """, (username, ip, int(success), time.time(), user_agent[:200]))
    conn.commit()
    conn.close()


# ── Session management ────────────────────────────────────────────────────────

def create_session(username: str, ip: str) -> str:
    """Create a new session token for a logged-in user."""
    token = secrets.token_urlsafe(48)
    now   = time.time()
    conn  = get_auth_conn()
    conn.execute("""
        INSERT INTO sessions (token, username, created_at, expires_at, ip_address, last_active)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (token, username, now, now + SESSION_HOURS * 3600, ip, now))
    conn.commit()
    conn.close()
    return token


def validate_session(token: str) -> dict | None:
    """
    Check if a session token is valid and not expired.
    Returns user dict or None.
    """
    if not token:
        return None
    conn = get_auth_conn()
    sess = conn.execute("""
        SELECT s.*, u.role, u.must_change_password, u.is_active
        FROM sessions s
        JOIN users u ON s.username = u.username
        WHERE s.token = ? AND s.expires_at > ?
    """, (token, time.time())).fetchone()

    if sess and sess["is_active"]:
        # Refresh last_active
        conn.execute(
            "UPDATE sessions SET last_active = ? WHERE token = ?",
            (time.time(), token)
        )
        conn.commit()
        conn.close()
        return dict(sess)

    conn.close()
    return None


def invalidate_session(token: str):
    """Delete a session (logout)."""
    conn = get_auth_conn()
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def cleanup_expired_sessions():
    """Remove expired sessions from the database."""
    conn = get_auth_conn()
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
    conn.commit()
    conn.close()


# ── User management ───────────────────────────────────────────────────────────

def authenticate(username: str, password: str, ip: str, user_agent: str = "") -> tuple:
    """
    Attempt to authenticate a user.
    Returns (success, message, user_dict_or_None).
    """
    locked, secs = is_locked_out(username, ip)
    if locked:
        return False, f"Account locked. Try again in {secs} seconds.", None

    conn = get_auth_conn()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)
    ).fetchone()
    conn.close()

    if not user or not verify_password(password, user["salt"], user["password_hash"]):
        log_attempt(username, ip, False, user_agent)
        remaining = MAX_ATTEMPTS - get_recent_failure_count(username, ip) - 1
        if remaining <= 0:
            return False, f"Too many failed attempts. Account locked for {LOCKOUT_SECS//60} minutes.", None
        return False, f"Invalid username or password. {remaining} attempts remaining.", None

    # Success
    log_attempt(username, ip, True, user_agent)
    conn = get_auth_conn()
    conn.execute("UPDATE users SET last_login = ? WHERE username = ?", (time.time(), username))
    conn.commit()
    conn.close()
    return True, "Login successful.", dict(user)


def get_recent_failure_count(username: str, ip: str) -> int:
    cutoff = time.time() - LOCKOUT_SECS
    conn = get_auth_conn()
    count = conn.execute("""
        SELECT COUNT(*) FROM login_attempts
        WHERE (username = ? OR ip_address = ?) AND success = 0 AND timestamp > ?
    """, (username, ip, cutoff)).fetchone()[0]
    conn.close()
    return count


def change_password(username: str, new_password: str) -> tuple:
    """Change a user's password. Returns (success, message)."""
    issues = validate_password_strength(new_password)
    if issues:
        return False, " | ".join(issues)

    salt, pw_hash = hash_password(new_password)
    conn = get_auth_conn()
    conn.execute("""
        UPDATE users SET password_hash = ?, salt = ?, must_change_password = 0
        WHERE username = ?
    """, (pw_hash, salt, username))
    conn.commit()
    conn.close()
    return True, "Password changed successfully."


def get_audit_log(limit: int = 50) -> list:
    """Fetch recent login attempts for the admin panel."""
    conn = get_auth_conn()
    rows = conn.execute("""
        SELECT username, ip_address, success,
               datetime(timestamp, 'unixepoch', 'localtime') as time_str
        FROM login_attempts
        ORDER BY timestamp DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Flask decorator ───────────────────────────────────────────────────────────

def login_required(f):
    """Decorator — redirects to login if user is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("token")
        user  = validate_session(token)
        if not user:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    """Return the currently logged-in user dict, or None."""
    return validate_session(session.get("token"))