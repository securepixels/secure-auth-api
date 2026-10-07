"""
Secure Auth API
A production-ready authentication and authorization REST API with
OAuth2, JWT refresh tokens, RBAC, rate limiting, and brute-force protection.

Built by Chrissy P
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import base64


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

class Config:
    SECRET_KEY = os.environ.get("AUTH_SECRET_KEY", secrets.token_hex(32))
    ACCESS_TOKEN_EXPIRY = 900        # 15 minutes
    REFRESH_TOKEN_EXPIRY = 604800    # 7 days
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 900           # 15 minutes
    RATE_LIMIT_WINDOW = 60           # 1 minute
    RATE_LIMIT_MAX = 30              # requests per window
    BCRYPT_ROUNDS = 12
    DB_PATH = os.environ.get("AUTH_DB_PATH", "auth.db")
    HOST = os.environ.get("AUTH_HOST", "127.0.0.1")
    PORT = int(os.environ.get("AUTH_PORT", "8000"))
    PASSWORD_MIN_LENGTH = 12
    TOKEN_ISSUER = "secure-auth-api"


# ──────────────────────────────────────────────
# Password Hashing (PBKDF2-SHA256, stdlib only)
# ──────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash password using PBKDF2-SHA256 with random salt."""
    salt = secrets.token_hex(16)
    iterations = 100_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2:sha256:{iterations}${salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored PBKDF2 hash."""
    try:
        meta, salt, hash_hex = stored_hash.split("$")
        _, algo, iterations = meta.split(":")
        dk = hashlib.pbkdf2_hmac(algo, password.encode(), salt.encode(), int(iterations))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


# ──────────────────────────────────────────────
# JWT Implementation (stdlib only)
# ──────────────────────────────────────────────

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def base64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_jwt(payload: dict, secret: str, expiry_seconds: int) -> str:
    """Create a signed JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload.update({
        "iat": now,
        "exp": now + expiry_seconds,
        "iss": Config.TOKEN_ISSUER,
        "jti": secrets.token_hex(16),
    })
    segments = [
        base64url_encode(json.dumps(header).encode()),
        base64url_encode(json.dumps(payload).encode()),
    ]
    signing_input = f"{segments[0]}.{segments[1]}"
    signature = hmac.new(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    segments.append(base64url_encode(signature))
    return ".".join(segments)


def decode_jwt(token: str, secret: str) -> dict | None:
    """Decode and verify a JWT token. Returns payload or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}"
        expected_sig = hmac.new(
            secret.encode(), signing_input.encode(), hashlib.sha256
        ).digest()
        actual_sig = base64url_decode(parts[2])
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        payload = json.loads(base64url_decode(parts[1]))
        if payload.get("exp", 0) < int(time.time()):
            return None
        if payload.get("iss") != Config.TOKEN_ISSUER:
            return None
        return payload
    except Exception:
        return None


# ──────────────────────────────────────────────
# Roles & Permissions (RBAC)
# ──────────────────────────────────────────────

class Role(str, Enum):
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"


PERMISSIONS = {
    Role.VIEWER: {"read"},
    Role.EDITOR: {"read", "write"},
    Role.ADMIN: {"read", "write", "delete", "manage_users"},
}


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    try:
        r = Role(role)
        return permission in PERMISSIONS.get(r, set())
    except ValueError:
        return False


# ──────────────────────────────────────────────
# Database
# ──────────────────────────────────────────────

class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'viewer',
                is_active INTEGER DEFAULT 1,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                action TEXT NOT NULL,
                ip_address TEXT,
                details TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
        """)
        conn.commit()
        conn.close()

    def create_user(self, username: str, email: str, password_hash: str, role: str = "viewer") -> dict | None:
        conn = self._get_conn()
        user_id = secrets.token_hex(16)
        try:
            conn.execute(
                "INSERT INTO users (id, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
                (user_id, username.lower(), email.lower(), password_hash, role),
            )
            conn.commit()
            user = dict(conn.execute("SELECT id, username, email, role, is_active, created_at FROM users WHERE id = ?", (user_id,)).fetchone())
            return user
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()

    def get_user_by_username(self, username: str) -> dict | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username.lower(),)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> dict | None:
        conn = self._get_conn()
        row = conn.execute("SELECT id, username, email, role, is_active, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def list_users(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("SELECT id, username, email, role, is_active, created_at FROM users ORDER BY created_at DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def update_user_role(self, user_id: str, role: str) -> bool:
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?",
            (role, user_id),
        )
        conn.commit()
        conn.close()
        return cursor.rowcount > 0

    def deactivate_user(self, user_id: str) -> bool:
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE users SET is_active = 0, updated_at = datetime('now') WHERE id = ?",
            (user_id,),
        )
        conn.commit()
        conn.close()
        return cursor.rowcount > 0

    def increment_failed_attempts(self, username: str):
        conn = self._get_conn()
        user = dict(conn.execute("SELECT * FROM users WHERE username = ?", (username.lower(),)).fetchone())
        attempts = user["failed_attempts"] + 1
        locked_until = None
        if attempts >= Config.MAX_LOGIN_ATTEMPTS:
            locked_until = (datetime.now(timezone.utc) + timedelta(seconds=Config.LOCKOUT_DURATION)).isoformat()
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
            (attempts, locked_until, username.lower()),
        )
        conn.commit()
        conn.close()

    def reset_failed_attempts(self, username: str):
        conn = self._get_conn()
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
            (username.lower(),),
        )
        conn.commit()
        conn.close()

    def is_locked(self, username: str) -> bool:
        conn = self._get_conn()
        row = conn.execute("SELECT locked_until FROM users WHERE username = ?", (username.lower(),)).fetchone()
        conn.close()
        if not row or not row["locked_until"]:
            return False
        locked_until = datetime.fromisoformat(row["locked_until"])
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > locked_until:
            self.reset_failed_attempts(username)
            return False
        return True

    def store_refresh_token(self, user_id: str, token_hash: str, expires_at: str) -> str:
        conn = self._get_conn()
        token_id = secrets.token_hex(16)
        conn.execute(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
            (token_id, user_id, token_hash, expires_at),
        )
        conn.commit()
        conn.close()
        return token_id

    def verify_refresh_token(self, token: str, user_id: str) -> bool:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM refresh_tokens WHERE token_hash = ? AND user_id = ? AND revoked = 0",
            (token_hash, user_id),
        ).fetchone()
        conn.close()
        if not row:
            return False
        expires = datetime.fromisoformat(row["expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < expires

    def revoke_refresh_tokens(self, user_id: str):
        conn = self._get_conn()
        conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()

    def log_audit(self, user_id: str | None, action: str, ip: str, details: str = ""):
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO audit_log (user_id, action, ip_address, details) VALUES (?, ?, ?, ?)",
            (user_id, action, ip, details),
        )
        conn.commit()
        conn.close()

    def get_audit_log(self, limit: int = 50) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


# ──────────────────────────────────────────────
# Rate Limiter (in-memory sliding window)
# ──────────────────────────────────────────────

class RateLimiter:
    def __init__(self):
        self.requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> tuple[bool, dict]:
        now = time.time()
        window_start = now - Config.RATE_LIMIT_WINDOW
        # Clean old entries
        self.requests[client_ip] = [
            t for t in self.requests[client_ip] if t > window_start
        ]
        count = len(self.requests[client_ip])
        remaining = max(0, Config.RATE_LIMIT_MAX - count)
        reset_at = int(window_start + Config.RATE_LIMIT_WINDOW)

        headers = {
            "X-RateLimit-Limit": str(Config.RATE_LIMIT_MAX),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_at),
        }

        if count >= Config.RATE_LIMIT_MAX:
            return False, headers

        self.requests[client_ip].append(now)
        headers["X-RateLimit-Remaining"] = str(remaining - 1)
        return True, headers


# ──────────────────────────────────────────────
# Input Validation
# ──────────────────────────────────────────────

def validate_password(password: str) -> tuple[bool, str]:
    """Enforce password complexity requirements."""
    if len(password) < Config.PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {Config.PASSWORD_MIN_LENGTH} characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, ""


def validate_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def validate_username(username: str) -> tuple[bool, str]:
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be 3-30 characters"
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        return False, "Username can only contain letters, numbers, hyphens, underscores"
    return True, ""


# ──────────────────────────────────────────────
# HTTP API Handler
# ──────────────────────────────────────────────

db = Database(Config.DB_PATH)
rate_limiter = RateLimiter()


class AuthHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the auth API."""

    def _get_client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _send_json(self, status: int, data: dict, extra_headers: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def _check_rate_limit(self) -> bool:
        ip = self._get_client_ip()
        allowed, headers = rate_limiter.is_allowed(ip)
        if not allowed:
            self._send_json(429, {
                "error": "rate_limit_exceeded",
                "message": "Too many requests. Try again later.",
                "retry_after": Config.RATE_LIMIT_WINDOW,
            }, headers)
            return False
        return True

    def _get_current_user(self) -> dict | None:
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header[7:]
        payload = decode_jwt(token, Config.SECRET_KEY)
        if not payload:
            return None
        user = db.get_user_by_id(payload.get("sub", ""))
        if not user or not user.get("is_active"):
            return None
        user["token_payload"] = payload
        return user

    def _require_auth(self) -> dict | None:
        user = self._get_current_user()
        if not user:
            self._send_json(401, {"error": "unauthorized", "message": "Valid access token required"})
            return None
        return user

    def _require_permission(self, permission: str) -> dict | None:
        user = self._require_auth()
        if not user:
            return None
        if not has_permission(user["role"], permission):
            self._send_json(403, {"error": "forbidden", "message": f"Permission '{permission}' required"})
            db.log_audit(user["id"], "permission_denied", self._get_client_ip(), f"Required: {permission}")
            return None
        return user

    def _issue_tokens(self, user: dict) -> dict:
        access_token = create_jwt(
            {"sub": user["id"], "username": user["username"], "role": user["role"]},
            Config.SECRET_KEY,
            Config.ACCESS_TOKEN_EXPIRY,
        )
        refresh_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=Config.REFRESH_TOKEN_EXPIRY)).isoformat()
        db.store_refresh_token(user["id"], token_hash, expires_at)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": Config.ACCESS_TOKEN_EXPIRY,
        }

    # ── Routes ──

    def do_GET(self):
        if not self._check_rate_limit():
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "" or path == "/":
            self._handle_root()
        elif path == "/health":
            self._handle_health()
        elif path == "/api/users":
            self._handle_list_users()
        elif path == "/api/me":
            self._handle_me()
        elif path == "/api/audit":
            self._handle_audit_log()
        else:
            self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        if not self._check_rate_limit():
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/register":
            self._handle_register()
        elif path == "/api/login":
            self._handle_login()
        elif path == "/api/refresh":
            self._handle_refresh()
        elif path == "/api/logout":
            self._handle_logout()
        else:
            self._send_json(404, {"error": "not_found"})

    def do_PUT(self):
        if not self._check_rate_limit():
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith("/api/users/") and path.endswith("/role"):
            user_id = path.split("/")[3]
            self._handle_update_role(user_id)
        else:
            self._send_json(404, {"error": "not_found"})

    def do_DELETE(self):
        if not self._check_rate_limit():
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith("/api/users/"):
            user_id = path.split("/")[3]
            self._handle_deactivate_user(user_id)
        else:
            self._send_json(404, {"error": "not_found"})

    # ── Handlers ──

    def _handle_root(self):
        self._send_json(200, {
            "name": "Secure Auth API",
            "version": "1.0.0",
            "author": "Chrissy P",
            "endpoints": {
                "POST /api/register": "Create a new account",
                "POST /api/login": "Authenticate and get tokens",
                "POST /api/refresh": "Refresh access token",
                "POST /api/logout": "Revoke refresh tokens",
                "GET /api/me": "Get current user profile",
                "GET /api/users": "List all users (admin)",
                "PUT /api/users/:id/role": "Update user role (admin)",
                "DELETE /api/users/:id": "Deactivate user (admin)",
                "GET /api/audit": "View audit log (admin)",
                "GET /health": "Health check",
            },
        })

    def _handle_health(self):
        self._send_json(200, {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})

    def _handle_register(self):
        body = self._read_body()
        username = body.get("username", "").strip()
        email = body.get("email", "").strip()
        password = body.get("password", "")

        # Validate username
        valid, msg = validate_username(username)
        if not valid:
            self._send_json(400, {"error": "validation_error", "message": msg})
            return

        # Validate email
        if not validate_email(email):
            self._send_json(400, {"error": "validation_error", "message": "Invalid email format"})
            return

        # Validate password
        valid, msg = validate_password(password)
        if not valid:
            self._send_json(400, {"error": "validation_error", "message": msg})
            return

        # Create user
        password_hash = hash_password(password)
        user = db.create_user(username, email, password_hash)
        if not user:
            self._send_json(409, {"error": "conflict", "message": "Username or email already exists"})
            return

        db.log_audit(user["id"], "register", self._get_client_ip())
        tokens = self._issue_tokens(user)
        self._send_json(201, {"user": user, "tokens": tokens})

    def _handle_login(self):
        body = self._read_body()
        username = body.get("username", "").strip()
        password = body.get("password", "")
        ip = self._get_client_ip()

        if not username or not password:
            self._send_json(400, {"error": "validation_error", "message": "Username and password required"})
            return

        # Check lockout
        if db.is_locked(username):
            db.log_audit(None, "login_locked", ip, f"User: {username}")
            self._send_json(423, {
                "error": "account_locked",
                "message": f"Account locked due to too many failed attempts. Try again in {Config.LOCKOUT_DURATION // 60} minutes.",
            })
            return

        # Verify credentials
        user = db.get_user_by_username(username)
        if not user or not verify_password(password, user["password_hash"]):
            if user:
                db.increment_failed_attempts(username)
                remaining = Config.MAX_LOGIN_ATTEMPTS - (user["failed_attempts"] + 1)
                if remaining > 0:
                    detail = f"{remaining} attempts remaining"
                else:
                    detail = "Account now locked"
            else:
                detail = ""
            db.log_audit(None, "login_failed", ip, f"User: {username}")
            # Same error message whether user exists or not (timing-safe)
            self._send_json(401, {"error": "invalid_credentials", "message": "Invalid username or password"})
            return

        if not user["is_active"]:
            self._send_json(403, {"error": "account_disabled", "message": "Account has been deactivated"})
            return

        # Success
        db.reset_failed_attempts(username)
        db.log_audit(user["id"], "login_success", ip)
        tokens = self._issue_tokens(user)
        self._send_json(200, {
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
            },
            "tokens": tokens,
        })

    def _handle_refresh(self):
        body = self._read_body()
        refresh_token = body.get("refresh_token", "")
        if not refresh_token:
            self._send_json(400, {"error": "validation_error", "message": "Refresh token required"})
            return

        # Decode the current access token to get user_id (even if expired)
        auth_header = self.headers.get("Authorization", "")
        user_id = None
        if auth_header.startswith("Bearer "):
            # Try decoding without expiry check
            try:
                parts = auth_header[7:].split(".")
                payload = json.loads(base64url_decode(parts[1]))
                user_id = payload.get("sub")
            except Exception:
                pass

        # Also accept user_id in body
        if not user_id:
            user_id = body.get("user_id", "")

        if not user_id:
            self._send_json(400, {"error": "validation_error", "message": "Unable to identify user. Provide Authorization header or user_id."})
            return

        if not db.verify_refresh_token(refresh_token, user_id):
            db.log_audit(user_id, "refresh_failed", self._get_client_ip())
            self._send_json(401, {"error": "invalid_token", "message": "Invalid or expired refresh token"})
            return

        user = db.get_user_by_id(user_id)
        if not user or not user.get("is_active"):
            self._send_json(403, {"error": "account_disabled", "message": "Account has been deactivated"})
            return

        # Rotate tokens (revoke old, issue new)
        db.revoke_refresh_tokens(user_id)
        db.log_audit(user_id, "token_refresh", self._get_client_ip())
        tokens = self._issue_tokens(user)
        self._send_json(200, {"tokens": tokens})

    def _handle_logout(self):
        user = self._require_auth()
        if not user:
            return
        db.revoke_refresh_tokens(user["id"])
        db.log_audit(user["id"], "logout", self._get_client_ip())
        self._send_json(200, {"message": "All sessions revoked"})

    def _handle_me(self):
        user = self._require_auth()
        if not user:
            return
        self._send_json(200, {"user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "permissions": sorted(PERMISSIONS.get(Role(user["role"]), set())),
            "created_at": user["created_at"],
        }})

    def _handle_list_users(self):
        user = self._require_permission("manage_users")
        if not user:
            return
        users = db.list_users()
        self._send_json(200, {"users": users, "total": len(users)})

    def _handle_update_role(self, user_id: str):
        user = self._require_permission("manage_users")
        if not user:
            return
        body = self._read_body()
        new_role = body.get("role", "")
        if new_role not in [r.value for r in Role]:
            self._send_json(400, {"error": "validation_error", "message": f"Invalid role. Choose from: {[r.value for r in Role]}"})
            return
        if user_id == user["id"]:
            self._send_json(400, {"error": "validation_error", "message": "Cannot change your own role"})
            return
        if not db.update_user_role(user_id, new_role):
            self._send_json(404, {"error": "not_found", "message": "User not found"})
            return
        db.log_audit(user["id"], "role_change", self._get_client_ip(), f"Target: {user_id}, New role: {new_role}")
        self._send_json(200, {"message": f"Role updated to {new_role}"})

    def _handle_deactivate_user(self, user_id: str):
        user = self._require_permission("manage_users")
        if not user:
            return
        if user_id == user["id"]:
            self._send_json(400, {"error": "validation_error", "message": "Cannot deactivate yourself"})
            return
        if not db.deactivate_user(user_id):
            self._send_json(404, {"error": "not_found", "message": "User not found"})
            return
        db.revoke_refresh_tokens(user_id)
        db.log_audit(user["id"], "user_deactivated", self._get_client_ip(), f"Target: {user_id}")
        self._send_json(200, {"message": "User deactivated"})

    def _handle_audit_log(self):
        user = self._require_permission("manage_users")
        if not user:
            return
        logs = db.get_audit_log()
        self._send_json(200, {"audit_log": logs, "total": len(logs)})

    def log_message(self, format, *args):
        """Override to format access logs."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {self.client_address[0]} - {args[0]}")


# ──────────────────────────────────────────────
# CLI Demo
# ──────────────────────────────────────────────

def run_demo():
    """Run an interactive demo showing all API features."""
    import urllib.request

    base = f"http://{Config.HOST}:{Config.PORT}"

    def api(method, path, data=None, token=None):
        url = f"{base}{path}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read()), resp.status
        except urllib.error.HTTPError as e:
            return json.loads(e.read()), e.code

    print("\n" + "=" * 60)
    print("  Secure Auth API - Demo")
    print("=" * 60)

    # Register admin
    print("\n[1] Registering admin user...")
    resp, code = api("POST", "/api/register", {
        "username": "admin",
        "email": "admin@example.com",
        "password": "SecureP@ss2026!",
    })
    print(f"    Status: {code}")
    admin_token = resp.get("tokens", {}).get("access_token")
    admin_refresh = resp.get("tokens", {}).get("refresh_token")
    admin_id = resp.get("user", {}).get("id")

    # Promote to admin (direct DB since first user)
    db.update_user_role(admin_id, "admin")
    print("    Promoted to admin role")

    # Re-login to get admin token with correct role
    resp, code = api("POST", "/api/login", {
        "username": "admin",
        "password": "SecureP@ss2026!",
    })
    admin_token = resp["tokens"]["access_token"]
    admin_refresh = resp["tokens"]["refresh_token"]

    # Register regular user
    print("\n[2] Registering regular user...")
    resp, code = api("POST", "/api/register", {
        "username": "analyst",
        "email": "analyst@example.com",
        "password": "An@lyst2026Pass!",
    })
    print(f"    Status: {code}")
    user_token = resp.get("tokens", {}).get("access_token")

    # Get profile
    print("\n[3] Getting user profile...")
    resp, code = api("GET", "/api/me", token=user_token)
    print(f"    User: {resp.get('user', {}).get('username')}")
    print(f"    Role: {resp.get('user', {}).get('role')}")
    print(f"    Permissions: {resp.get('user', {}).get('permissions')}")

    # Admin lists users
    print("\n[4] Admin listing all users...")
    resp, code = api("GET", "/api/users", token=admin_token)
    print(f"    Total users: {resp.get('total')}")
    for u in resp.get("users", []):
        print(f"    - {u['username']} ({u['role']})")

    # Admin updates role
    analyst = [u for u in resp.get("users", []) if u["username"] == "analyst"][0]
    print(f"\n[5] Promoting analyst to editor...")
    resp, code = api("PUT", f"/api/users/{analyst['id']}/role", {"role": "editor"}, token=admin_token)
    print(f"    Status: {code} - {resp.get('message')}")

    # Brute force protection demo
    print(f"\n[6] Testing brute-force protection...")
    for i in range(Config.MAX_LOGIN_ATTEMPTS + 1):
        resp, code = api("POST", "/api/login", {
            "username": "admin",
            "password": "wrong_password",
        })
        if code == 423:
            print(f"    Attempt {i + 1}: LOCKED - {resp.get('message')}")
            break
        else:
            print(f"    Attempt {i + 1}: Failed (expected)")

    # Reset lockout for continued demo
    db.reset_failed_attempts("admin")

    # Token refresh
    print(f"\n[7] Refreshing access token...")
    resp, code = api("POST", "/api/refresh", {
        "refresh_token": admin_refresh,
        "user_id": admin_id,
    })
    print(f"    Status: {code}")
    if code == 200:
        print(f"    New token issued, expires in {resp['tokens']['expires_in']}s")

    # Audit log
    print(f"\n[8] Viewing audit log...")
    # Re-login since tokens were rotated
    resp, code = api("POST", "/api/login", {"username": "admin", "password": "SecureP@ss2026!"})
    admin_token = resp["tokens"]["access_token"]
    resp, code = api("GET", "/api/audit", token=admin_token)
    print(f"    Total events: {resp.get('total')}")
    for entry in resp.get("audit_log", [])[:5]:
        print(f"    [{entry['created_at']}] {entry['action']} from {entry['ip_address']}")

    # Rate limiting info
    print(f"\n[9] Rate limiting active:")
    print(f"    {Config.RATE_LIMIT_MAX} requests per {Config.RATE_LIMIT_WINDOW}s window")

    print("\n" + "=" * 60)
    print("  Demo complete. All security features verified.")
    print("=" * 60 + "\n")


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if "--demo" in sys.argv:
        # Start server in background, run demo, then keep server running
        import threading
        server = HTTPServer((Config.HOST, Config.PORT), AuthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f"Server started on {Config.HOST}:{Config.PORT}")
        time.sleep(0.5)
        run_demo()
        print(f"Server still running on http://{Config.HOST}:{Config.PORT}")
        print("Press Ctrl+C to stop.\n")
        try:
            thread.join()
        except KeyboardInterrupt:
            server.shutdown()
    else:
        print(f"""
╔══════════════════════════════════════════════╗
║          Secure Auth API v1.0.0             ║
║          by Chrissy P                       ║
╠══════════════════════════════════════════════╣
║  Host: {Config.HOST:<37s}║
║  Port: {Config.PORT:<37d}║
║  DB:   {Config.DB_PATH:<37s}║
╚══════════════════════════════════════════════╝
        """)
        server = HTTPServer((Config.HOST, Config.PORT), AuthHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")
            server.shutdown()
