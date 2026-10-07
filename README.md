# Secure Auth API

A production-ready authentication and authorization REST API built from scratch in Python. No frameworks, no dependencies -- just the standard library.

Implements OAuth2 patterns, JWT access/refresh tokens, role-based access control (RBAC), rate limiting, brute-force protection, and full audit logging.

## Features

- **JWT Authentication** -- HMAC-SHA256 signed access tokens (15min) and rotating refresh tokens (7 days)
- **PBKDF2 Password Hashing** -- 100,000 iteration PBKDF2-SHA256 with random salts
- **Role-Based Access Control** -- Viewer, Editor, and Admin roles with granular permissions
- **Brute-Force Protection** -- Account lockout after 5 failed attempts (15min cooldown)
- **Rate Limiting** -- Sliding window rate limiter (30 req/min per IP)
- **Audit Logging** -- Every auth event logged with timestamp, IP, and action
- **Security Headers** -- HSTS, X-Content-Type-Options, X-Frame-Options, no-cache
- **Input Validation** -- Password complexity, email format, username rules
- **Token Rotation** -- Refresh tokens are revoked and reissued on use

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/register` | None | Create account |
| POST | `/api/login` | None | Get tokens |
| POST | `/api/refresh` | None | Rotate tokens |
| POST | `/api/logout` | Bearer | Revoke sessions |
| GET | `/api/me` | Bearer | User profile |
| GET | `/api/users` | Admin | List users |
| PUT | `/api/users/:id/role` | Admin | Change role |
| DELETE | `/api/users/:id` | Admin | Deactivate user |
| GET | `/api/audit` | Admin | Audit log |
| GET | `/health` | None | Health check |

## Quick Start

```bash
# Run the server
python app.py

# Run with interactive demo
python app.py --demo
```

No pip installs. No virtual environment. Just Python 3.10+.

## Demo Output

```
[1] Registering admin user...          Status: 201
[2] Registering regular user...        Status: 201
[3] Getting user profile...            Role: viewer, Permissions: [read]
[4] Admin listing all users...         Total: 2
[5] Promoting analyst to editor...     Status: 200
[6] Testing brute-force protection...  LOCKED after 5 attempts
[7] Refreshing access token...         New token issued
[8] Viewing audit log...               All events tracked
[9] Rate limiting active               30 req/60s window
```

## Security Design Decisions

- **No external dependencies**: Entire auth stack built on Python stdlib to minimize supply chain risk
- **Constant-time comparison**: `hmac.compare_digest` used for all secret comparisons to prevent timing attacks
- **Generic error messages**: Login failures return the same message whether the user exists or not
- **Token rotation**: Refresh tokens are single-use; old tokens are revoked when a new one is issued
- **Self-protection**: Admins cannot change their own role or deactivate themselves
- **Audit trail**: Every authentication event is logged for incident response

## Tech Stack

- Python 3.10+ (standard library only)
- SQLite (WAL mode)
- PBKDF2-SHA256
- HMAC-SHA256 JWT


