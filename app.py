"""Vault demo server: validated ciphertext storage and optional WebAuthn authorization."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, g, jsonify, request, send_from_directory, session
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from webauthn import (
    generate_authentication_options, generate_registration_options, options_to_json,
    verify_authentication_response, verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference, AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor, ResidentKeyRequirement, UserVerificationRequirement,
)

import fakebank

APP_ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get("VAULT_DB_PATH", APP_ROOT / "demo.db"))
STATIC = Path(__file__).parent / "static"
CHALLENGE_TTL = int(os.environ.get("VAULT_CHALLENGE_TTL", "300"))
SESSION_TTL = int(os.environ.get("VAULT_SESSION_TTL", str(8 * 60 * 60)))
SESSION_IDLE_TTL = int(os.environ.get("VAULT_SESSION_IDLE_TTL", "1800"))
MAX_REQUEST_BYTES = int(os.environ.get("VAULT_MAX_REQUEST_BYTES", str(8 * 1024 * 1024)))
MAX_RECORDS_PER_BATCH = int(os.environ.get("VAULT_MAX_RECORDS_PER_BATCH", "1000"))
MAX_TOTAL_RECORDS = int(os.environ.get("VAULT_MAX_TOTAL_RECORDS", "100000"))
MIN_SEALED_HEX_LENGTH = int(os.environ.get("VAULT_MIN_SEALED_HEX_LENGTH", "96"))
MAX_SEALED_HEX_LENGTH = int(os.environ.get("VAULT_MAX_SEALED_HEX_LENGTH", "16384"))
MAX_JSON_OBJECT_BYTES = int(os.environ.get("VAULT_MAX_JSON_OBJECT_BYTES", str(8 * 1024 * 1024)))
MAX_LABEL_LENGTH = 80
COOKIE_NAME = "vault_session"
TRUST_PROXY = os.environ.get("VAULT_TRUST_PROXY", "0") == "1"
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_HEX = re.compile(r"[0-9a-f]+\Z")
_B64URL = re.compile(r"[A-Za-z0-9_-]{2,1024}\Z")


def _configuration():
    production = os.environ.get("VAULT_ENV", os.environ.get("FLASK_ENV", "development")).lower() == "production"
    policy_raw = os.environ.get("VAULT_AUTH_POLICY")
    policy = policy_raw or ("optional" if not production else "")
    if policy not in {"optional", "required"}:
        raise RuntimeError("VAULT_AUTH_POLICY must be optional or required")
    if production and policy != "required":
        raise RuntimeError("Production requires VAULT_AUTH_POLICY=required")
    secret, rp_id, origin = (os.environ.get(k) for k in ("VAULT_SECRET_KEY", "VAULT_RP_ID", "VAULT_ORIGIN"))
    if production:
        missing = [n for n, v in (("VAULT_SECRET_KEY", secret), ("VAULT_RP_ID", rp_id), ("VAULT_ORIGIN", origin)) if not v]
        if missing:
            raise RuntimeError("Missing production configuration: " + ", ".join(missing))
    origin = origin or "http://localhost:5000"
    parsed = _parse_origin(origin)
    if parsed is None:
        raise RuntimeError("VAULT_ORIGIN must be an origin without path, query, fragment, or user-info")
    if production and parsed[0] != "https":
        raise RuntimeError("VAULT_ORIGIN must use HTTPS in production")
    csp_mode = os.environ.get("VAULT_CSP_MODE", "enforce" if production else "report-only")
    if csp_mode not in {"enforce", "report-only"}:
        raise RuntimeError("VAULT_CSP_MODE must be enforce or report-only")
    if production:
        db_path = DB.resolve(strict=False)
        if not DB.is_absolute() or db_path == APP_ROOT or APP_ROOT in db_path.parents:
            raise RuntimeError("Production VAULT_DB_PATH must be absolute and outside application source")
        if DB.is_symlink() or not DB.parent.exists() or DB.parent.is_symlink():
            raise RuntimeError("Production database parent must exist and database path must not be a symlink")
        if os.name == "posix" and DB.parent.stat().st_mode & 0o002:
            raise RuntimeError("Production database parent must not be world-writable")
    return secret or secrets.token_hex(32), rp_id or "localhost", origin, os.environ.get("VAULT_RP_NAME", "Vault"), production, policy, csp_mode


def _parse_origin(value: str):
    try:
        p = urlsplit(value)
        if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password or p.path or p.query or p.fragment:
            return None
        if p.netloc.endswith(".") or p.hostname != p.hostname.lower():
            return None
        port = p.port or (443 if p.scheme == "https" else 80)
        expected_netloc = p.hostname if port == (443 if p.scheme == "https" else 80) else f"{p.hostname}:{port}"
        if p.netloc != expected_netloc:
            return None
        return p.scheme, p.hostname, port
    except (ValueError, AttributeError):
        return None


SECRET, RP_ID, ORIGIN, RP_NAME, PRODUCTION, AUTH_POLICY, CSP_MODE = _configuration()
EXPECTED_ORIGIN = _parse_origin(ORIGIN)
app = Flask(__name__, static_folder=None)
app.config.update(
    SECRET_KEY=SECRET, MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
    SESSION_COOKIE_NAME=COOKIE_NAME, SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=PRODUCTION,
)
if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)
logging.basicConfig(level=os.environ.get("VAULT_LOG_LEVEL", "INFO"), format="%(message)s")
LOG = logging.getLogger("vault.security")
LOG.info('event="startup" environment="%s" auth_policy="%s" csp_mode="%s" proxy_trust="%s"', "production" if PRODUCTION else "development", AUTH_POLICY, CSP_MODE, int(TRUST_PROXY))
RATE_KEY = hmac.new(SECRET.encode(), b"vault-rate-limit-v1", hashlib.sha256).digest()
RATE_LIMITS = {
    "general": (int(os.environ.get("VAULT_RATE_GENERAL", "120")), 60),
    "session": (int(os.environ.get("VAULT_RATE_SESSION", "60")), 60),
    "login_options": (int(os.environ.get("VAULT_RATE_LOGIN_OPTIONS", "20")), 300),
    "login_verify": (int(os.environ.get("VAULT_RATE_LOGIN_VERIFY", "10")), 600),
    "registration": (int(os.environ.get("VAULT_RATE_REGISTRATION", "10")), 3600),
    "upload": (int(os.environ.get("VAULT_RATE_UPLOAD", "10")), 60),
    "relay": (int(os.environ.get("VAULT_RATE_RELAY", "6")), 60),
    "delete": (int(os.environ.get("VAULT_RATE_DELETE", "3")), 3600),
    "passkey_admin": (int(os.environ.get("VAULT_RATE_PASSKEY_ADMIN", "5")), 3600),
    "logout": (int(os.environ.get("VAULT_RATE_LOGOUT", "30")), 60),
}


def _connect() -> sqlite3.Connection:
    existed = DB.exists()
    conn = sqlite3.connect(DB, timeout=5)
    if PRODUCTION and not existed and os.name == "posix":
        os.chmod(DB, 0o600)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    _migrate(conn)
    return conn


def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = _connect()
    return g.db


def _migrate(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS records (
      id INTEGER PRIMARY KEY, blind_index TEXT NOT NULL UNIQUE,
      sealed TEXT NOT NULL, bytes INTEGER NOT NULL, stored_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vault_identity (
      id INTEGER PRIMARY KEY CHECK (id=1), user_handle TEXT NOT NULL UNIQUE,
      passkey_required INTEGER NOT NULL DEFAULT 0 CHECK(passkey_required IN (0,1)),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS passkey_credentials (
      id INTEGER PRIMARY KEY, identity_id INTEGER NOT NULL, credential_id TEXT NOT NULL UNIQUE,
      credential_public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0,
      transports TEXT NOT NULL DEFAULT '[]', device_type TEXT, backed_up INTEGER,
      label TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_used_at TEXT,
      FOREIGN KEY(identity_id) REFERENCES vault_identity(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS server_sessions (
      session_id_hash TEXT PRIMARY KEY, csrf_token TEXT NOT NULL, identity_id INTEGER,
      authenticated_at REAL, vault_unlocked INTEGER NOT NULL DEFAULT 0,
      active_ceremony_id TEXT, created_at REAL NOT NULL, last_seen_at REAL NOT NULL,
      expires_at REAL NOT NULL, revoked_at REAL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON server_sessions(expires_at, last_seen_at);
    CREATE TABLE IF NOT EXISTS webauthn_challenges (
      ceremony_id TEXT PRIMARY KEY, session_id_hash TEXT NOT NULL, identity_id INTEGER,
      kind TEXT NOT NULL CHECK(kind IN ('registration','authentication')),
      challenge TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL, consumed_at REAL,
      FOREIGN KEY(session_id_hash) REFERENCES server_sessions(session_id_hash)
    );
    CREATE INDEX IF NOT EXISTS idx_challenges_session ON webauthn_challenges(session_id_hash, ceremony_id);
    CREATE TABLE IF NOT EXISTS rate_limits (
      bucket_hash TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL,
      expires_at INTEGER NOT NULL, PRIMARY KEY(bucket_hash,window_start)
    );
    CREATE INDEX IF NOT EXISTS idx_rate_expiry ON rate_limits(expires_at);
    """)
    conn.execute("INSERT OR IGNORE INTO vault_identity(id,user_handle) VALUES(1,?)", (bytes_to_base64url(secrets.token_bytes(32)),))
    conn.commit()


class ServerSession(dict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        super().__init__(initial or {})
        self.sid, self.new, self.modified = sid, new, False


def _sid_hash(sid: str) -> str:
    return hashlib.sha256(sid.encode("ascii")).hexdigest()


class SQLiteSessionInterface(SessionInterface):
    def open_session(self, app, req):
        sid = req.cookies.get(COOKIE_NAME, "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", sid):
            return self._new()
        now = time.time()
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM server_sessions WHERE session_id_hash=?", (_sid_hash(sid),)).fetchone()
        finally:
            conn.close()
        if not row or row["revoked_at"] is not None or row["expires_at"] <= now or row["last_seen_at"] + SESSION_IDLE_TTL <= now:
            return self._new()
        return ServerSession({
            "csrf_token": row["csrf_token"], "identity_id": row["identity_id"],
            "authenticated_at": row["authenticated_at"], "vault_unlocked": bool(row["vault_unlocked"]),
            "active_ceremony_id": row["active_ceremony_id"], "created_at": row["created_at"],
        }, sid=sid)

    def _new(self):
        now = time.time()
        return ServerSession({"csrf_token": secrets.token_urlsafe(32), "created_at": now}, sid=secrets.token_urlsafe(32), new=True)

    def save_session(self, app, sess, response):
        now = time.time()
        conn = _connect()
        try:
            if not sess:
                if getattr(sess, "sid", None):
                    conn.execute("UPDATE server_sessions SET revoked_at=? WHERE session_id_hash=?", (now, _sid_hash(sess.sid)))
                conn.commit()
                response.delete_cookie(COOKIE_NAME, path="/", secure=PRODUCTION, httponly=True, samesite="Strict")
                return
            created = float(sess.get("created_at") or now)
            expires = min(created + SESSION_TTL, now + SESSION_IDLE_TTL)
            conn.execute("""INSERT INTO server_sessions
                (session_id_hash,csrf_token,identity_id,authenticated_at,vault_unlocked,active_ceremony_id,created_at,last_seen_at,expires_at,revoked_at)
                VALUES(?,?,?,?,?,?,?,?,?,NULL)
                ON CONFLICT(session_id_hash) DO UPDATE SET csrf_token=excluded.csrf_token,
                identity_id=excluded.identity_id,authenticated_at=excluded.authenticated_at,
                vault_unlocked=excluded.vault_unlocked,active_ceremony_id=excluded.active_ceremony_id,
                last_seen_at=excluded.last_seen_at,expires_at=excluded.expires_at,revoked_at=NULL""",
                (_sid_hash(sess.sid), sess.get("csrf_token"), sess.get("identity_id"), sess.get("authenticated_at"),
                 int(bool(sess.get("vault_unlocked"))), sess.get("active_ceremony_id"), created, now, expires))
            if secrets.randbelow(100) == 0:
                conn.execute("DELETE FROM webauthn_challenges WHERE expires_at<? OR consumed_at<?", (now - 3600, now - 86400))
                conn.execute("DELETE FROM server_sessions WHERE revoked_at<? OR expires_at<? OR last_seen_at<?", (now-86400, now-86400, now-SESSION_IDLE_TTL-86400))
            conn.commit()
        finally:
            conn.close()
        response.set_cookie(COOKIE_NAME, sess.sid, max_age=SESSION_TTL, httponly=True, secure=PRODUCTION, samesite="Strict", path="/")


app.session_interface = SQLiteSessionInterface()


@app.teardown_appcontext
def _close(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def api_error(message, status):
    return jsonify({"error": message}), status


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    LOG.warning('event="request_rejected" reason="body_too_large"')
    return api_error("Request body is too large", 413)


@app.errorhandler(sqlite3.Error)
def database_error(_error):
    return api_error("The request could not be completed", 503)


@app.before_request
def protect_unsafe_requests():
    if request.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if _parse_origin(request.headers.get("Origin", "")) != EXPECTED_ORIGIN:
            LOG.warning('event="request_rejected" reason="origin" client="%s"', _client_log_id())
            return api_error("Request authorization failed", 403)
        supplied, expected = request.headers.get("X-CSRF-Token", ""), session.get("csrf_token", "")
        if not isinstance(supplied, str) or not supplied or len(supplied) > 128 or not expected or not secrets.compare_digest(supplied, expected):
            LOG.warning('event="request_rejected" reason="csrf" client="%s"', _client_log_id())
            return api_error("Request authorization failed", 403)


def _client_log_id():
    value = request.remote_addr or "unknown"
    return hmac.new(RATE_KEY, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]


def _rate_group():
    path, method = request.path, request.method
    if path == "/api/session": return "session"
    if path == "/api/passkeys/login/options": return "login_options"
    if path == "/api/passkeys/login/verify": return "login_verify"
    if path.startswith("/api/passkeys/register/"): return "registration"
    if path == "/api/records" and method == "POST": return "upload"
    if path == "/api/records" and method == "DELETE": return "delete"
    if path == "/api/relay": return "relay"
    if path == "/api/logout": return "logout"
    if (path.startswith("/api/passkeys/") and method in {"PATCH", "DELETE"}) or path == "/api/passkeys/disable": return "passkey_admin"
    return "general"


def _rate_subject(group):
    ip = request.remote_addr or "unknown"
    identity = session.get("identity_id")
    principal = f"identity:{identity}" if identity else f"session:{_sid_hash(session.sid)}"
    raw = f"{group}|{ip}|{principal}".encode()
    return hmac.new(RATE_KEY, raw, hashlib.sha256).hexdigest()


@app.before_request
def apply_rate_limit():
    if not request.path.startswith("/api/"):
        return None
    group = _rate_group()
    limit, seconds = RATE_LIMITS[group]
    now = int(time.time()); window = now - now % seconds; expires = window + seconds
    conn = db(); conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("""INSERT INTO rate_limits(bucket_hash,window_start,count,expires_at) VALUES(?,?,1,?)
        ON CONFLICT(bucket_hash,window_start) DO UPDATE SET count=count+1 RETURNING count""",
        (_rate_subject(group), window, expires)).fetchone()
    if secrets.randbelow(100) == 0:
        conn.execute("DELETE FROM rate_limits WHERE expires_at<?", (now,))
    conn.commit()
    if row["count"] > limit:
        retry = max(1, expires-now)
        LOG.warning('event="rate_limited" group="%s" client="%s"', group, _client_log_id())
        response = api_error("Request rate limit exceeded", 429)
        response[0].headers["Retry-After"] = str(retry)
        return response


CSP = "; ".join([
    "default-src 'none'", "base-uri 'none'", "object-src 'none'", "frame-ancestors 'none'",
    "form-action 'self'", "script-src 'self' 'wasm-unsafe-eval'", "script-src-attr 'none'",
    "style-src 'self'", "style-src-attr 'none'", "img-src 'self' data:", "font-src 'self'",
    "connect-src 'self'", "worker-src 'self'", "manifest-src 'self'", "media-src 'none'", "frame-src 'none'",
] + (["upgrade-insecure-requests"] if PRODUCTION else []))


@app.after_request
def security_headers(response):
    header = "Content-Security-Policy" if CSP_MODE == "enforce" else "Content-Security-Policy-Report-Only"
    response.headers[header] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()"
    if request.path.startswith("/api/") or request.path == "/" or response.status_code >= 400:
        response.headers["Cache-Control"] = "no-store"
    elif request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=300"
    if PRODUCTION and EXPECTED_ORIGIN[0] == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def identity():
    return db().execute("SELECT * FROM vault_identity WHERE id=1").fetchone()


def auth_required():
    return AUTH_POLICY == "required" or bool(identity()["passkey_required"])


def authenticated():
    when = session.get("authenticated_at")
    return session.get("identity_id") == 1 and isinstance(when, (int, float)) and time.time() - when < SESSION_TTL


def require_access():
    return api_error("Passkey authentication required", 401) if auth_required() and not authenticated() else None


def require_management():
    denied = require_access()
    if denied:
        return denied
    return None if session.get("vault_unlocked") else api_error("Unlock the vault with its passphrase first", 403)


def _rotate_session(**values):
    old_hash = _sid_hash(session.sid)
    conn = db()
    conn.execute("UPDATE server_sessions SET revoked_at=? WHERE session_id_hash=?", (time.time(), old_hash))
    conn.commit()
    session.sid = secrets.token_urlsafe(32)
    session.clear()
    session.update({"csrf_token": secrets.token_urlsafe(32), "created_at": time.time(), **values})
    session.modified = True


def _json_object():
    if request.mimetype != "application/json":
        return None, api_error("Content-Type must be application/json", 400)
    if request.content_length is not None and request.content_length > MAX_JSON_OBJECT_BYTES:
        return None, api_error("JSON body is too large", 413)
    try:
        value = request.get_json(silent=False)
    except RequestEntityTooLarge:
        raise
    except Exception:
        return None, api_error("Malformed JSON", 400)
    if not isinstance(value, dict):
        return None, api_error("JSON body must be an object", 400)
    return value, None


def _new_challenge(kind):
    challenge, ceremony = secrets.token_bytes(32), secrets.token_urlsafe(32)
    conn = db()
    conn.execute("INSERT INTO webauthn_challenges VALUES(?,?,?,?,?,?,?,NULL)",
                 (ceremony, _sid_hash(session.sid), 1 if kind == "registration" else None, kind,
                  bytes_to_base64url(challenge), time.time(), time.time()+CHALLENGE_TTL))
    conn.commit()
    session["active_ceremony_id"] = ceremony
    return challenge


def _take_challenge(kind):
    ceremony = session.pop("active_ceremony_id", None)
    if not ceremony:
        return None
    now, conn = time.time(), db()
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("""UPDATE webauthn_challenges SET consumed_at=?
        WHERE ceremony_id=? AND session_id_hash=? AND kind=? AND consumed_at IS NULL AND expires_at>?
        RETURNING challenge""", (now, ceremony, _sid_hash(session.sid), kind, now)).fetchone()
    conn.commit()
    if not row:
        return None
    try:
        return base64url_to_bytes(row["challenge"])
    except Exception:
        return None


@app.get("/")
def index(): return send_from_directory(STATIC, "index.html")

@app.get("/static/<path:name>")
def static_file(name): return send_from_directory(STATIC, name)

@app.get("/api/session")
def session_status():
    return jsonify({"authenticated": authenticated(), "vault_unlocked": bool(session.get("vault_unlocked")),
                    "csrf_token": session["csrf_token"], "expires_in": SESSION_TTL, "idle_expires_in": SESSION_IDLE_TTL})

@app.post("/api/vault/unlocked")
def mark_unlocked():
    denied = require_access()
    if denied: return denied
    session["vault_unlocked"] = True
    return jsonify({"unlocked": True})

@app.post("/api/logout")
def logout():
    conn = db(); conn.execute("UPDATE server_sessions SET revoked_at=? WHERE session_id_hash=?", (time.time(), _sid_hash(session.sid))); conn.commit()
    session.clear()
    LOG.info('event="session_revoked" client="%s"', _client_log_id())
    return jsonify({"signed_out": True})

@app.post("/api/relay")
def relay():
    denied = require_access()
    return denied or jsonify({"transactions": fakebank.generate(months=6)})

@app.post("/api/records")
def put_records():
    denied = require_access()
    if denied: return denied
    payload, error = _json_object()
    if error: return error
    if set(payload) != {"records"}: return api_error("Body must contain only records", 400)
    rows = payload["records"]
    if not isinstance(rows, list): return api_error("records must be a list", 400)
    if len(rows) > MAX_RECORDS_PER_BATCH: return api_error("Record batch is too large", 413)
    validated, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"blind_index", "sealed"}: return api_error("Invalid record", 400)
        blind, sealed = row["blind_index"], row["sealed"]
        if not isinstance(blind, str) or not _LOWER_HEX_64.fullmatch(blind): return api_error("Invalid record", 400)
        if blind in seen: return api_error("Duplicate record in batch", 400)
        if not isinstance(sealed, str) or not _LOWER_HEX.fullmatch(sealed) or len(sealed)%2 or not MIN_SEALED_HEX_LENGTH <= len(sealed) <= MAX_SEALED_HEX_LENGTH:
            return api_error("Invalid record", 400)
        seen.add(blind); validated.append((blind, sealed, len(bytes.fromhex(sealed))))
    conn = db(); conn.execute("BEGIN IMMEDIATE")
    existing = 0
    if seen:
        placeholders = ",".join("?" for _ in seen)
        existing = conn.execute(f"SELECT COUNT(*) c FROM records WHERE blind_index IN ({placeholders})", tuple(seen)).fetchone()["c"]
    total = conn.execute("SELECT COUNT(*) c FROM records").fetchone()["c"]
    if total + len(validated) - existing > MAX_TOTAL_RECORDS:
        conn.rollback(); return api_error("Vault record quota exceeded", 409)
    conn.executemany("""INSERT INTO records(blind_index,sealed,bytes,stored_at) VALUES(?,?,?,datetime('now','start of day'))
        ON CONFLICT(blind_index) DO UPDATE SET sealed=excluded.sealed,bytes=excluded.bytes""", validated)
    conn.commit()
    return jsonify({"stored": len(validated)})

@app.get("/api/records")
def get_records():
    denied = require_access()
    if denied: return denied
    rows=db().execute("SELECT id,blind_index,sealed FROM records ORDER BY id").fetchall(); return jsonify({"records":[dict(r) for r in rows]})

@app.get("/api/server-view")
def server_view():
    denied=require_access()
    if denied: return denied
    conn=db(); total=conn.execute("SELECT COUNT(*) c FROM records").fetchone()["c"]
    sizes=conn.execute("SELECT bytes,COUNT(*) n FROM records GROUP BY bytes ORDER BY bytes").fetchall(); days=conn.execute("SELECT stored_at d,COUNT(*) n FROM records GROUP BY stored_at ORDER BY stored_at").fetchall(); sample=conn.execute("SELECT blind_index,sealed FROM records ORDER BY id LIMIT 12").fetchall()
    return jsonify({"record_count":total,"size_histogram":[dict(r) for r in sizes],"write_days":[dict(r) for r in days],"sample":[dict(r) for r in sample],"columns":["id","blind_index","sealed","bytes","stored_at"]})

@app.delete("/api/records")
def reset():
    denied=require_access()
    if denied: return denied
    conn=db(); conn.execute("DELETE FROM records"); conn.commit(); return jsonify({"reset":True})

@app.get("/api/passkeys/status")
def passkey_status():
    count=db().execute("SELECT COUNT(*) c FROM passkey_credentials WHERE identity_id=1").fetchone()["c"]
    return jsonify({"passkey_required":auth_required(),"authenticated":authenticated(),"has_usable_passkey":count>0})

@app.post("/api/passkeys/register/options")
def register_options():
    denied=require_management()
    if denied: return denied
    ident=identity(); credentials=db().execute("SELECT credential_id FROM passkey_credentials WHERE identity_id=1").fetchall()
    options=generate_registration_options(rp_id=RP_ID,rp_name=RP_NAME,user_id=base64url_to_bytes(ident["user_handle"]),user_name="local-vault",challenge=_new_challenge("registration"),exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"])) for r in credentials],authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,user_verification=UserVerificationRequirement.REQUIRED),attestation=AttestationConveyancePreference.NONE)
    return app.response_class(options_to_json(options),mimetype="application/json")

@app.post("/api/passkeys/register/verify")
def register_verify():
    denied=require_management()
    if denied: return denied
    challenge=_take_challenge("registration")
    if challenge is None: return api_error("Passkey ceremony could not be verified",400)
    payload,error=_json_object()
    if error: return error
    credential=payload.get("credential"); label=payload.get("label","Passkey")
    if not isinstance(credential,dict) or not isinstance(label,str) or not label.strip() or len(label.strip())>MAX_LABEL_LENGTH: return api_error("Passkey registration could not be verified",400)
    label=label.strip()
    try:
        result=verify_registration_response(credential=credential,expected_challenge=challenge,expected_rp_id=RP_ID,expected_origin=ORIGIN,require_user_verification=True)
        credential_id=bytes_to_base64url(result.credential_id); conn=db(); conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO passkey_credentials(identity_id,credential_id,credential_public_key,sign_count,transports,device_type,backed_up,label) VALUES(1,?,?,?,?,?,?,?)",(credential_id,result.credential_public_key,result.sign_count,json.dumps((credential.get("response") or {}).get("transports",[])),str(result.credential_device_type),int(result.credential_backed_up),label))
        conn.execute("UPDATE vault_identity SET passkey_required=1,updated_at=CURRENT_TIMESTAMP WHERE id=1"); conn.commit()
    except sqlite3.IntegrityError: return api_error("Passkey registration conflict",409)
    except (WebAuthnException,ValueError,KeyError,TypeError):
        LOG.warning('event="authentication_failure" category="registration_verification" client="%s"', _client_log_id())
        return api_error("Passkey registration could not be verified",400)
    _rotate_session(identity_id=1,authenticated_at=time.time(),vault_unlocked=True)
    LOG.info('event="passkey_registered" client="%s"', _client_log_id())
    return jsonify({"verified":True,"csrf_token":session["csrf_token"]})

@app.post("/api/passkeys/login/options")
def login_options():
    rows=db().execute("SELECT credential_id FROM passkey_credentials WHERE identity_id=1").fetchall()
    if not rows: return api_error("Passkey sign-in is unavailable",409)
    options=generate_authentication_options(rp_id=RP_ID,challenge=_new_challenge("authentication"),allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"])) for r in rows],user_verification=UserVerificationRequirement.REQUIRED)
    return app.response_class(options_to_json(options),mimetype="application/json")

@app.post("/api/passkeys/login/verify")
def login_verify():
    challenge=_take_challenge("authentication")
    if challenge is None: return api_error("Passkey ceremony could not be verified",400)
    payload,error=_json_object()
    if error: return error
    credential=payload.get("credential")
    if not isinstance(credential,dict): return api_error("Passkey authentication could not be verified",400)
    credential_id=credential.get("id","")
    if not isinstance(credential_id,str) or not _B64URL.fullmatch(credential_id): return api_error("Passkey authentication could not be verified",400)
    row=db().execute("SELECT * FROM passkey_credentials WHERE credential_id=? AND identity_id=1",(credential_id,)).fetchone()
    if row is None: return api_error("Passkey authentication could not be verified",400)
    try:
        result=verify_authentication_response(credential=credential,expected_challenge=challenge,expected_rp_id=RP_ID,expected_origin=ORIGIN,credential_public_key=row["credential_public_key"],credential_current_sign_count=row["sign_count"],require_user_verification=True)
    except (WebAuthnException,ValueError,KeyError,TypeError):
        LOG.warning('event="authentication_failure" category="assertion_verification" client="%s"', _client_log_id())
        return api_error("Passkey authentication could not be verified",400)
    conn=db(); conn.execute("UPDATE passkey_credentials SET sign_count=?,device_type=?,backed_up=?,last_used_at=CURRENT_TIMESTAMP WHERE id=?",(result.new_sign_count,str(result.credential_device_type),int(result.credential_backed_up),row["id"])); conn.commit()
    _rotate_session(identity_id=1,authenticated_at=time.time())
    LOG.info('event="authentication_success" client="%s"', _client_log_id())
    return jsonify({"authenticated":True,"csrf_token":session["csrf_token"]})

@app.get("/api/passkeys")
def list_passkeys():
    denied=require_management()
    if denied: return denied
    rows=db().execute("SELECT credential_id,label,device_type,backed_up,created_at,last_used_at FROM passkey_credentials WHERE identity_id=1 ORDER BY id").fetchall(); return jsonify({"passkeys":[dict(r) for r in rows]})

def _valid_credential_id(value): return isinstance(value,str) and bool(_B64URL.fullmatch(value))

@app.patch("/api/passkeys/<credential_id>")
def rename_passkey(credential_id):
    denied=require_management()
    if denied: return denied
    if not _valid_credential_id(credential_id): return api_error("Unknown passkey",404)
    payload,error=_json_object()
    if error: return error
    label=payload.get("label")
    if set(payload)!={"label"} or not isinstance(label,str) or not label.strip() or len(label.strip())>MAX_LABEL_LENGTH: return api_error("Invalid passkey label",400)
    cur=db().execute("UPDATE passkey_credentials SET label=? WHERE identity_id=1 AND credential_id=?",(label.strip(),credential_id)); db().commit(); return jsonify({"renamed":True}) if cur.rowcount else api_error("Unknown passkey",404)

@app.delete("/api/passkeys/<credential_id>")
def remove_passkey(credential_id):
    denied=require_management()
    if denied: return denied
    if not _valid_credential_id(credential_id): return api_error("Unknown passkey",404)
    count=db().execute("SELECT COUNT(*) c FROM passkey_credentials WHERE identity_id=1").fetchone()["c"]
    if auth_required() and count<=1: return api_error("Disable protection before removing the final passkey",409)
    cur=db().execute("DELETE FROM passkey_credentials WHERE identity_id=1 AND credential_id=?",(credential_id,)); db().commit()
    if cur.rowcount: LOG.info('event="passkey_removed" client="%s"', _client_log_id())
    return jsonify({"removed":True}) if cur.rowcount else api_error("Unknown passkey",404)

@app.post("/api/passkeys/disable")
def disable_passkeys():
    denied=require_management()
    if denied: return denied
    payload,error=_json_object()
    if error: return error
    if payload!={"confirm_unlocked":True}: return api_error("Unlocked-vault confirmation is required",400)
    if AUTH_POLICY=="required": return api_error("Authentication is required by deployment policy",409)
    db().execute("UPDATE vault_identity SET passkey_required=0,updated_at=CURRENT_TIMESTAMP WHERE id=1"); db().commit()
    _rotate_session(vault_unlocked=True)
    LOG.info('event="passkey_protection_disabled" client="%s"', _client_log_id())
    return jsonify({"disabled":True,"csrf_token":session["csrf_token"]})


if __name__ == "__main__":
    if PRODUCTION:
        raise RuntimeError("Production must run app:app through the supported Gunicorn service")
    host=os.environ.get("VAULT_HOST","127.0.0.1")
    if AUTH_POLICY=="optional" and host not in {"127.0.0.1","::1","localhost"}: raise RuntimeError("Optional authentication may bind only to loopback")
    print(f"vault demo  ->  {ORIGIN}")
    app.run(host=host,port=int(os.environ.get("VAULT_PORT","5000")),debug=False)
