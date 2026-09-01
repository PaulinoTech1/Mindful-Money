"""Vault demo server: validated ciphertext storage and optional WebAuthn authorization."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_from_directory, session
from flask.sessions import SessionInterface, SessionMixin
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from webauthn import (
    generate_authentication_options, generate_registration_options, options_to_json,
    verify_authentication_response, verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes, bytes_to_base64url, parse_authentication_credential_json, parse_authenticator_data,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference, AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor, ResidentKeyRequirement, UserVerificationRequirement,
)

import db as dbmod
import fakebank
import models
import simplefin

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
VAULT_STEPUP_WINDOW_SECONDS = int(os.environ.get("VAULT_STEPUP_WINDOW_SECONDS", "300"))
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
        missing = [n for n, v in (
            ("VAULT_SECRET_KEY", secret), ("VAULT_RP_ID", rp_id), ("VAULT_ORIGIN", origin),
            ("VAULT_DATABASE_URL", os.environ.get("VAULT_DATABASE_URL")),
        ) if not v]
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
# Browsers commonly open the development server through either loopback name.
# Treat only localhost and 127.0.0.1 as equivalent in development; deployed
# origins continue to require an exact scheme, host and port match.
ALLOWED_ORIGINS = {EXPECTED_ORIGIN}
if not PRODUCTION and EXPECTED_ORIGIN[1] in {"localhost", "127.0.0.1"}:
    alias = "127.0.0.1" if EXPECTED_ORIGIN[1] == "localhost" else "localhost"
    ALLOWED_ORIGINS.add((EXPECTED_ORIGIN[0], alias, EXPECTED_ORIGIN[2]))
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

db = dbmod.db
dbmod.init_app(app)


def api_error(message, status):
    return jsonify({"error": message}), status


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    LOG.warning('event="request_rejected" reason="body_too_large"')
    return api_error("Request body is too large", 413)


@app.errorhandler(SQLAlchemyError)
def database_error(_error):
    return api_error("The request could not be completed", 503)


@app.before_request
def protect_unsafe_requests():
    if request.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if _parse_origin(request.headers.get("Origin", "")) not in ALLOWED_ORIGINS:
            LOG.warning('event="request_rejected" reason="origin" client="%s"', _client_log_id())
            return api_error("Request authorization failed", 403)
        supplied, expected = request.headers.get("X-CSRF-Token", ""), session.get("csrf_token", "")
        if not isinstance(supplied, str) or not supplied or len(supplied) > 128 or not expected or not secrets.compare_digest(supplied, expected):
            LOG.warning('event="request_rejected" reason="csrf" client="%s"', _client_log_id())
            return api_error("Request authorization failed", 403)


def _client_log_id():
    value = request.remote_addr or "unknown"
    return hmac.new(RATE_KEY, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]


def _audit_event(event_type, credential_id=None, detail=None):
    """Append-only audit trail. Never commits on its own -- relies on the
    caller's existing commit so the audit row lands atomically with
    whatever state transition it documents. identity_id is always 1: this
    is a single-vault app, so there is only ever one possible subject.
    Never pass a challenge, session token, or public key as detail."""
    table = models.AuditEvent.__table__
    db().execute(insert(table).values(
        event_type=event_type, identity_id=1, client_ref=_client_log_id(),
        credential_id=credential_id, detail=detail,
    ))


def _sign_count_regressed(credential_payload, stored_sign_count) -> bool:
    """Independently replicate the webauthn library's own counter-regression
    check so a SUSPICIOUS_COUNTER_EVENT can be audit-logged regardless of
    which exception (if any) verify_authentication_response ends up raising
    for this request. See webauthn.authentication.verify_authentication_response:
    it raises a generic InvalidAuthenticationResponse for every failure mode,
    with no distinct exception type for a counter regression specifically.
    """
    try:
        parsed = parse_authentication_credential_json(credential_payload)
        auth_data = parse_authenticator_data(parsed.response.authenticator_data)
    except Exception:
        return False
    return (auth_data.sign_count > 0 or stored_sign_count > 0) and auth_data.sign_count <= stored_sign_count


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
    table = models.RateLimit.__table__
    stmt = pg_insert(table).values(bucket_hash=_rate_subject(group), window_start=window, count=1, expires_at=expires)
    stmt = stmt.on_conflict_do_update(
        index_elements=["bucket_hash", "window_start"], set_=dict(count=table.c.count + 1),
    ).returning(table.c.count)
    conn = db()
    count = conn.execute(stmt).scalar_one()
    if secrets.randbelow(100) == 0:
        conn.execute(delete(table).where(table.c.expires_at < now))
    conn.commit()
    if count > limit:
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
    table = models.VaultIdentity.__table__
    return db().execute(select(table).where(table.c.id == 1)).mappings().first()


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


def require_recent_reauth():
    """Extra freshness check for consequential passkey-management actions
    (adding another passkey, removing one, disabling protection), layered
    on top of require_management(). Only meaningful once at least one
    passkey already exists and was used to authenticate this session --
    first-time enrollment has no prior passkey ceremony to be "recent"
    relative to, and stays gated by vault-unlock alone, matching how a
    brand-new installation has no step-up history to check against."""
    table = models.PasskeyCredential.__table__
    has_existing = db().execute(select(func.count()).select_from(table).where(table.c.identity_id == 1)).scalar_one() > 0
    if not has_existing:
        return None
    when = session.get("authenticated_at")
    if not isinstance(when, (int, float)) or time.time() - when > VAULT_STEPUP_WINDOW_SECONDS:
        return api_error("Recent passkey authentication required", 401)
    return None


def _rotate_session(**values):
    old_hash = _sid_hash(session.sid)
    table = models.ServerSession.__table__
    conn = db()
    conn.execute(update(table).where(table.c.session_id_hash == old_hash).values(revoked_at=time.time()))
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
    table = models.WebAuthnChallenge.__table__
    conn = db()
    conn.execute(insert(table).values(
        ceremony_id=ceremony, session_id_hash=_sid_hash(session.sid),
        identity_id=1 if kind == "registration" else None, kind=kind,
        challenge=challenge, created_at=time.time(), expires_at=time.time() + CHALLENGE_TTL, consumed_at=None,
    ))
    conn.commit()
    session["active_ceremony_id"] = ceremony
    return challenge


def _take_challenge(kind):
    ceremony = session.pop("active_ceremony_id", None)
    if not ceremony:
        return None
    now, conn = time.time(), db()
    table = models.WebAuthnChallenge.__table__
    row = conn.execute(
        update(table)
        .where(
            (table.c.ceremony_id == ceremony) & (table.c.session_id_hash == _sid_hash(session.sid))
            & (table.c.kind == kind) & (table.c.consumed_at.is_(None)) & (table.c.expires_at > now)
        )
        .values(consumed_at=now)
        .returning(table.c.challenge)
    ).mappings().first()
    conn.commit()
    if not row:
        return None
    return bytes(row["challenge"])


class ServerSession(dict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        super().__init__(initial or {})
        self.sid, self.new, self.modified = sid, new, False


def _sid_hash(sid: str) -> str:
    return hashlib.sha256(sid.encode("ascii")).hexdigest()


class SQLAlchemySessionInterface(SessionInterface):
    """Server-side sessions backed by Postgres.

    Session open/save use their own dedicated connection, not the
    request's g.db, so cookie/session persistence never depends on
    whatever transaction state a view function left g.db in mid-request.
    """

    def open_session(self, app, req):
        sid = req.cookies.get(COOKIE_NAME, "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", sid):
            return self._new()
        now = time.time()
        table = models.ServerSession.__table__
        with dbmod.get_engine().connect() as conn:
            row = conn.execute(select(table).where(table.c.session_id_hash == _sid_hash(sid))).mappings().first()
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
        table = models.ServerSession.__table__
        challenges = models.WebAuthnChallenge.__table__
        with dbmod.get_engine().begin() as conn:
            if not sess:
                if getattr(sess, "sid", None):
                    conn.execute(update(table).where(table.c.session_id_hash == _sid_hash(sess.sid)).values(revoked_at=now))
                response.delete_cookie(COOKIE_NAME, path="/", secure=PRODUCTION, httponly=True, samesite="Strict")
                return
            created = float(sess.get("created_at") or now)
            expires = min(created + SESSION_TTL, now + SESSION_IDLE_TTL)
            stmt = pg_insert(table).values(
                session_id_hash=_sid_hash(sess.sid), csrf_token=sess.get("csrf_token"),
                identity_id=sess.get("identity_id"), authenticated_at=sess.get("authenticated_at"),
                vault_unlocked=bool(sess.get("vault_unlocked")), active_ceremony_id=sess.get("active_ceremony_id"),
                created_at=created, last_seen_at=now, expires_at=expires, revoked_at=None,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["session_id_hash"],
                set_=dict(
                    csrf_token=stmt.excluded.csrf_token, identity_id=stmt.excluded.identity_id,
                    authenticated_at=stmt.excluded.authenticated_at, vault_unlocked=stmt.excluded.vault_unlocked,
                    active_ceremony_id=stmt.excluded.active_ceremony_id, last_seen_at=stmt.excluded.last_seen_at,
                    expires_at=stmt.excluded.expires_at, revoked_at=stmt.excluded.revoked_at,
                ),
            )
            conn.execute(stmt)
            if secrets.randbelow(100) == 0:
                conn.execute(delete(challenges).where(
                    (challenges.c.expires_at < now - 3600) | (challenges.c.consumed_at < now - 86400)
                ))
                conn.execute(delete(table).where(
                    (table.c.revoked_at < now - 86400) | (table.c.expires_at < now - 86400)
                    | (table.c.last_seen_at < now - SESSION_IDLE_TTL - 86400)
                ))
        response.set_cookie(COOKIE_NAME, sess.sid, max_age=SESSION_TTL, httponly=True, secure=PRODUCTION, samesite="Strict", path="/")


app.session_interface = SQLAlchemySessionInterface()


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
    table = models.ServerSession.__table__
    conn = db()
    conn.execute(update(table).where(table.c.session_id_hash == _sid_hash(session.sid)).values(revoked_at=time.time()))
    _audit_event("SESSION_REVOKED")
    conn.commit()
    session.clear()
    LOG.info('event="session_revoked" client="%s"', _client_log_id())
    return jsonify({"signed_out": True})

@app.get("/api/relay/sources")
def relay_sources():
    return jsonify({"simplefin_available": bool(os.environ.get("SIMPLEFIN_ACCESS_URL"))})

@app.post("/api/relay")
def relay():
    denied = require_access()
    if denied: return denied
    source = "fakebank"
    if request.mimetype == "application/json" and request.data:
        payload, error = _json_object()
        if error: return error
        if set(payload) - {"source"}: return api_error("Unknown field in relay request", 400)
        source = payload.get("source", "fakebank")
        if source not in {"fakebank", "simplefin"}: return api_error("Unknown transaction source", 400)
    if source == "simplefin":
        try:
            transactions = simplefin.generate()
        except simplefin.SimpleFinNotConfigured:
            return api_error("SimpleFin is not configured on this server", 503)
        except simplefin.SimpleFinError:
            LOG.warning('event="simplefin_fetch_failed" client="%s"', _client_log_id())
            return api_error("Could not fetch accounts from SimpleFin", 502)
    else:
        transactions = fakebank.generate(months=6)
    return jsonify({"transactions": transactions})

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
    table = models.Record.__table__
    conn = db()
    existing = 0
    if seen:
        existing = conn.execute(select(func.count()).select_from(table).where(table.c.blind_index.in_(seen))).scalar_one()
    total = conn.execute(select(func.count()).select_from(table)).scalar_one()
    if total + len(validated) - existing > MAX_TOTAL_RECORDS:
        conn.rollback(); return api_error("Vault record quota exceeded", 409)
    if validated:
        # pg_insert(...).values([]) on an empty list degrades to a single
        # DEFAULT VALUES row rather than a no-op, unlike the old
        # executemany() -- guard explicitly so an empty batch stores nothing.
        today = date.today()
        stmt = pg_insert(table).values([
            {"blind_index": blind, "sealed": sealed, "bytes": nbytes, "stored_at": today}
            for blind, sealed, nbytes in validated
        ])
        stmt = stmt.on_conflict_do_update(index_elements=["blind_index"], set_=dict(sealed=stmt.excluded.sealed, bytes=stmt.excluded.bytes))
        conn.execute(stmt)
    conn.commit()
    return jsonify({"stored": len(validated)})

@app.get("/api/records")
def get_records():
    denied = require_access()
    if denied: return denied
    table = models.Record.__table__
    rows = db().execute(select(table.c.id, table.c.blind_index, table.c.sealed).order_by(table.c.id)).mappings().all()
    return jsonify({"records": [dict(r) for r in rows]})

@app.get("/api/server-view")
def server_view():
    denied=require_access()
    if denied: return denied
    table = models.Record.__table__
    conn=db(); total=conn.execute(select(func.count()).select_from(table)).scalar_one()
    sizes=conn.execute(select(table.c.bytes, func.count().label("n")).group_by(table.c.bytes).order_by(table.c.bytes)).mappings().all()
    days=conn.execute(select(table.c.stored_at.label("d"), func.count().label("n")).group_by(table.c.stored_at).order_by(table.c.stored_at)).mappings().all()
    sample=conn.execute(select(table.c.blind_index, table.c.sealed).order_by(table.c.id).limit(12)).mappings().all()
    return jsonify({"record_count":total,"size_histogram":[dict(r) for r in sizes],"write_days":[{"d": r["d"].isoformat(), "n": r["n"]} for r in days],"sample":[dict(r) for r in sample],"columns":["id","blind_index","sealed","bytes","stored_at"]})

@app.delete("/api/records")
def reset():
    denied=require_access()
    if denied: return denied
    table = models.Record.__table__
    conn=db(); conn.execute(delete(table)); conn.commit(); return jsonify({"reset":True})

@app.get("/api/passkeys/status")
def passkey_status():
    table = models.PasskeyCredential.__table__
    count=db().execute(select(func.count()).select_from(table).where(table.c.identity_id==1)).scalar_one()
    return jsonify({"passkey_required":auth_required(),"authenticated":authenticated(),"has_usable_passkey":count>0})

@app.post("/api/passkeys/register/options")
def register_options():
    denied=require_management() or require_recent_reauth()
    if denied: return denied
    table = models.PasskeyCredential.__table__
    ident=identity(); credentials=db().execute(select(table.c.credential_id).where(table.c.identity_id==1)).mappings().all()
    options=generate_registration_options(rp_id=RP_ID,rp_name=RP_NAME,user_id=bytes(ident["user_handle"]),user_name="local-vault",challenge=_new_challenge("registration"),exclude_credentials=[PublicKeyCredentialDescriptor(id=bytes(r["credential_id"])) for r in credentials],authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,user_verification=UserVerificationRequirement.REQUIRED),attestation=AttestationConveyancePreference.NONE)
    return app.response_class(options_to_json(options),mimetype="application/json")

@app.post("/api/passkeys/register/verify")
def register_verify():
    denied=require_management() or require_recent_reauth()
    if denied: return denied
    challenge=_take_challenge("registration")
    if challenge is None: return api_error("Passkey ceremony could not be verified",400)
    payload,error=_json_object()
    if error: return error
    credential=payload.get("credential"); label=payload.get("label","Passkey")
    if not isinstance(credential,dict) or not isinstance(label,str) or not label.strip() or len(label.strip())>MAX_LABEL_LENGTH: return api_error("Passkey registration could not be verified",400)
    label=label.strip()
    conn=db()
    try:
        result=verify_registration_response(credential=credential,expected_challenge=challenge,expected_rp_id=RP_ID,expected_origin=ORIGIN,require_user_verification=True)
        table = models.PasskeyCredential.__table__
        conn.execute(insert(table).values(
            identity_id=1, credential_id=result.credential_id, credential_public_key=result.credential_public_key,
            sign_count=result.sign_count, transports=(credential.get("response") or {}).get("transports", []),
            device_type=str(result.credential_device_type), backed_up=bool(result.credential_backed_up), label=label,
        ))
        identity_table = models.VaultIdentity.__table__
        conn.execute(update(identity_table).where(identity_table.c.id==1).values(passkey_required=True, updated_at=func.now()))
        _audit_event("PASSKEY_REGISTERED", credential_id=result.credential_id, detail={"label": label})
        conn.commit()
    except IntegrityError:
        conn.rollback(); return api_error("Passkey registration conflict",409)
    except (WebAuthnException,ValueError,KeyError,TypeError):
        conn.rollback()
        LOG.warning('event="authentication_failure" category="registration_verification" client="%s"', _client_log_id())
        return api_error("Passkey registration could not be verified",400)
    _rotate_session(identity_id=1,authenticated_at=time.time(),vault_unlocked=True)
    LOG.info('event="passkey_registered" client="%s"', _client_log_id())
    return jsonify({"verified":True,"csrf_token":session["csrf_token"]})

@app.post("/api/passkeys/login/options")
def login_options():
    table = models.PasskeyCredential.__table__
    rows=db().execute(select(table.c.credential_id).where(table.c.identity_id==1)).mappings().all()
    if not rows: return api_error("Passkey sign-in is unavailable",409)
    options=generate_authentication_options(rp_id=RP_ID,challenge=_new_challenge("authentication"),allow_credentials=[PublicKeyCredentialDescriptor(id=bytes(r["credential_id"])) for r in rows],user_verification=UserVerificationRequirement.REQUIRED)
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
    try:
        credential_id_bytes=base64url_to_bytes(credential_id)
    except Exception:
        return api_error("Passkey authentication could not be verified",400)
    table = models.PasskeyCredential.__table__
    row=db().execute(select(table).where((table.c.credential_id==credential_id_bytes)&(table.c.identity_id==1))).mappings().first()
    if row is None: return api_error("Passkey authentication could not be verified",400)
    if _sign_count_regressed(credential, row["sign_count"]):
        _audit_event("SUSPICIOUS_COUNTER_EVENT", credential_id=row["credential_id"], detail={"stored_sign_count": row["sign_count"]})
        db().commit()
        LOG.warning('event="suspicious_counter_event" client="%s"', _client_log_id())
    try:
        result=verify_authentication_response(credential=credential,expected_challenge=challenge,expected_rp_id=RP_ID,expected_origin=ORIGIN,credential_public_key=bytes(row["credential_public_key"]),credential_current_sign_count=row["sign_count"],require_user_verification=True)
    except (WebAuthnException,ValueError,KeyError,TypeError):
        conn=db(); _audit_event("PASSKEY_AUTH_FAILURE", credential_id=row["credential_id"]); conn.commit()
        LOG.warning('event="authentication_failure" category="assertion_verification" client="%s"', _client_log_id())
        return api_error("Passkey authentication could not be verified",400)
    conn=db(); conn.execute(update(table).where(table.c.id==row["id"]).values(sign_count=result.new_sign_count,device_type=str(result.credential_device_type),backed_up=bool(result.credential_backed_up),last_used_at=func.now()))
    _audit_event("PASSKEY_AUTH_SUCCESS", credential_id=row["credential_id"])
    conn.commit()
    _rotate_session(identity_id=1,authenticated_at=time.time())
    LOG.info('event="authentication_success" client="%s"', _client_log_id())
    return jsonify({"authenticated":True,"csrf_token":session["csrf_token"]})

@app.get("/api/passkeys")
def list_passkeys():
    denied=require_management()
    if denied: return denied
    table = models.PasskeyCredential.__table__
    rows=db().execute(select(table.c.credential_id,table.c.label,table.c.device_type,table.c.backed_up,table.c.created_at,table.c.last_used_at).where(table.c.identity_id==1).order_by(table.c.id)).mappings().all()
    return jsonify({"passkeys":[{**dict(r), "credential_id": bytes_to_base64url(bytes(r["credential_id"]))} for r in rows]})

def _valid_credential_id(value): return isinstance(value,str) and bool(_B64URL.fullmatch(value))

@app.patch("/api/passkeys/<credential_id>")
def rename_passkey(credential_id):
    denied=require_management()
    if denied: return denied
    if not _valid_credential_id(credential_id): return api_error("Unknown passkey",404)
    try:
        credential_id_bytes=base64url_to_bytes(credential_id)
    except Exception:
        return api_error("Unknown passkey",404)
    payload,error=_json_object()
    if error: return error
    label=payload.get("label")
    if set(payload)!={"label"} or not isinstance(label,str) or not label.strip() or len(label.strip())>MAX_LABEL_LENGTH: return api_error("Invalid passkey label",400)
    table = models.PasskeyCredential.__table__
    conn=db(); cur=conn.execute(update(table).where((table.c.identity_id==1)&(table.c.credential_id==credential_id_bytes)).values(label=label.strip())); conn.commit()
    return jsonify({"renamed":True}) if cur.rowcount else api_error("Unknown passkey",404)

@app.delete("/api/passkeys/<credential_id>")
def remove_passkey(credential_id):
    denied=require_management() or require_recent_reauth()
    if denied: return denied
    if not _valid_credential_id(credential_id): return api_error("Unknown passkey",404)
    try:
        credential_id_bytes=base64url_to_bytes(credential_id)
    except Exception:
        return api_error("Unknown passkey",404)
    table = models.PasskeyCredential.__table__
    conn=db()
    count=conn.execute(select(func.count()).select_from(table).where(table.c.identity_id==1)).scalar_one()
    if auth_required() and count<=1: return api_error("Disable protection before removing the final passkey",409)
    cur=conn.execute(delete(table).where((table.c.identity_id==1)&(table.c.credential_id==credential_id_bytes)))
    if cur.rowcount: _audit_event("PASSKEY_REMOVED", credential_id=credential_id_bytes)
    conn.commit()
    if cur.rowcount: LOG.info('event="passkey_removed" client="%s"', _client_log_id())
    return jsonify({"removed":True}) if cur.rowcount else api_error("Unknown passkey",404)

@app.post("/api/passkeys/disable")
def disable_passkeys():
    denied=require_management() or require_recent_reauth()
    if denied: return denied
    payload,error=_json_object()
    if error: return error
    if payload!={"confirm_unlocked":True}: return api_error("Unlocked-vault confirmation is required",400)
    if AUTH_POLICY=="required": return api_error("Authentication is required by deployment policy",409)
    table = models.VaultIdentity.__table__
    conn=db(); conn.execute(update(table).where(table.c.id==1).values(passkey_required=False, updated_at=func.now()))
    _audit_event("PASSKEY_PROTECTION_DISABLED")
    conn.commit()
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
