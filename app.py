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
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
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
import zkp_verifier

STATIC = Path(__file__).parent / "static"
CHALLENGE_TTL = int(os.environ.get("VAULT_CHALLENGE_TTL", "300"))
ZKP_CHALLENGE_TTL = int(os.environ.get("VAULT_ZKP_CHALLENGE_TTL", "300"))
_DEFAULT_ZKP_CRS_ROOT = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local")) / "MindfulMoney" / "barretenberg-5.1.0" / "crs"
ZKP_CRS_ROOT = Path(os.environ.get("ZKP_CRS_ROOT", _DEFAULT_ZKP_CRS_ROOT))
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
DEFAULT_IDENTITY_ID = 1
COOKIE_NAME = "vault_session"
TRUST_PROXY = os.environ.get("VAULT_TRUST_PROXY", "0") == "1"
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_HEX = re.compile(r"[0-9a-f]+\Z")
_B64URL = re.compile(r"[A-Za-z0-9_-]{2,1024}\Z")
_ERROR_CODE = re.compile(r"MM_SERVER_[A-Z0-9]+(?:_[A-Z0-9]+){3,15}\Z")


def _configuration():
    production = os.environ.get("VAULT_ENV", os.environ.get("FLASK_ENV", "development")).lower() == "production"
    policy_raw = os.environ.get("VAULT_AUTH_POLICY")
    policy = policy_raw or ("required" if not production else "")
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
LOG.info('event="zkp_artifacts_available" available="%s"', int(zkp_verifier.artifacts_available()))
LOG.info('event="zkp_crs_available" available="%s"', int(all((ZKP_CRS_ROOT / name).is_file() for name in ("g1_compressed.dat", "g2.dat", "grumpkin_g1_v2.dat"))))
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
    "zkp_challenge": (int(os.environ.get("VAULT_RATE_ZKP_CHALLENGE", "20")), 300),
    # Proof verification shells out to `bb` -- meaningfully more expensive
    # than ordinary form validation, hence a tighter budget than "upload".
    "zkp_verify": (int(os.environ.get("VAULT_RATE_ZKP_VERIFY", "10")), 300),
    "passkey_admin": (int(os.environ.get("VAULT_RATE_PASSKEY_ADMIN", "5")), 3600),
    "logout": (int(os.environ.get("VAULT_RATE_LOGOUT", "30")), 60),
}

db = dbmod.db
dbmod.init_app(app)


def api_error(message, status, code):
    """Return a safe message plus a stable, origin-oriented diagnostic code.

    Codes follow MM_<SIDE>_<DOMAIN>_<OPERATION>_<CONDITION>. Requiring every
    call site to supply one prevents ambiguous status-only failures from
    silently entering the API. Codes classify the likely layer, but must not
    expose paths, credentials, tenant existence, proof bytes, or verifier
    output.
    """
    if not isinstance(code, str) or _ERROR_CODE.fullmatch(code) is None:
        raise RuntimeError("invalid application error code")
    return jsonify({"error": message, "error_code": code}), status


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    LOG.warning('event="request_rejected" reason="body_too_large"')
    return api_error("Request body is too large", 413, "MM_SERVER_HTTP_REQUEST_BODY_MAXIMUM_SIZE_EXCEEDED")


@app.errorhandler(SQLAlchemyError)
def database_error(_error):
    return api_error("The request could not be completed", 503, "MM_SERVER_DATABASE_REQUEST_EXECUTION_TEMPORARILY_UNAVAILABLE")


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return api_error("API endpoint not found", 404, "MM_SERVER_HTTP_REQUEST_ROUTE_ENDPOINT_NOT_FOUND")
    return error


@app.errorhandler(405)
def method_not_allowed(error):
    if not request.path.startswith("/api/"):
        return error
    response, status = api_error(
        "HTTP method is not allowed for this API endpoint", 405,
        "MM_SERVER_HTTP_REQUEST_ROUTE_METHOD_NOT_ALLOWED",
    )
    if error.valid_methods:
        response.headers["Allow"] = ", ".join(error.valid_methods)
    return response, status


@app.errorhandler(Exception)
def unexpected_error(error):
    if isinstance(error, HTTPException):
        return error
    LOG.exception('event="request_failed" reason="unexpected_application_error"')
    return api_error(
        "The request could not be completed", 500,
        "MM_SERVER_APPLICATION_REQUEST_EXECUTION_UNEXPECTED_FAILURE",
    )


@app.before_request
def protect_unsafe_requests():
    if request.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if _parse_origin(request.headers.get("Origin", "")) not in ALLOWED_ORIGINS:
            LOG.warning('event="request_rejected" reason="origin" client="%s"', _client_log_id())
            return api_error("Request authorization failed", 403, "MM_SERVER_SECURITY_ORIGIN_VALIDATION_REQUEST_REJECTED")
        supplied, expected = request.headers.get("X-CSRF-Token", ""), session.get("csrf_token", "")
        if not isinstance(supplied, str) or not supplied or len(supplied) > 128 or not expected or not secrets.compare_digest(supplied, expected):
            LOG.warning('event="request_rejected" reason="csrf" client="%s"', _client_log_id())
            return api_error("Request authorization failed", 403, "MM_SERVER_SECURITY_CSRF_TOKEN_VALIDATION_REQUEST_REJECTED")


def _client_log_id():
    value = request.remote_addr or "unknown"
    return hmac.new(RATE_KEY, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]


def _audit_event(event_type, credential_id=None, detail=None, identity_id=None):
    """Append-only audit trail. Never commits on its own -- relies on the
    caller's existing commit so the audit row lands atomically with
    whatever state transition it documents. The subject is the authenticated
    tenant (or an explicitly supplied identity during sign-in). Never pass a
    challenge, session token, or public key as detail."""
    table = models.AuditEvent.__table__
    db().execute(insert(table).values(
        event_type=event_type, identity_id=identity_id or current_identity_id(), client_ref=_client_log_id(),
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
    if path == "/api/zkp/challenge": return "zkp_challenge"
    if path == "/api/records/manual": return "zkp_verify"
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
        response = api_error("Request rate limit exceeded", 429, "MM_SERVER_RATE_LIMIT_REQUEST_BUDGET_WINDOW_EXCEEDED")
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
    # Required with COOP for SharedArrayBuffer-backed Barretenberg WASM
    # workers. All application assets are same-origin and also receive
    # Cross-Origin-Resource-Policy below.
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()"
    if request.path.startswith("/api/") or request.path == "/" or response.status_code >= 400:
        response.headers["Cache-Control"] = "no-store"
    elif request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=300"
    if PRODUCTION and EXPECTED_ORIGIN[0] == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def _session_identity_id():
    value = session.get("identity_id")
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def current_identity_id():
    """Return the server-selected tenant for this request.

    Identity 1 is retained only as the backwards-compatible tenant for the
    optional-authentication local demo. Production requires an authenticated
    session, so callers cannot select a tenant through request data.
    """
    return _session_identity_id() or DEFAULT_IDENTITY_ID


def identity(identity_id=None):
    table = models.VaultIdentity.__table__
    owner_id = identity_id or current_identity_id()
    return db().execute(select(table).where(table.c.id == owner_id)).mappings().first()


def auth_required():
    subject = identity()
    return AUTH_POLICY == "required" or bool(subject and subject["passkey_required"])


def authenticated():
    when = session.get("authenticated_at")
    if _session_identity_id() is None or isinstance(when, bool) or not isinstance(when, (int, float)):
        return False
    age = time.time() - when
    return 0 <= age < SESSION_TTL


def require_access():
    return api_error("Passkey authentication required", 401, "MM_SERVER_AUTHORIZATION_SESSION_ACCESS_PASSKEY_AUTHENTICATION_REQUIRED") if auth_required() and not authenticated() else None


def require_client_vault_open():
    """Workflow/UX gate for passkey-management screens.

    ``vault_unlocked`` is asserted by the browser after local decryption. The
    server cannot verify the passphrase or vault key, so this value is not an
    authentication factor and must never authorize destructive operations.
    """
    denied = require_access()
    if denied:
        return denied
    return None if session.get("vault_unlocked") else api_error("Unlock the vault with its passphrase first", 403, "MM_SERVER_VAULT_MANAGEMENT_ACCESS_BROWSER_UNLOCK_REQUIRED")


def require_recent_reauth():
    """Require a recent verified WebAuthn assertion when a passkey exists.

    Callers separately apply their access/workflow gate. First enrollment is
    the sole no-passkey case and therefore has no earlier assertion to check.
    Only login_verify() establishes ``authenticated_at`` in application code.
    """
    table = models.PasskeyCredential.__table__
    owner_id = current_identity_id()
    has_existing = db().execute(select(func.count()).select_from(table).where(table.c.identity_id == owner_id)).scalar_one() > 0
    if not has_existing:
        return None
    when = session.get("authenticated_at")
    if not authenticated() or isinstance(when, bool) or not isinstance(when, (int, float)):
        return api_error("Recent passkey authentication required", 401, "MM_SERVER_AUTHORIZATION_STEP_UP_PASSKEY_AUTHENTICATION_REQUIRED")
    age = time.time() - when
    if age < 0 or age > VAULT_STEPUP_WINDOW_SECONDS:
        return api_error("Recent passkey authentication required", 401, "MM_SERVER_AUTHORIZATION_STEP_UP_PASSKEY_AUTHENTICATION_EXPIRED")
    return None


def require_destructive_management():
    """Authorize irreversible server-side vault management.

    Unlike the browser-reported vault-open hint, this fails closed unless a
    registered passkey exists and this session has a recent, server-verified
    WebAuthn authentication assertion.
    """
    table = models.PasskeyCredential.__table__
    has_passkey = db().execute(
        select(func.count()).select_from(table).where(table.c.identity_id == current_identity_id())
    ).scalar_one() > 0
    if not has_passkey:
        return api_error("A passkey is required for this destructive action", 409, "MM_SERVER_VAULT_DESTRUCTIVE_OPERATION_REGISTERED_PASSKEY_REQUIRED")
    denied = require_access()
    if denied:
        return denied
    if not authenticated():
        return api_error("Passkey authentication required", 401, "MM_SERVER_VAULT_DESTRUCTIVE_OPERATION_PASSKEY_AUTHENTICATION_REQUIRED")
    return require_recent_reauth()


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
        return None, api_error("Content-Type must be application/json", 400, "MM_SERVER_HTTP_JSON_PARSE_APPLICATION_CONTENT_TYPE_REQUIRED")
    if request.content_length is not None and request.content_length > MAX_JSON_OBJECT_BYTES:
        return None, api_error("JSON body is too large", 413, "MM_SERVER_HTTP_JSON_PARSE_MAXIMUM_SIZE_EXCEEDED")
    try:
        value = request.get_json(silent=False)
    except RequestEntityTooLarge:
        raise
    except Exception:
        return None, api_error("Malformed JSON", 400, "MM_SERVER_HTTP_JSON_PARSE_SYNTAX_INVALID")
    if not isinstance(value, dict):
        return None, api_error("JSON body must be an object", 400, "MM_SERVER_HTTP_JSON_PARSE_TOP_LEVEL_OBJECT_REQUIRED")
    return value, None


def _new_challenge(kind, identity_id=None):
    challenge, ceremony = secrets.token_bytes(32), secrets.token_urlsafe(32)
    table = models.WebAuthnChallenge.__table__
    conn = db()
    conn.execute(insert(table).values(
        ceremony_id=ceremony, session_id_hash=_sid_hash(session.sid),
        identity_id=identity_id, kind=kind,
        challenge=challenge, created_at=time.time(), expires_at=time.time() + CHALLENGE_TTL, consumed_at=None,
    ))
    conn.commit()
    session["active_ceremony_id"] = ceremony
    return challenge


def _take_challenge(kind, identity_id=None):
    ceremony = session.pop("active_ceremony_id", None)
    if not ceremony:
        return None
    now, conn = time.time(), db()
    table = models.WebAuthnChallenge.__table__
    conditions = [
        table.c.ceremony_id == ceremony,
        table.c.session_id_hash == _sid_hash(session.sid),
        table.c.kind == kind,
        table.c.consumed_at.is_(None),
        table.c.expires_at > now,
    ]
    if identity_id is not None:
        conditions.append(table.c.identity_id == identity_id)
    row = conn.execute(
        update(table)
        .where(*conditions)
        .values(consumed_at=now)
        .returning(table.c.challenge, table.c.identity_id)
    ).mappings().first()
    conn.commit()
    if not row:
        return None
    return {"challenge": bytes(row["challenge"]), "identity_id": row["identity_id"]}


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

# Vite emits Barretenberg's module workers with root-relative `/assets/...`
# URLs. Keep this route narrow: it exposes only the committed worker assets,
# never the build directory or arbitrary filesystem paths.
@app.get("/assets/<path:name>")
def zkp_asset(name): return send_from_directory(STATIC / "zkp" / "dist" / "assets", name)

# The bb.js browser backend normally fetches these public CRS files from an
# external CDN. Serve the pinned local copy instead so proving does not stall
# on a blocked CDN or disclose browser/network metadata to a third party.
@app.get("/zkp-crs/<path:name>")
def zkp_crs(name):
    if name not in {"g1_compressed.dat", "g2.dat", "grumpkin_g1_v2.dat"}:
        return app.response_class("Not found", status=404, mimetype="text/plain")
    return send_from_directory(ZKP_CRS_ROOT, name, conditional=True, max_age=31536000)

@app.get("/api/session")
def session_status():
    return jsonify({"authenticated": authenticated(), "vault_unlocked": bool(session.get("vault_unlocked")),
                    "csrf_token": session["csrf_token"], "expires_in": SESSION_TTL, "idle_expires_in": SESSION_IDLE_TTL})

@app.post("/api/vault/unlocked")
def mark_unlocked():
    """Record a browser-reported UI state hint, not key possession proof."""
    denied = require_access()
    if denied: return denied
    if request.data:
        return api_error("This endpoint does not accept a request body", 400, "MM_SERVER_VAULT_UNLOCK_STATE_REQUEST_BODY_NOT_ALLOWED")
    # UI state only. This value is asserted by the browser and is NOT proof
    # that the client possesses the vault passphrase or encryption key.
    # Never use it as an authentication factor for destructive operations.
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
    # The legacy environment credential belongs only to the compatibility
    # tenant. Never expose that bank feed to another authenticated identity.
    available = current_identity_id() == DEFAULT_IDENTITY_ID and bool(os.environ.get("SIMPLEFIN_ACCESS_URL"))
    return jsonify({"simplefin_available": available})

@app.post("/api/relay")
def relay():
    denied = require_access()
    if denied: return denied
    owner_id = current_identity_id()
    source = "fakebank"
    if request.mimetype == "application/json" and request.data:
        payload, error = _json_object()
        if error: return error
        if set(payload) - {"source"}: return api_error("Unknown field in relay request", 400, "MM_SERVER_BANK_RELAY_REQUEST_UNKNOWN_FIELD_REJECTED")
        source = payload.get("source", "fakebank")
        if source not in {"fakebank", "simplefin"}: return api_error("Unknown transaction source", 400, "MM_SERVER_BANK_RELAY_SOURCE_ALLOWLIST_VALIDATION_FAILED")
    if source == "simplefin":
        if owner_id != DEFAULT_IDENTITY_ID:
            return api_error("SimpleFin is not configured for this account", 503, "MM_SERVER_BANK_SIMPLEFIN_ACCOUNT_CONFIGURATION_UNAVAILABLE")
        try:
            transactions = simplefin.generate()
        except simplefin.SimpleFinNotConfigured:
            return api_error("SimpleFin is not configured on this server", 503, "MM_SERVER_BANK_SIMPLEFIN_SERVER_CONFIGURATION_UNAVAILABLE")
        except simplefin.SimpleFinAccessRevoked:
            LOG.warning('event="simplefin_fetch_failed" reason="access_revoked" client="%s"', _client_log_id())
            return api_error(
                "SimpleFin declined this connection. The stored access URL may have been "
                "claimed elsewhere or revoked -- disable it and set up SimpleFin again.", 502,
                "MM_SERVER_BANK_SIMPLEFIN_ACCESS_CREDENTIAL_REVOKED_OR_RECLAIMED",
            )
        except simplefin.SimpleFinError:
            LOG.warning('event="simplefin_fetch_failed" client="%s"', _client_log_id())
            return api_error("Could not fetch accounts from SimpleFin", 502, "MM_SERVER_BANK_SIMPLEFIN_ACCOUNT_FETCH_UPSTREAM_REQUEST_FAILED")
    else:
        transactions = fakebank.generate(months=6)
    return jsonify({"transactions": transactions})

@app.post("/api/records")
def put_records():
    denied = require_access()
    if denied: return denied
    owner_id = current_identity_id()
    payload, error = _json_object()
    if error: return error
    if set(payload) != {"records"}: return api_error("Body must contain only records", 400, "MM_SERVER_VAULT_RECORD_BATCH_REQUEST_SCHEMA_INVALID")
    rows = payload["records"]
    if not isinstance(rows, list): return api_error("records must be a list", 400, "MM_SERVER_VAULT_RECORD_BATCH_COLLECTION_TYPE_INVALID")
    if len(rows) > MAX_RECORDS_PER_BATCH: return api_error("Record batch is too large", 413, "MM_SERVER_VAULT_RECORD_BATCH_MAXIMUM_COUNT_EXCEEDED")
    validated, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"blind_index", "sealed"}: return api_error("Invalid record", 400, "MM_SERVER_VAULT_RECORD_WRITE_ENVELOPE_SCHEMA_INVALID")
        blind, sealed = row["blind_index"], row["sealed"]
        if not isinstance(blind, str) or not _LOWER_HEX_64.fullmatch(blind): return api_error("Invalid record", 400, "MM_SERVER_VAULT_RECORD_WRITE_BLIND_INDEX_ENCODING_INVALID")
        if blind in seen: return api_error("Duplicate record in batch", 400, "MM_SERVER_VAULT_RECORD_BATCH_DUPLICATE_BLIND_INDEX_REJECTED")
        if not isinstance(sealed, str) or not _LOWER_HEX.fullmatch(sealed) or len(sealed)%2 or not MIN_SEALED_HEX_LENGTH <= len(sealed) <= MAX_SEALED_HEX_LENGTH:
            return api_error("Invalid record", 400, "MM_SERVER_VAULT_RECORD_WRITE_CIPHERTEXT_ENVELOPE_INVALID")
        seen.add(blind); validated.append((blind, sealed, len(bytes.fromhex(sealed))))
    table = models.Record.__table__
    conn = db()
    existing = 0
    if seen:
        existing = conn.execute(select(func.count()).select_from(table).where(
            (table.c.identity_id == owner_id) & table.c.blind_index.in_(seen)
        )).scalar_one()
    total = conn.execute(select(func.count()).select_from(table).where(table.c.identity_id == owner_id)).scalar_one()
    if total + len(validated) - existing > MAX_TOTAL_RECORDS:
        conn.rollback(); return api_error("Vault record quota exceeded", 409, "MM_SERVER_VAULT_RECORD_STORAGE_TENANT_QUOTA_EXCEEDED")
    if validated:
        # pg_insert(...).values([]) on an empty list degrades to a single
        # DEFAULT VALUES row rather than a no-op, unlike the old
        # executemany() -- guard explicitly so an empty batch stores nothing.
        today = date.today()
        stmt = pg_insert(table).values([
            {"identity_id": owner_id, "blind_index": blind, "sealed": sealed, "bytes": nbytes, "stored_at": today}
            for blind, sealed, nbytes in validated
        ])
        stmt = stmt.on_conflict_do_update(
            index_elements=["identity_id", "blind_index"],
            set_=dict(sealed=stmt.excluded.sealed, bytes=stmt.excluded.bytes),
        )
        conn.execute(stmt)
    conn.commit()
    return jsonify({"stored": len(validated)})

@app.post("/api/zkp/challenge")
def zkp_challenge():
    """Issue a one-time challenge for a manual-transaction ZK proof. See
    zkp/README.md and zkp_verifier.py. The client uses `challenge` and
    `record_id` (both server-generated randomness, hex-encoded) as public
    circuit inputs; Flask re-checks both against this row before ever
    calling the verifier -- see zkp_proof_reject below."""
    denied = require_access()
    if denied: return denied
    payload, error = _json_object()
    if error: return error
    if set(payload) != {"purpose"}: return api_error("Unknown field in challenge request", 400, "MM_SERVER_ZKP_CHALLENGE_CREATE_REQUEST_SCHEMA_INVALID")
    if payload["purpose"] != "manual_expense_create":
        return api_error("Unsupported challenge purpose", 400, "MM_SERVER_ZKP_CHALLENGE_CREATE_PURPOSE_NOT_SUPPORTED")
    if not zkp_verifier.artifacts_available():
        LOG.warning('event="zkp_challenge_unavailable" client="%s"', _client_log_id())
        return api_error(
            "Encrypted-record validation is temporarily unavailable", 503,
            "MM_SERVER_ZKP_CHALLENGE_CREATE_BARRETENBERG_EXECUTABLE_OR_VERIFICATION_KEY_UNAVAILABLE",
        )

    challenge_id = secrets.token_urlsafe(32)
    # 31 bytes, not 32: kept strictly below the BN254 scalar field modulus
    # (~2^254) so the client's big-endian byte-to-Field encoding can never
    # wrap. record_id is intentionally short (16 bytes) -- it only needs
    # to be unguessable, not compressed, so no hash is used; see
    # zkp_verifier.py's module docstring.
    challenge_bytes = secrets.token_bytes(31)
    record_id_bytes = secrets.token_bytes(16)
    now = time.time()
    table = models.ZkpChallenge.__table__
    conn = db()
    conn.execute(insert(table).values(
        challenge_id=challenge_id, identity_id=current_identity_id(), session_id_hash=_sid_hash(session.sid),
        challenge=challenge_bytes, record_id=record_id_bytes,
        purpose="manual_expense_create", circuit_version=zkp_verifier.CIRCUIT_VERSION,
        schema_version=zkp_verifier.SCHEMA_VERSION, created_at=now, expires_at=now + ZKP_CHALLENGE_TTL,
    ))
    conn.commit()
    return jsonify({
        "challenge_id": challenge_id,
        "challenge": challenge_bytes.hex(),
        "record_id": record_id_bytes.hex(),
        "schema_version": zkp_verifier.SCHEMA_VERSION,
        "circuit_version": zkp_verifier.CIRCUIT_VERSION,
        "expires_in": ZKP_CHALLENGE_TTL,
        "categories": list(zkp_verifier.CATEGORY_IDS),
    })

def _claim_zkp_challenge(challenge_id, identity_id):
    """Atomically claim a challenge (single UPDATE ... RETURNING, matching
    _take_challenge()'s existing pattern above): consumed exactly once,
    with no SELECT-then-UPDATE race between two concurrent submissions of
    the same challenge_id. Consuming happens BEFORE proof verification,
    not after: a wasted challenge on an invalid/failed proof is cheap
    (the client just requests another one) and this keeps single-use
    genuinely race-free, which matters more here than being lenient about
    failed attempts. See zkp/README.md."""
    now = time.time()
    table = models.ZkpChallenge.__table__
    conn = db()
    row = conn.execute(
        update(table)
        .where(
            (table.c.challenge_id == challenge_id) & (table.c.session_id_hash == _sid_hash(session.sid))
            & (table.c.identity_id == identity_id)
            & (table.c.purpose == "manual_expense_create") & (table.c.consumed_at.is_(None))
            & (table.c.expires_at > now)
        )
        .values(consumed_at=now)
        .returning(table.c.challenge, table.c.record_id, table.c.schema_version, table.c.circuit_version)
    ).mappings().first()
    conn.commit()
    return row

@app.post("/api/records/manual")
def create_manual_expense_zkp():
    """ZK-proof-gated manual transaction creation. See zkp/README.md for the
    full design and its documented limitation: a valid proof here does NOT
    prove the ciphertext in this same request contains the record the
    proof was computed over -- Flask cannot decrypt `sealed` to check that.
    See that document's "What this circuit does and does not prove"."""
    denied = require_access()
    if denied: return denied
    owner_id = current_identity_id()
    payload, error = _json_object()
    if error: return error
    expected = {"challenge_id", "blind_index", "sealed", "commitment", "proof", "public_inputs"}
    if set(payload) != expected: return api_error("Invalid manual transaction submission", 400, "MM_SERVER_ZKP_MANUAL_TRANSACTION_REQUEST_ENVELOPE_SCHEMA_INVALID")

    challenge_id, blind, sealed, commitment, proof_hex, public_inputs = (
        payload["challenge_id"], payload["blind_index"], payload["sealed"],
        payload["commitment"], payload["proof"], payload["public_inputs"],
    )
    if not isinstance(challenge_id, str) or not challenge_id or len(challenge_id) > 128:
        return api_error("Invalid manual transaction submission", 400, "MM_SERVER_ZKP_MANUAL_TRANSACTION_CHALLENGE_IDENTIFIER_INVALID")
    if not isinstance(blind, str) or not _LOWER_HEX_64.fullmatch(blind):
        return api_error("Invalid record", 400, "MM_SERVER_ZKP_MANUAL_TRANSACTION_BLIND_INDEX_ENCODING_INVALID")
    if not isinstance(sealed, str) or not _LOWER_HEX.fullmatch(sealed) or len(sealed) % 2 \
            or not MIN_SEALED_HEX_LENGTH <= len(sealed) <= MAX_SEALED_HEX_LENGTH:
        return api_error("Invalid record", 400, "MM_SERVER_ZKP_MANUAL_TRANSACTION_CIPHERTEXT_ENVELOPE_INVALID")
    if not isinstance(commitment, str) or not _LOWER_HEX_64.fullmatch(commitment):
        return api_error("Invalid record", 400, "MM_SERVER_ZKP_MANUAL_TRANSACTION_COMMITMENT_ENCODING_INVALID")
    try:
        commitment_field = zkp_verifier.canonical_field_hex(commitment)
    except zkp_verifier.ZkpVerificationError:
        return api_error("Invalid record", 400, "MM_SERVER_ZKP_MANUAL_TRANSACTION_COMMITMENT_FIELD_VALUE_INVALID")
    if not isinstance(proof_hex, str) or not _LOWER_HEX.fullmatch(proof_hex) or len(proof_hex) % 2:
        return api_error("Unable to validate the encrypted record.", 400, "MM_SERVER_ZKP_MANUAL_TRANSACTION_PROOF_HEX_ENCODING_INVALID")
    try:
        public_inputs = zkp_verifier.validate_public_inputs(public_inputs)
    except zkp_verifier.ZkpVerificationError:
        return api_error("Unable to validate the encrypted record.", 400, "MM_SERVER_ZKP_MANUAL_TRANSACTION_PUBLIC_INPUTS_ENCODING_INVALID")

    claimed = _claim_zkp_challenge(challenge_id, owner_id)
    if claimed is None:
        LOG.warning('event="zkp_challenge_rejected" client="%s"', _client_log_id())
        return api_error("Unable to validate the encrypted record.", 400, "MM_SERVER_ZKP_CHALLENGE_CONSUME_UNAVAILABLE_EXPIRED_USED_OR_NOT_OWNED")

    # Independently reconstruct the complete public statement from
    # server-owned challenge data plus the separately validated
    # commitment. Public parameters appear in Noir declaration order and
    # the public return value follows them. Never let the client relabel,
    # omit, reorder, or append fields.
    expected_public_inputs = zkp_verifier.expected_public_inputs(
        challenge=bytes(claimed["challenge"]),
        record_id=bytes(claimed["record_id"]),
        schema_version=claimed["schema_version"],
        commitment=commitment_field,
    )
    if public_inputs != expected_public_inputs or claimed["circuit_version"] != zkp_verifier.CIRCUIT_VERSION:
        LOG.warning('event="zkp_context_mismatch" client="%s"', _client_log_id())
        return api_error("Unable to validate the encrypted record.", 400, "MM_SERVER_ZKP_MANUAL_TRANSACTION_PUBLIC_CONTEXT_OR_CIRCUIT_VERSION_MISMATCH")

    try:
        proof_bytes = bytes.fromhex(proof_hex)
    except ValueError:
        return api_error("Unable to validate the encrypted record.", 400, "MM_SERVER_ZKP_MANUAL_TRANSACTION_PROOF_BINARY_DECODING_FAILED")

    try:
        result = zkp_verifier.verify_proof(proof_bytes, public_inputs)
    except zkp_verifier.CircuitArtifactsUnavailable:
        LOG.warning('event="zkp_verifier_unavailable" client="%s"', _client_log_id())
        return api_error("Unable to validate the encrypted record.", 503, "MM_SERVER_ZKP_BARRETENBERG_VERIFY_EXECUTABLE_OR_VERIFICATION_KEY_UNAVAILABLE")
    except zkp_verifier.ZkpVerificationError:
        LOG.warning('event="zkp_proof_malformed" client="%s"', _client_log_id())
        return api_error("Unable to validate the encrypted record.", 400, "MM_SERVER_ZKP_BARRETENBERG_VERIFY_PROOF_STRUCTURE_OR_EXECUTION_INVALID")

    if not result.valid:
        LOG.warning(
            'event="zkp_proof_invalid" client="%s" duration_ms="%d"',
            _client_log_id(), int(result.duration_seconds * 1000),
        )
        return api_error("Unable to validate the encrypted record.", 400, "MM_SERVER_ZKP_BARRETENBERG_VERIFY_CRYPTOGRAPHIC_PROOF_REJECTED")

    table = models.Record.__table__
    conn = db()
    today = date.today()
    stmt = pg_insert(table).values(
        identity_id=owner_id, blind_index=blind, sealed=sealed, bytes=len(bytes.fromhex(sealed)), stored_at=today,
        commitment=commitment, circuit_version=zkp_verifier.CIRCUIT_VERSION,
    )
    stmt = stmt.on_conflict_do_update(index_elements=["identity_id", "blind_index"], set_=dict(
        sealed=stmt.excluded.sealed, bytes=stmt.excluded.bytes,
        commitment=stmt.excluded.commitment, circuit_version=stmt.excluded.circuit_version,
    ))
    conn.execute(stmt)
    conn.commit()
    LOG.info(
        'event="manual_transaction_created_zkp" client="%s" duration_ms="%d"',
        _client_log_id(), int(result.duration_seconds * 1000),
    )
    return jsonify({"stored": True})

@app.get("/api/records")
def get_records():
    denied = require_access()
    if denied: return denied
    table = models.Record.__table__
    rows = db().execute(select(
        table.c.id, table.c.blind_index, table.c.sealed,
        table.c.commitment, table.c.circuit_version,
    ).where(
        table.c.identity_id == current_identity_id()
    ).order_by(table.c.id)).mappings().all()
    records = []
    for row in rows:
        record = {"id": row["id"], "blind_index": row["blind_index"], "sealed": row["sealed"]}
        if row["commitment"] is not None:
            record["commitment"] = row["commitment"]
            record["circuit_version"] = row["circuit_version"]
        records.append(record)
    return jsonify({"records": records})

@app.get("/api/server-view")
def server_view():
    denied=require_access()
    if denied: return denied
    table = models.Record.__table__
    owner_id = current_identity_id()
    tenant = table.c.identity_id == owner_id
    conn=db(); total=conn.execute(select(func.count()).select_from(table).where(tenant)).scalar_one()
    sizes=conn.execute(select(table.c.bytes, func.count().label("n")).where(tenant).group_by(table.c.bytes).order_by(table.c.bytes)).mappings().all()
    days=conn.execute(select(table.c.stored_at.label("d"), func.count().label("n")).where(tenant).group_by(table.c.stored_at).order_by(table.c.stored_at)).mappings().all()
    sample=conn.execute(select(table.c.blind_index, table.c.sealed).where(tenant).order_by(table.c.id).limit(12)).mappings().all()
    zkp_count = conn.execute(select(func.count()).select_from(table).where(tenant & table.c.commitment.is_not(None))).scalar_one()
    circuits = conn.execute(select(table.c.circuit_version, func.count().label("n")).where(tenant & table.c.circuit_version.is_not(None)).group_by(table.c.circuit_version).order_by(table.c.circuit_version)).mappings().all()
    return jsonify({"record_count":total,"size_histogram":[dict(r) for r in sizes],"write_days":[{"d": r["d"].isoformat(), "n": r["n"]} for r in days],"sample":[dict(r) for r in sample],"zkp_verified_count":zkp_count,"zkp_circuits":[dict(r) for r in circuits],"columns":["id","blind_index","sealed","bytes","stored_at"]})

@app.delete("/api/records")
def reset():
    denied=require_destructive_management()
    if denied: return denied
    table = models.Record.__table__
    owner_id = current_identity_id()
    conn=db(); conn.execute(delete(table).where(table.c.identity_id == owner_id)); conn.commit()
    LOG.info('event="vault_records_deleted" client="%s"', _client_log_id())
    return jsonify({"reset":True})

@app.get("/api/passkeys/status")
def passkey_status():
    table = models.PasskeyCredential.__table__
    count=db().execute(select(func.count()).select_from(table).where(
        table.c.identity_id == current_identity_id()
    )).scalar_one()
    return jsonify({"passkey_required":auth_required(),"authenticated":authenticated(),"has_usable_passkey":count>0})

@app.post("/api/passkeys/register/options")
def register_options():
    denied=require_client_vault_open() or require_recent_reauth()
    if denied: return denied
    owner_id = current_identity_id()
    table = models.PasskeyCredential.__table__
    ident=identity(owner_id); credentials=db().execute(select(table.c.credential_id).where(table.c.identity_id==owner_id)).mappings().all()
    if ident is None:
        return api_error("Account is unavailable", 401, "MM_SERVER_AUTHORIZATION_ACCOUNT_LOOKUP_CURRENT_IDENTITY_UNAVAILABLE")
    options=generate_registration_options(rp_id=RP_ID,rp_name=RP_NAME,user_id=bytes(ident["user_handle"]),user_name=f"vault-{owner_id}",challenge=_new_challenge("registration", owner_id),exclude_credentials=[PublicKeyCredentialDescriptor(id=bytes(r["credential_id"])) for r in credentials],authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,user_verification=UserVerificationRequirement.REQUIRED),attestation=AttestationConveyancePreference.NONE)
    return app.response_class(options_to_json(options),mimetype="application/json")

@app.post("/api/passkeys/register/verify")
def register_verify():
    denied=require_client_vault_open() or require_recent_reauth()
    if denied: return denied
    owner_id = current_identity_id()
    challenge_row=_take_challenge("registration", owner_id)
    if challenge_row is None: return api_error("Passkey ceremony could not be verified",400, "MM_SERVER_PASSKEY_REGISTRATION_CHALLENGE_UNAVAILABLE_EXPIRED_USED_OR_NOT_OWNED")
    challenge = challenge_row["challenge"]
    payload,error=_json_object()
    if error: return error
    credential=payload.get("credential"); label=payload.get("label","Passkey")
    if not isinstance(credential,dict) or not isinstance(label,str) or not label.strip() or len(label.strip())>MAX_LABEL_LENGTH: return api_error("Passkey registration could not be verified",400, "MM_SERVER_PASSKEY_REGISTRATION_CREDENTIAL_OR_LABEL_SCHEMA_INVALID")
    label=label.strip()
    conn=db()
    try:
        result=verify_registration_response(credential=credential,expected_challenge=challenge,expected_rp_id=RP_ID,expected_origin=ORIGIN,require_user_verification=True)
        table = models.PasskeyCredential.__table__
        conn.execute(insert(table).values(
            identity_id=owner_id, credential_id=result.credential_id, credential_public_key=result.credential_public_key,
            sign_count=result.sign_count, transports=(credential.get("response") or {}).get("transports", []),
            device_type=str(result.credential_device_type), backed_up=bool(result.credential_backed_up), label=label,
        ))
        identity_table = models.VaultIdentity.__table__
        conn.execute(update(identity_table).where(identity_table.c.id==owner_id).values(passkey_required=True, updated_at=func.now()))
        _audit_event("PASSKEY_REGISTERED", credential_id=result.credential_id, detail={"label": label})
        conn.commit()
    except IntegrityError:
        conn.rollback(); return api_error("Passkey registration conflict",409, "MM_SERVER_PASSKEY_REGISTRATION_CREDENTIAL_IDENTIFIER_ALREADY_REGISTERED")
    except (WebAuthnException,ValueError,KeyError,TypeError):
        conn.rollback()
        LOG.warning('event="authentication_failure" category="registration_verification" client="%s"', _client_log_id())
        return api_error("Passkey registration could not be verified",400, "MM_SERVER_PASSKEY_REGISTRATION_WEBAUTHN_ATTESTATION_VERIFICATION_FAILED")
    # Registration verifies creation of a credential, not an authentication
    # assertion. Do not make authenticated_at fresh here; the client performs
    # a login assertion next when it needs an authenticated session.
    _rotate_session(identity_id=owner_id,vault_unlocked=True)
    LOG.info('event="passkey_registered" client="%s"', _client_log_id())
    return jsonify({"verified":True,"csrf_token":session["csrf_token"]})

@app.post("/api/passkeys/login/options")
def login_options():
    table = models.PasskeyCredential.__table__
    # During an in-session step-up, offer only that tenant's credentials.
    # A signed-out ceremony may select any registered credential; verify maps
    # the chosen globally unique credential back to its owning identity.
    bound_identity_id = current_identity_id() if authenticated() else None
    query = select(table.c.credential_id)
    if bound_identity_id is not None:
        query = query.where(table.c.identity_id == bound_identity_id)
    rows=db().execute(query).mappings().all()
    if not rows: return api_error("Passkey sign-in is unavailable",409, "MM_SERVER_PASSKEY_AUTHENTICATION_OPTIONS_NO_REGISTERED_CREDENTIAL_AVAILABLE")
    options=generate_authentication_options(rp_id=RP_ID,challenge=_new_challenge("authentication", bound_identity_id),allow_credentials=[PublicKeyCredentialDescriptor(id=bytes(r["credential_id"])) for r in rows],user_verification=UserVerificationRequirement.REQUIRED)
    return app.response_class(options_to_json(options),mimetype="application/json")

@app.post("/api/passkeys/login/verify")
def login_verify():
    challenge_row=_take_challenge("authentication")
    if challenge_row is None: return api_error("Passkey ceremony could not be verified",400, "MM_SERVER_PASSKEY_AUTHENTICATION_CHALLENGE_UNAVAILABLE_EXPIRED_USED_OR_NOT_OWNED")
    challenge = challenge_row["challenge"]
    payload,error=_json_object()
    if error: return error
    credential=payload.get("credential")
    if not isinstance(credential,dict): return api_error("Passkey authentication could not be verified",400, "MM_SERVER_PASSKEY_AUTHENTICATION_CREDENTIAL_ENVELOPE_TYPE_INVALID")
    credential_id=credential.get("id","")
    if not isinstance(credential_id,str) or not _B64URL.fullmatch(credential_id): return api_error("Passkey authentication could not be verified",400, "MM_SERVER_PASSKEY_AUTHENTICATION_CREDENTIAL_IDENTIFIER_ENCODING_INVALID")
    try:
        credential_id_bytes=base64url_to_bytes(credential_id)
    except Exception:
        return api_error("Passkey authentication could not be verified",400, "MM_SERVER_PASSKEY_AUTHENTICATION_CREDENTIAL_IDENTIFIER_DECODING_FAILED")
    table = models.PasskeyCredential.__table__
    row=db().execute(select(table).where(table.c.credential_id==credential_id_bytes)).mappings().first()
    if row is None: return api_error("Passkey authentication could not be verified",400, "MM_SERVER_PASSKEY_AUTHENTICATION_CREDENTIAL_UNKNOWN_OR_NOT_AVAILABLE")
    if challenge_row["identity_id"] is not None and row["identity_id"] != challenge_row["identity_id"]:
        return api_error("Passkey authentication could not be verified",400, "MM_SERVER_PASSKEY_AUTHENTICATION_CREDENTIAL_TENANT_CONTEXT_MISMATCH")
    if _sign_count_regressed(credential, row["sign_count"]):
        _audit_event("SUSPICIOUS_COUNTER_EVENT", credential_id=row["credential_id"], detail={"stored_sign_count": row["sign_count"]}, identity_id=row["identity_id"])
        db().commit()
        LOG.warning('event="suspicious_counter_event" client="%s"', _client_log_id())
    try:
        result=verify_authentication_response(credential=credential,expected_challenge=challenge,expected_rp_id=RP_ID,expected_origin=ORIGIN,credential_public_key=bytes(row["credential_public_key"]),credential_current_sign_count=row["sign_count"],require_user_verification=True)
    except (WebAuthnException,ValueError,KeyError,TypeError):
        conn=db(); _audit_event("PASSKEY_AUTH_FAILURE", credential_id=row["credential_id"], identity_id=row["identity_id"]); conn.commit()
        LOG.warning('event="authentication_failure" category="assertion_verification" client="%s"', _client_log_id())
        return api_error("Passkey authentication could not be verified",400, "MM_SERVER_PASSKEY_AUTHENTICATION_WEBAUTHN_ASSERTION_VERIFICATION_FAILED")
    conn=db(); conn.execute(update(table).where(table.c.id==row["id"]).values(sign_count=result.new_sign_count,device_type=str(result.credential_device_type),backed_up=bool(result.credential_backed_up),last_used_at=func.now()))
    _audit_event("PASSKEY_AUTH_SUCCESS", credential_id=row["credential_id"], identity_id=row["identity_id"])
    conn.commit()
    # Preserve only the browser's non-authoritative UI hint across rotation.
    # Successful verify_authentication_response() above is the sole
    # application path that establishes a fresh authenticated_at timestamp.
    client_vault_open = bool(session.get("vault_unlocked"))
    _rotate_session(identity_id=row["identity_id"],authenticated_at=time.time(),vault_unlocked=client_vault_open)
    LOG.info('event="authentication_success" client="%s"', _client_log_id())
    return jsonify({"authenticated":True,"csrf_token":session["csrf_token"]})

@app.get("/api/passkeys")
def list_passkeys():
    denied=require_client_vault_open()
    if denied: return denied
    table = models.PasskeyCredential.__table__
    rows=db().execute(select(table.c.credential_id,table.c.label,table.c.device_type,table.c.backed_up,table.c.created_at,table.c.last_used_at).where(table.c.identity_id==current_identity_id()).order_by(table.c.id)).mappings().all()
    return jsonify({"passkeys":[{**dict(r), "credential_id": bytes_to_base64url(bytes(r["credential_id"]))} for r in rows]})

def _valid_credential_id(value): return isinstance(value,str) and bool(_B64URL.fullmatch(value))

@app.patch("/api/passkeys/<credential_id>")
def rename_passkey(credential_id):
    denied=require_client_vault_open()
    if denied: return denied
    if not _valid_credential_id(credential_id): return api_error("Unknown passkey",404, "MM_SERVER_PASSKEY_MANAGEMENT_CREDENTIAL_IDENTIFIER_ENCODING_INVALID")
    try:
        credential_id_bytes=base64url_to_bytes(credential_id)
    except Exception:
        return api_error("Unknown passkey",404, "MM_SERVER_PASSKEY_MANAGEMENT_CREDENTIAL_IDENTIFIER_DECODING_FAILED")
    payload,error=_json_object()
    if error: return error
    label=payload.get("label")
    if set(payload)!={"label"} or not isinstance(label,str) or not label.strip() or len(label.strip())>MAX_LABEL_LENGTH: return api_error("Invalid passkey label",400, "MM_SERVER_PASSKEY_MANAGEMENT_RENAME_LABEL_SCHEMA_INVALID")
    table = models.PasskeyCredential.__table__
    conn=db(); cur=conn.execute(update(table).where((table.c.identity_id==current_identity_id())&(table.c.credential_id==credential_id_bytes)).values(label=label.strip())); conn.commit()
    return jsonify({"renamed":True}) if cur.rowcount else api_error("Unknown passkey",404, "MM_SERVER_PASSKEY_MANAGEMENT_RENAME_CREDENTIAL_NOT_FOUND_FOR_TENANT")

@app.delete("/api/passkeys/<credential_id>")
def remove_passkey(credential_id):
    denied=require_client_vault_open() or require_recent_reauth()
    if denied: return denied
    if not _valid_credential_id(credential_id): return api_error("Unknown passkey",404, "MM_SERVER_PASSKEY_MANAGEMENT_CREDENTIAL_IDENTIFIER_ENCODING_INVALID")
    try:
        credential_id_bytes=base64url_to_bytes(credential_id)
    except Exception:
        return api_error("Unknown passkey",404, "MM_SERVER_PASSKEY_MANAGEMENT_CREDENTIAL_IDENTIFIER_DECODING_FAILED")
    table = models.PasskeyCredential.__table__
    conn=db()
    owner_id = current_identity_id()
    count=conn.execute(select(func.count()).select_from(table).where(table.c.identity_id==owner_id)).scalar_one()
    if auth_required() and count<=1: return api_error("Disable protection before removing the final passkey",409, "MM_SERVER_PASSKEY_MANAGEMENT_REMOVE_FINAL_REQUIRED_CREDENTIAL_BLOCKED")
    cur=conn.execute(delete(table).where((table.c.identity_id==owner_id)&(table.c.credential_id==credential_id_bytes)))
    if cur.rowcount: _audit_event("PASSKEY_REMOVED", credential_id=credential_id_bytes)
    conn.commit()
    if cur.rowcount: LOG.info('event="passkey_removed" client="%s"', _client_log_id())
    return jsonify({"removed":True}) if cur.rowcount else api_error("Unknown passkey",404, "MM_SERVER_PASSKEY_MANAGEMENT_REMOVE_CREDENTIAL_NOT_FOUND_FOR_TENANT")

@app.post("/api/passkeys/disable")
def disable_passkeys():
    denied=require_client_vault_open() or require_recent_reauth()
    if denied: return denied
    payload,error=_json_object()
    if error: return error
    if payload!={"confirm_unlocked":True}: return api_error("Unlocked-vault confirmation is required",400, "MM_SERVER_PASSKEY_MANAGEMENT_DISABLE_UNLOCK_CONFIRMATION_REQUIRED")
    if AUTH_POLICY=="required": return api_error("Authentication is required by deployment policy",409, "MM_SERVER_PASSKEY_MANAGEMENT_DISABLE_DEPLOYMENT_POLICY_REQUIRES_AUTHENTICATION")
    owner_id = current_identity_id()
    table = models.VaultIdentity.__table__
    conn=db(); conn.execute(update(table).where(table.c.id==owner_id).values(passkey_required=False, updated_at=func.now()))
    _audit_event("PASSKEY_PROTECTION_DISABLED")
    conn.commit()
    _rotate_session(identity_id=owner_id,vault_unlocked=True)
    LOG.info('event="passkey_protection_disabled" client="%s"', _client_log_id())
    return jsonify({"disabled":True,"csrf_token":session["csrf_token"]})


if __name__ == "__main__":
    if PRODUCTION:
        raise RuntimeError("Production must run app:app through the supported Gunicorn service")
    host=os.environ.get("VAULT_HOST","127.0.0.1")
    if AUTH_POLICY=="optional" and host not in {"127.0.0.1","::1","localhost"}: raise RuntimeError("Optional authentication may bind only to loopback")
    print(f"vault demo  ->  {ORIGIN}")
    app.run(host=host,port=int(os.environ.get("VAULT_PORT","5000")),debug=False)
