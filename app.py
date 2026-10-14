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
from sqlalchemy import delete, func, insert, literal, select, text, update
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
import models
import zkp_verifier

STATIC = Path(__file__).parent / "static"
CHALLENGE_TTL = int(os.environ.get("VAULT_CHALLENGE_TTL", "300"))
ZKP_CHALLENGE_TTL = int(os.environ.get("VAULT_ZKP_CHALLENGE_TTL", "300"))
SESSION_TTL = int(os.environ.get("VAULT_SESSION_TTL", str(4 * 60 * 60)))
# Strict: 4 hour absolute max (was 8h). Prevents long-lived session takeover.
SESSION_IDLE_TTL = int(os.environ.get("VAULT_SESSION_IDLE_TTL", "900"))
# Strict: 15 minute idle timeout (was 30min). Reduces window for session hijacking.
MAX_REQUEST_BYTES = int(os.environ.get("VAULT_MAX_REQUEST_BYTES", str(8 * 1024 * 1024)))
# 500 so the worst-case batch fits MAX_REQUEST_BYTES by construction:
# 14 + 500 * 16575 = 8,287,514 <= 8,388,608 (derivation: README "Ciphertext and resource limits").
MAX_RECORDS_PER_BATCH = int(os.environ.get("VAULT_MAX_RECORDS_PER_BATCH", "500"))
MAX_TOTAL_RECORDS = int(os.environ.get("VAULT_MAX_TOTAL_RECORDS", "100000"))
MIN_SEALED_HEX_LENGTH = int(os.environ.get("VAULT_MIN_SEALED_HEX_LENGTH", "96"))
# Largest client bucket (static/app.js PAD_BUCKETS) is 8192 bytes; a NaCl
# sealed box adds crypto_box_SEALBYTES = 48 (ephemeral public key 32 + MAC 16),
# so the largest ciphertext is 8240 bytes = 16480 hex characters.
MAX_SEALED_HEX_LENGTH = int(os.environ.get("VAULT_MAX_SEALED_HEX_LENGTH", "16480"))
KDF_VERSIONS = frozenset({1, 2, 3})
MAX_JSON_OBJECT_BYTES = int(os.environ.get("VAULT_MAX_JSON_OBJECT_BYTES", str(8 * 1024 * 1024)))
MAX_LABEL_LENGTH = 80
VAULT_STEPUP_WINDOW_SECONDS = int(os.environ.get("VAULT_STEPUP_WINDOW_SECONDS", "300"))
DEFAULT_IDENTITY_ID = 1
TRUST_PROXY = os.environ.get("VAULT_TRUST_PROXY", "0") == "1"
# Opt-in IP address logging. Default off for privacy.
# When "on", the full client IP is stored in audit_events.client_ip.
# When "off" (default), only the HMAC-truncated client_ref is stored.
IP_LOGGING = os.environ.get("VAULT_IP_LOGGING", "off").lower() == "on"

# ASN lookup for honeypot hits. Uses bundled GeoLite2-ASN database (free, local file).
# Zero per-query cost, microseconds per lookup. Only used when IP_LOGGING is on.
_ASN_READER = None
def _get_asn_reader():
    """Lazy-load the GeoLite2-ASN database. Returns None if unavailable."""
    global _ASN_READER
    if _ASN_READER is None:
        try:
            import maxminddb
            import os
            db_path = os.path.join(os.path.dirname(__file__), "geoip", "GeoLite2-ASN.mmdb")
            if os.path.exists(db_path):
                _ASN_READER = maxminddb.open_database(db_path)
        except Exception:
            pass
    return _ASN_READER

def _lookup_asn(ip_address):
    """Look up ASN for an IP. Returns (asn_number, asn_org) or (None, None).
    Only call when IP_LOGGING is on."""
    if not IP_LOGGING or not ip_address:
        return None, None
    try:
        reader = _get_asn_reader()
        if not reader:
            return None, None
        result = reader.get(ip_address)
        if result:
            return result.get("autonomous_system_number"), result.get("autonomous_system_organization")
    except Exception:
        pass
    return None, None
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_HEX = re.compile(r"[0-9a-f]+\Z")
_LOWER_HEX_CHARS = frozenset("0123456789abcdef")


def _is_lower_hex(value: str) -> bool:
    """Non-empty lowercase hex, checked without a regex (linear, no backtracking)."""
    return bool(value) and set(value) <= _LOWER_HEX_CHARS
_B64URL = re.compile(r"[A-Za-z0-9_-]{2,1024}\Z")


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

# __Host- prefix in production (requires Secure + Path=/ + no Domain).
# In development (HTTP), __Host- cookies are rejected by browsers,
# so we use the plain name there.
COOKIE_NAME = "__Host-vault_session" if PRODUCTION else "vault_session"
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
RATE_KEY = hmac.new(SECRET.encode(), b"vault-rate-limit-v1", hashlib.sha256).digest()
RATE_LIMITS = {
    "general": (int(os.environ.get("VAULT_RATE_GENERAL", "120")), 60),
    "session": (int(os.environ.get("VAULT_RATE_SESSION", "60")), 60),
    "login_options": (int(os.environ.get("VAULT_RATE_LOGIN_OPTIONS", "20")), 300),
    "login_verify": (int(os.environ.get("VAULT_RATE_LOGIN_VERIFY", "10")), 600),
    "registration": (int(os.environ.get("VAULT_RATE_REGISTRATION", "10")), 3600),
    # 60 per minute per identity (anonymous: per client IP). Derivation:
    # README "Ciphertext and resource limits".
    "upload": (int(os.environ.get("VAULT_RATE_UPLOAD", "60")), 60),
    # Rekey begin/commit/abort and recovery blob fetch/delete: a handful per
    # recovery; 10 and 20 per hour leave room for retries.
    "rekey": (int(os.environ.get("VAULT_RATE_REKEY", "10")), 3600),
    "recovery": (int(os.environ.get("VAULT_RATE_RECOVERY", "20")), 3600),
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


def api_error(message, status):
    return jsonify({"error": message}), status


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    LOG.warning('event="request_rejected" reason="body_too_large"')
    return api_error("Request body is too large", 413)


# Redaction for DB error logging. Patterns are applied in order to the
# FIRST LINE of the driver error only. SQLAlchemy's str(error) appends
# "[SQL: ...]" and "[parameters: ...]", so it is never logged.
_REDACT_PATTERNS = [
    (re.compile(r"[a-z][a-z0-9+.\-]*://\S+", re.I), "<url>"),
    (re.compile(r"\b(password|passwd|pwd|user|host|hostaddr|dbname|sslpassword)\s*=\s*('[^']*'|\S+)", re.I), r"\1=<redacted>"),
    (re.compile(r"\b[\w.+\-]+@[\w.\-]+(:\d+)?", re.I), "<user@host>"),
    (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b"), "<ip>"),
    (re.compile(r'\b(?:host|server|address)(?:\s+at)?\s+"?[\w.\-]+"?', re.I), "host <redacted>"),
    # Any remaining dotted hostname (a.b.c or longer), quoted or not.
    (re.compile(r"\b[a-z0-9\-_]+(?:\.[a-z0-9\-_]+){2,}\b", re.I), "<host>"),
    (re.compile(r"\b(?:user|role)\s+\"[^\"]*\"", re.I), "user <redacted>"),
    (re.compile(r"\[(?:SQL|parameters):.*", re.I | re.S), "<stmt>"),
    (re.compile(r"\([^()]*\)=\([^()]*\)"), "(<key>)=(<redacted>)"),
]


def _redact_db_detail(error, limit=200):
    """Class names, SQLSTATE, and a redacted first line. Never the URL,
    statement, or bound parameters."""
    orig = getattr(error, "orig", None)
    source = orig if orig is not None else error
    try:
        raw = str(source)
    except Exception:
        raw = ""
    first = (raw.strip().splitlines() or [""])[0]
    for pattern, repl in _REDACT_PATTERNS:
        first = pattern.sub(repl, first)
    first = first.replace('"', "'")[:limit]
    sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None) or getattr(error, "code", None) or ""
    return {
        "cls": type(error).__name__,
        "orig_cls": type(orig).__name__ if orig is not None else "",
        "sqlstate": str(sqlstate)[:16],
        "detail": first,
    }


@app.errorhandler(SQLAlchemyError)
def database_error(error):
    # Fail loudly to the operator, generically to the client.
    # See docs/CLOUD_RUN_TROUBLESHOOTING.md "_seed_identity NotNullViolation".
    info = _redact_db_detail(error)
    LOG.error('event="db_error" class="%s" orig_class="%s" sqlstate="%s" path="%s" detail="%s"',
              info["cls"], info["orig_cls"], info["sqlstate"], request.path, info["detail"])
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


def _audit_event(event_type, credential_id=None, detail=None, identity_id=None):
    """Append-only audit trail. Never commits on its own -- relies on the
    caller's existing commit so the audit row lands atomically with
    whatever state transition it documents. The subject is the authenticated
    tenant (or an explicitly supplied identity during sign-in). Never pass a
    challenge, session token, or public key as detail."""
    table = models.AuditEvent.__table__
    # Opt-in IP logging: store full IP only when VAULT_IP_LOGGING=on
    client_ip = None
    if IP_LOGGING:
        client_ip = request.remote_addr
    db().execute(insert(table).values(
        event_type=event_type, identity_id=identity_id or current_identity_id(), client_ref=_client_log_id(),
        credential_id=credential_id, detail=detail, client_ip=client_ip,
    ))
    # Webhook alerting for critical security events (fire-and-forget)
    if event_type in ("HONEYPOT_HIT", "ACCOUNT_LOCKED", "SUSPICIOUS_COUNTER_EVENT"):
        _send_security_webhook(event_type, detail)


def _send_security_webhook(event_type, detail=None):
    """Send a webhook alert for critical security events.
    Configured via VAULT_SECURITY_WEBHOOK_URL env var.
    Failures are logged but don't block the request."""
    webhook_url = os.environ.get("VAULT_SECURITY_WEBHOOK_URL")
    if not webhook_url:
        return
    try:
        import urllib.request, json
        payload = json.dumps({
            "event": event_type,
            "timestamp": time.time(),
            "detail": detail,
            "client_ref": _client_log_id(),
        }).encode()
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        # Short timeout; don't block the request on webhook
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        LOG.warning('event="webhook_failed" error="%s"', str(e)[:100])


def _log_detection(detection_type, detail=None):
    """Log a detection event from the unusual activity detector.
    Always audit-logged regardless of IP logging setting."""
    _audit_event("UNUSUAL_ACTIVITY_DETECTED", detail={
        "detection_type": detection_type,
        **(detail or {}),
    })
    LOG.warning('event="unusual_activity_detected" type="%s" client="%s"', detection_type, _client_log_id())


def _is_account_locked(identity_id) -> bool:
    """Check if account is locked due to too many failed logins.
    Lockout: 5+ failures in 15 minutes = locked for 30 minutes."""
    table = models.AuditEvent.__table__
    fifteen_min_ago = func.now() - text("INTERVAL '15 minutes'")
    failure_count = db().execute(
        select(func.count().label("count"))
        .where(
            table.c.identity_id == identity_id,
            table.c.event_type == "PASSKEY_AUTH_FAILURE",
            table.c.occurred_at >= fifteen_min_ago,
        )
    ).scalar() or 0
    if failure_count >= 5:
        # Check if there's a recent lockout that hasn't expired
        thirty_min_ago = func.now() - text("INTERVAL '30 minutes'")
        recent_lockout = db().execute(
            select(func.count().label("count"))
            .where(
                table.c.identity_id == identity_id,
                table.c.event_type == "ACCOUNT_LOCKED",
                table.c.occurred_at >= thirty_min_ago,
            )
        ).scalar() or 0
        if recent_lockout == 0:
            # First lockout in this window, log it
            _audit_event("ACCOUNT_LOCKED", identity_id=identity_id,
                         detail={"failure_count": failure_count})
            db().commit()
        return True
    return False


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
    if path == "/api/vault/rekey/records": return "upload"
    if path.startswith("/api/vault/rekey/"): return "rekey"
    if path in {"/api/recovery/blob", "/api/recovery/delete"}: return "recovery"
    if path == "/api/records" and method == "DELETE": return "delete"
    if path == "/api/zkp/challenge": return "zkp_challenge"
    if path == "/api/records/manual": return "zkp_verify"
    if path == "/api/logout": return "logout"
    if (path.startswith("/api/passkeys/") and method in {"PATCH", "DELETE"}) or path == "/api/passkeys/disable": return "passkey_admin"
    return "general"


def _rate_subject(group):
    """Rate limit bucket key.
    
    Authenticated: keyed by identity ID (per-account limits).
    Unauthenticated: keyed by client IP via _client_log_id() (trusted remote_addr).
    
    Previously used session ID for anonymous users, which allowed budget reset
    by clearing cookies. Now uses the client IP so anonymous abuse is tracked
    consistently regardless of session rotation.
    """
    identity = session.get("identity_id")
    if identity:
        principal = f"identity:{identity}"
    else:
        # Anonymous: use trusted client IP, not session ID
        # _client_log_id() is HMAC(remote_addr), not spoofable via headers
        principal = f"anon:{_client_log_id()}"
    raw = f"{group}|{principal}".encode()
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
    # connect-src allows https: (not just 'self') because SimpleFin bridge
    # fetches happen client-side directly to user-configured bridge hosts.
    # The client validates HTTPS and refuses redirects. Server never sees
    # the access URL or plaintext.
    "connect-src 'self' https:", "worker-src 'self'", "manifest-src 'self'", "media-src 'none'", "frame-src 'none'",
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
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
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
    return api_error("Passkey authentication required", 401) if auth_required() and not authenticated() else None


def require_client_vault_open():
    """Workflow/UX gate for passkey-management screens.

    ``vault_unlocked`` is asserted by the browser after local decryption. The
    server cannot verify the passphrase or vault key, so this value is not an
    authentication factor and must never authorize destructive operations.
    """
    denied = require_access()
    if denied:
        return denied
    return None if session.get("vault_unlocked") else api_error("Unlock the vault with its passphrase first", 403)


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
        return api_error("Recent passkey authentication required", 401)
    age = time.time() - when
    if age < 0 or age > VAULT_STEPUP_WINDOW_SECONDS:
        return api_error("Recent passkey authentication required", 401)
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
        return api_error("A passkey is required for this destructive action", 409)
    denied = require_access()
    if denied:
        return denied
    if not authenticated():
        return api_error("Passkey authentication required", 401)
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
        # Ceremony id as loaded, so save_session can tell whether THIS request
        # changed it (bug F: a concurrent request must not clobber it).
        self.loaded_ceremony_id = self.get("active_ceremony_id")


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
            # Only a request that started or consumed a ceremony writes
            # active_ceremony_id; any other request keeps the stored value, so
            # an overlapping request on the same session (e.g. a stray login
            # options call during bootstrap) cannot erase a live ceremony.
            ceremony_changed = getattr(sess, "loaded_ceremony_id", None) != sess.get("active_ceremony_id")
            stmt = stmt.on_conflict_do_update(
                index_elements=["session_id_hash"],
                set_=dict(
                    csrf_token=stmt.excluded.csrf_token, identity_id=stmt.excluded.identity_id,
                    authenticated_at=stmt.excluded.authenticated_at, vault_unlocked=stmt.excluded.vault_unlocked,
                    active_ceremony_id=stmt.excluded.active_ceremony_id if ceremony_changed else table.c.active_ceremony_id,
                    last_seen_at=stmt.excluded.last_seen_at,
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

@app.get("/health")
def health():
    """Liveness probe. Returns 200 if the app is running. No auth required.
    Used by Cloud Run health checks."""
    return jsonify({"status": "ok"})


@app.get("/api/version")
def version():
    """Build version info. No auth required. Used by CI to verify the
    deployed revision matches the tested commit.
    
    Returns:
        - commit: GITHUB_SHA (short) or "unknown" if not set
        - built_at: ISO timestamp of container build (if available)
    """
    return jsonify({
        "commit": os.environ.get("GITHUB_SHA", "unknown")[:12],
        "built_at": os.environ.get("BUILD_TIMESTAMP", "unknown"),
    })


# ------------------------------------------------------------------
# Honeypot endpoints: common attack paths that should never be hit
# by legitimate users. Any hit is logged as a security event.
# ------------------------------------------------------------------
HONEYPOT_PATHS = [
    "/wp-admin", "/wp-login.php", "/xmlrpc.php",
    "/api/admin", "/admin", "/.env", "/.git/config",
    "/api/v1/admin", "/phpmyadmin", "/server-status",
]

# Tarpit configuration: slow down attackers, waste their time, increase
# the chance they are detected. These delays only apply to honeypot paths
# which legitimate users never visit.
TARPIT_MIN_DELAY = 3   # seconds
TARPIT_MAX_DELAY = 12  # seconds

# Note: _tarpit_delay() is defined below with rate limiting.
# See _honeypot_log() section for the full implementation.

def _fake_wordpress_login(attempts_remaining=5, login_failed=False):
    """Convincing fake WordPress login page.
    
    Contains intentional 'mistakes': HTML comments suggesting debug mode,
    a fake version number with known CVEs, and a commented-out test credential.
    All lead nowhere.
    
    The attempts_remaining counter is XFF-based deception: attacker changes
    X-Forwarded-For, counter resets, they believe they bypassed a rate limit.
    The real limit is independent.
    """
    error_html = ""
    if login_failed:
        error_html = '<div id="login_error" style="color:#d63638;border-left:4px solid #d63638;padding:12px;margin-bottom:20px;background:#fff;">' \
                     '<strong>Error:</strong> The username or password you entered is incorrect.</div>'
    counter_html = f'<p style="color:#646970;font-size:13px;">Login attempts remaining: {attempts_remaining}</p>' \
                   if attempts_remaining <= 5 else ""
    return f"""<!DOCTYPE html>
<html lang="en-US">
<head><meta charset="UTF-8"><title>Log In &lsaquo; WordPress</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f0f1;color:#3c434a}} #login{{width:320px;margin:auto;padding:8% 0 0}} .button{{background:#2271b1;color:#fff;border:1px solid #2271b1;padding:0 12px;height:32px;cursor:pointer}} input{{width:100%;padding:3px;margin:2px 6px 16px 0;border:1px solid #8c8f94}}</style>
</head><body>
<!-- TODO: disable WP_DEBUG before production push - exposes paths in errors -->
<!-- Test account: wp_admin / TempPass123! (remove before go-live) -->
<div id="login"><h1>WordPress</h1>
{error_html}
<form method="post" action="/wp-login.php">
<p><label>Username or Email Address<br><input type="text" name="log"></label></p>
<p><label>Password<br><input type="password" name="pwd"></label></p>
{counter_html}
<p><input type="submit" class="button" value="Log In"></p>
</form></div>
<!-- WordPress 5.8.3 | PHP 7.4.21 -->
<!-- Debug: /wp-content/debug.log (rotated daily) -->
</body></html>"""

def _fake_env_file():
    """Fake .env file with plausible but useless secrets. Attackers will
    waste time trying these credentials.
    
    Contains intentional 'mistakes': commented-out production credentials,
    a TODO about rotating keys, and an AWS key that looks real but is fake.
    """
    return """# Production environment - DO NOT COMMIT
# TODO: rotate all keys before Q4 audit
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vault_production
DB_USER=vault_app
DB_PASSWORD=xK9#mP2$vL5@nQ8wE4rT6yU1iO3pA7sD
# Old credentials (disabled 2024-03, kept for reference):
# DB_PASSWORD_OLD=Summer2023!Vault
SECRET_KEY=sk-live-7f3a9b2e4d1c8f6a5e3b9d2c4f6a8e1b3d
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
REDIS_URL=redis://:p@ssw0rd123@localhost:6379/0
# Backup bucket: s3://vault-backups-prod (migrating to Glacier)
"""

def _fake_phpmyadmin(login_failed=False):
    """Fake phpMyAdmin login. Attackers love database admin panels.
    Does NOT log submitted passwords."""
    error_html = ""
    if login_failed:
        error_html = '<p style="color:red;">#1045 - Access denied for user</p>'
    return f"""<!DOCTYPE html>
<html><head><title>phpMyAdmin</title>
<style>body{{font-family:sans-serif;background:#e9e9e9}} .login{{width:400px;margin:100px auto;background:#fff;padding:20px;border:1px solid #ccc}} input{{width:100%;padding:8px;margin:5px 0}} .btn{{background:#444;color:#fff;padding:10px;border:none;cursor:pointer;width:100%}}</style>
</head><body><div class="login">
<h2>phpMyAdmin</h2><p>Welcome to phpMyAdmin</p>
{error_html}
<form method="post">
<p>Username:<br><input type="text" name="pma_username"></p>
<p>Password:<br><input type="password" name="pma_password"></p>
<p><input type="submit" class="btn" value="Go"></p>
</form><p><small>phpMyAdmin 5.2.1</small></p>
</div></body></html>"""

def _fake_xmlrpc():
    """Fake XML-RPC response. WordPress pingback scanners will engage."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><array><data>
<value><string>pingback.ping</string></value>
<value><string>demo.addPing</string></value>
<value><string>demo.sayHello</string></value>
</data></array></value></param></params></methodResponse>"""

def _fake_git_config():
    """Fake git config. May reveal (fake) remote URLs to waste time."""
    return """[core]
\trepositoryformatversion = 0
\tfilemode = true
[remote "origin"]
\turl = https://github.com/example/vault-backup.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

@app.route("/wp-admin", methods=["GET", "POST"])
@app.route("/wp-login.php", methods=["GET", "POST"])
def honeypot_wordpress():
    """Deception: fake WordPress login.
    
    Shows a fake "attempts remaining" counter based on X-Forwarded-For.
    Attacker changes XFF, counter resets, they believe they bypassed a limit.
    Real rate limit (_honeypot_rate_limited) uses trusted remote_addr and is
    unaffected.
    
    Does NOT log submitted passwords. Only logs that an attempt occurred.
    """
    if _honeypot_log():
        # Over budget: minimal response, no deception frills
        return jsonify({"error": "Not found"}), 404
    if request.method == "POST":
        # Log the attempt, NOT the credentials
        LOG.warning('event="honeypot_credential_attempt" path="%s" client="%s"',
                    request.path, _client_log_id())
        # Always "fail" the login, show remaining attempts (XFF-based deception)
        remaining = _deception_attempts_remaining()
        return _fake_wordpress_login(attempts_remaining=remaining,
                                     login_failed=True), 200, {"Content-Type": "text/html"}
    # Peek at current count without consuming an attempt (GET is free)
    import hashlib
    xff_id = _deception_xff_identity()
    key = hashlib.sha256(xff_id.encode()).hexdigest()[:12]
    used = _deception_attempt_counters.get(key, 0)
    remaining = max(0, 5 - used)
    return _fake_wordpress_login(attempts_remaining=remaining), 200, {"Content-Type": "text/html"}

@app.route("/xmlrpc.php", methods=["GET", "POST"])
def honeypot_xmlrpc():
    """Deception: fake XML-RPC. Scanners will try pingback attacks."""
    if _honeypot_log():
        return jsonify({"error": "Not found"}), 404
    return _fake_xmlrpc(), 200, {"Content-Type": "text/xml"}

@app.route("/.env", methods=["GET"])
def honeypot_env():
    """Deception: fake secrets. Attackers will try these dead credentials."""
    if _honeypot_log():
        return jsonify({"error": "Not found"}), 404
    LOG.warning('event="honeypot_env_exfiltrated" client="%s"', _client_log_id())
    return _fake_env_file(), 200, {"Content-Type": "text/plain"}

@app.route("/phpmyadmin", methods=["GET", "POST"])
def honeypot_phpmyadmin():
    """Deception: fake database admin. Does NOT log submitted passwords."""
    if _honeypot_log():
        return jsonify({"error": "Not found"}), 404
    if request.method == "POST":
        LOG.warning('event="honeypot_credential_attempt" path="%s" client="%s"',
                    request.path, _client_log_id())
        return _fake_phpmyadmin(login_failed=True), 200, {"Content-Type": "text/html"}
    return _fake_phpmyadmin(), 200, {"Content-Type": "text/html"}

@app.route("/.git/config", methods=["GET"])
def honeypot_git():
    """Deception: fake git config."""
    if _honeypot_log():
        return jsonify({"error": "Not found"}), 404
    return _fake_git_config(), 200, {"Content-Type": "text/plain"}

@app.route("/robots.txt", methods=["GET"])
def honeypot_robots():
    """Deception: robots.txt directing scanners to dead ends.
    No delay - kept cheap for legitimate crawlers."""
    # Light logging only, no rate limit check (cheap endpoint)
    LOG.info('event="honeypot_hit" path="/robots.txt" method="GET" client="%s"',
             _client_log_id())
    return """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /old-site/
Disallow: /test/
Disallow: /dev/
Disallow: /staging/
# TODO: remove /backup-2024-01.zip before launch
""", 200, {"Content-Type": "text/plain"}

@app.route("/backup/export", methods=["POST"])
def honeypot_backup_start():
    """Deception: simulated async backup export.
    
    Instead of time.sleep(12) occupying a worker, return immediately with
    a job ID. The attacker polls /backup/status for progress. Each poll
    is cheap. The deception stays interactive without blocking workers.
    """
    if _honeypot_log():
        return jsonify({"error": "Not found"}), 404
    job_id = _deception_start_backup_job()
    return jsonify({
        "job_id": job_id,
        "status": "queued",
        "message": "Backup export queued. Poll /backup/status for progress.",
        "status_url": f"/backup/status?job_id={job_id}",
    }), 202

@app.route("/backup/status", methods=["GET"])
def honeypot_backup_status():
    """Deception: fake backup job progress. Cheap per-poll, never completes."""
    if _honeypot_log():
        return jsonify({"error": "Not found"}), 404
    job_id = request.args.get("job_id", "")
    status = _deception_backup_status(job_id)
    if not status:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(status), 200

@app.route("/backup.zip", methods=["GET"])
@app.route("/backup-2024-01.zip", methods=["GET"])
@app.route("/db_backup.sql", methods=["GET"])
def honeypot_backup():
    """Deception: redirect to async export. The old direct download is gone;
    the attacker must use the job API, which keeps them engaged longer."""
    if _honeypot_log():
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "error": "Direct download disabled",
        "message": "Use POST /backup/export to queue a backup job.",
    }), 410

@app.route("/api/admin", methods=["GET", "POST"])
@app.route("/admin", methods=["GET", "POST"])
@app.route("/api/v1/admin", methods=["GET", "POST"])
@app.route("/server-status", methods=["GET"])
def honeypot():
    """Generic deception: 404 for paths without specific fake content."""
    _honeypot_log()
    return jsonify({"error": "Not found"}), 404

def _honeypot_log(sample_rate=1.0):
    """Common logging for all honeypot hits.
    
    Rate limiting is checked FIRST (before DB writes) to bound resource usage.
    When rate-limited, only the log line is emitted; DB and webhook are skipped.
    
    Telemetry sampling: when sample_rate < 1.0, only that fraction of hits
    write to the database. This bounds DB load during floods while preserving
    a representative sample.
    
    Note: _audit_event already fires the webhook for HONEYPOT_HIT, so we do
    NOT call _send_security_webhook separately (avoids double webhook).
    """
    import time, secrets
    client_id = _client_log_id()
    # Check rate limit BEFORE expensive operations
    rate_limited = _honeypot_rate_limited()
    # ASN lookup (only when IP logging is enabled, cheap local file read)
    asn_num, asn_org = None, None
    if IP_LOGGING:
        asn_num, asn_org = _lookup_asn(request.remote_addr)
    asn_str = f' asn="AS{asn_num} {asn_org}"' if asn_num else ""
    LOG.warning('event="honeypot_hit" path="%s" method="%s" client="%s"%s%s',
                request.path, request.method, client_id, asn_str,
                ' rate_limited="true"' if rate_limited else "")
    if rate_limited:
        return True  # Signal to caller: minimal response
    # Sampling: skip DB write for (1 - sample_rate) of hits
    if sample_rate < 1.0 and secrets.randbelow(1000) >= int(sample_rate * 1000):
        return
    try:
        detail = {"path": request.path, "method": request.method}
        if asn_num:
            detail["asn"] = asn_num
            detail["asn_org"] = asn_org
        _audit_event("HONEYPOT_HIT", detail=detail)
        db().commit()
        # Webhook is fired by _audit_event for HONEYPOT_HIT - do not call again
    except Exception:
        pass
    return False

# In-memory per-client honeypot hit tracking.
# Keyed by HMAC of request.remote_addr (trusted, not spoofable).
# This is the REAL resource budget. It cannot be bypassed by header spoofing.
#
# MEMORY BOUNDS: All deception dicts have max entries and TTL eviction.
# _evict_deception_state() is called periodically from _honeypot_rate_limited().
_DECEPTION_MAX_ENTRIES = 10000
_DECEPTION_TTL_SECONDS = 3600  # 1 hour

def _evict_deception_state():
    """Remove stale entries from deception dicts. Called on each rate limit check."""
    import time
    now = time.time()
    # Evict _honeypot_hits entries older than 60s (they're pruned per-client anyway)
    # Just cap total size
    if len(_honeypot_hits) > _DECEPTION_MAX_ENTRIES:
        # Remove oldest by arbitrary order (dicts preserve insertion order)
        for k in list(_honeypot_hits.keys())[:len(_honeypot_hits) - _DECEPTION_MAX_ENTRIES]:
            del _honeypot_hits[k]
    # Evict old backup jobs
    stale_jobs = [jid for jid, job in _deception_backup_jobs.items()
                  if now - job.get("started", 0) > _DECEPTION_TTL_SECONDS]
    for jid in stale_jobs:
        del _deception_backup_jobs[jid]
    if len(_deception_backup_jobs) > _DECEPTION_MAX_ENTRIES:
        for jid in list(_deception_backup_jobs.keys())[:len(_deception_backup_jobs) - _DECEPTION_MAX_ENTRIES]:
            del _deception_backup_jobs[jid]
    # Evict old attempt counters (no timestamp, just cap size)
    if len(_deception_attempt_counters) > _DECEPTION_MAX_ENTRIES:
        for k in list(_deception_attempt_counters.keys())[:len(_deception_attempt_counters) - _DECEPTION_MAX_ENTRIES]:
            del _deception_attempt_counters[k]
_honeypot_hits = {}
HONEYPOT_MAX_HITS_PER_MINUTE = 30

def _honeypot_rate_limited():
    """Check if this client has exceeded the honeypot rate limit.
    
    Uses _client_log_id() which is HMAC(request.remote_addr) - the trusted
    client IP, not spoofable via X-Forwarded-For. This is the real resource
    budget. Returns True if the client should get minimal-cost responses.
    """
    import time
    client_id = _client_log_id()
    now = time.time()
    cutoff = now - 60
    _honeypot_hits[client_id] = [t for t in _honeypot_hits.get(client_id, []) if t > cutoff]
    _honeypot_hits[client_id].append(now)
    if len(_honeypot_hits[client_id]) > HONEYPOT_MAX_HITS_PER_MINUTE:
        LOG.warning('event="honeypot_rate_limited" client="%s"', client_id)
        return True
    # Periodic eviction (amortized: runs on every check, cheap)
    _evict_deception_state()
    return False

# --- Deception layer ---
# The visible "vulnerabilities" below are entirely cosmetic. They change what
# the attacker SEES, not what the server DOES. The real resource limits above
# are independent and cannot be affected by these.

def _deception_xff_identity():
    """Get the attacker's claimed identity from X-Forwarded-For.
    
    This is DELIBERATELY spoofable. It's used ONLY for cosmetic deception:
    the fake WordPress page shows a "login attempts remaining" counter that
    resets when XFF changes. The attacker believes they bypassed a rate limit.
    In reality, the real budget (_honeypot_rate_limited) is unaffected.
    
    Perceived vulnerability (fake counter resets) vs actual vulnerability
    (none - real limits use trusted remote_addr).
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

# Fake per-XFF login attempt counters (cosmetic only)
_deception_attempt_counters = {}

def _deception_attempts_remaining():
    """Return fake 'attempts remaining' for the deception layer.
    Resets when XFF changes. Purely cosmetic - does not affect real limits.
    """
    import hashlib
    xff_id = _deception_xff_identity()
    key = hashlib.sha256(xff_id.encode()).hexdigest()[:12]
    used = _deception_attempt_counters.get(key, 0) + 1
    _deception_attempt_counters[key] = used
    return max(0, 5 - used)

# Fake async backup jobs (simulated long-running operation)
# Instead of time.sleep(12) occupying a worker, return immediately with a job ID.
# Polling returns plausible progress. Interactive deception, zero worker blocking.
_deception_backup_jobs = {}

def _deception_start_backup_job():
    """Start a fake backup export job. Returns job ID immediately."""
    import secrets, time
    job_id = secrets.token_hex(8)
    _deception_backup_jobs[job_id] = {"started": time.time(), "polls": 0}
    LOG.warning('event="honeypot_backup_job_started" job="%s" client="%s"',
                job_id, _client_log_id())
    return job_id

def _deception_backup_status(job_id):
    """Return fake backup job progress. Advances on each poll."""
    import time
    job = _deception_backup_jobs.get(job_id)
    if not job:
        return None
    job["polls"] += 1
    elapsed = time.time() - job["started"]
    # Fake progress: 0-100% over ~5 minutes of polling
    progress = min(99, int((elapsed / 300) * 100) + job["polls"] * 2)
    progress = min(99, progress)  # Never quite finishes
    return {
        "job_id": job_id,
        "status": "preparing",
        "progress": progress,
        "message": f"Compressing database dump... {progress}%"
                   if progress < 50 else
                   f"Encrypting backup archive... {progress}%",
    }


@app.get("/ready")
def ready():
    """Readiness probe. Returns 200 if the app can serve traffic (DB reachable).
    No auth required. Used by Cloud Run health checks."""
    try:
        # Check database connectivity
        conn = db()
        conn.execute(text("SELECT 1"))
        # ZKP is an optional feature: report the verifier state, never fail
        # readiness on it (docs/ZKP_BINDING.md, "Availability").
        return jsonify({"status": "ready", "database": "ok",
                        "zkp": "available" if zkp_verifier.artifacts_available() else "unavailable"})
    except Exception as e:
        info = _redact_db_detail(e, limit=100)
        LOG.warning('event="readiness_failed" class="%s" orig_class="%s" sqlstate="%s" detail="%s"',
                    info["cls"], info["orig_cls"], info["sqlstate"], info["detail"])
        return jsonify({"status": "not_ready", "database": "error"}), 503


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
        return api_error("This endpoint does not accept a request body", 400)
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

REKEY_TTL_SECONDS = int(os.environ.get("VAULT_REKEY_TTL_SECONDS", "600"))


def _vault_write_guard(conn, owner_id):
    """Serialize record writes against a vault rekey commit.

    Takes a shared lock on the identity row (rekey commit takes it FOR
    UPDATE), then refuses the write if this session was revoked (a commit
    revokes every other session of the vault, whose tabs hold the old keys)
    or a rekey is in progress (records written now would be under the old
    keys and missing from the staged set). Returns an error response or None.
    """
    ident = models.VaultIdentity.__table__
    conn.execute(select(ident.c.id).where(ident.c.id == owner_id).with_for_update(read=True))
    sessions = models.ServerSession.__table__
    revoked = conn.execute(select(sessions.c.revoked_at).where(
        sessions.c.session_id_hash == _sid_hash(session.sid))).scalar()
    if revoked is not None:
        conn.rollback(); return api_error("This session has ended. Sign in again.", 401)
    rekeys = models.VaultRekey.__table__
    active = conn.execute(select(func.count()).select_from(rekeys).where(
        (rekeys.c.identity_id == owner_id) & (rekeys.c.expires_at > time.time()))).scalar_one()
    if active:
        conn.rollback(); return api_error("Vault re-encryption in progress. Try again shortly.", 409)
    return None


@app.post("/api/records")
def put_records():
    denied = require_access()
    if denied: return denied
    owner_id = current_identity_id()
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
    blocked = _vault_write_guard(conn, owner_id)
    if blocked: return blocked
    existing = 0
    if seen:
        existing = conn.execute(select(func.count()).select_from(table).where(
            (table.c.identity_id == owner_id) & table.c.blind_index.in_(seen)
        )).scalar_one()
    total = conn.execute(select(func.count()).select_from(table).where(table.c.identity_id == owner_id)).scalar_one()
    if total + len(validated) - existing > MAX_TOTAL_RECORDS:
        conn.rollback(); return api_error("Vault record quota exceeded", 409)
    if validated:
        # pg_insert(...).values([]) on an empty list degrades to a single
        # DEFAULT VALUES row rather than a no-op, unlike the old
        # executemany() -- guard explicitly so an empty batch stores nothing.
        today = date.today()
        stmt = pg_insert(table).values([
            {"identity_id": owner_id, "blind_index": blind, "sealed": sealed, "bytes": nbytes, "stored_at": today}
            for blind, sealed, nbytes in validated
        ])
        # A record rewritten through this path is a plain sealed box, so any
        # ZK proof tag on the old row no longer describes it: clear it.
        stmt = stmt.on_conflict_do_update(
            index_elements=["identity_id", "blind_index"],
            set_=dict(sealed=stmt.excluded.sealed, bytes=stmt.excluded.bytes, commitment=None, circuit_version=None),
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
    if set(payload) != {"purpose"}: return api_error("Unknown field in challenge request", 400)
    if payload["purpose"] != "manual_expense_create":
        return api_error("Unsupported challenge purpose", 400)
    if not zkp_verifier.artifacts_available():
        LOG.warning('event="zkp_challenge_unavailable" client="%s"', _client_log_id())
        return api_error("Encrypted-record validation is temporarily unavailable", 503)
    key = _zkp_vault_key(db(), current_identity_id())
    if key is None:
        return api_error("This vault has no registered ZK key commitment", 409)

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
        "key_commitment": key[0].hex(),
        "vault_salt": key[1].hex(),
    })


def _zkp_vault_key(conn, identity_id, for_update=False):
    """(key_commitment, vault_salt) bytes for this vault, or None when it has
    not enrolled. Always read from the database, never from the request."""
    ident = models.VaultIdentity.__table__
    stmt = select(ident.c.zkp_key_commitment, ident.c.zkp_vault_salt).where(ident.c.id == identity_id)
    if for_update: stmt = stmt.with_for_update()
    row = conn.execute(stmt).first()
    if not row or row.zkp_key_commitment is None or row.zkp_vault_salt is None:
        return None
    return bytes(row.zkp_key_commitment), bytes(row.zkp_vault_salt)


def _parse_zkp_key_commitment(value):
    """64 lowercase hex chars naming a canonical, nonzero BN254 field element."""
    if not isinstance(value, str) or not _LOWER_HEX_64.fullmatch(value): return None
    integer = int(value, 16)
    if not 0 < integer < zkp_verifier.BN254_SCALAR_MODULUS: return None
    return bytes.fromhex(value)


@app.get("/api/zkp/key-commitment")
def zkp_key_commitment_status():
    """Whether this vault has enrolled its v4 key commitment, and its public
    salt (the browser needs it to recompute the commitment, e.g. at rekey)."""
    denied = require_access()
    if denied: return denied
    ident = models.VaultIdentity.__table__
    row = db().execute(select(ident.c.zkp_key_commitment, ident.c.zkp_vault_salt)
                       .where(ident.c.id == current_identity_id())).first()
    return jsonify({
        "registered": bool(row and row.zkp_key_commitment is not None),
        "vault_salt": bytes(row.zkp_vault_salt).hex() if row and row.zkp_vault_salt is not None else None,
    })


@app.post("/api/zkp/key-commitment/salt")
def zkp_key_commitment_salt():
    """Step 1 of enrollment (step-up gated): issue a fresh server-generated
    salt. Refused once a commitment exists; only rekey commit replaces it."""
    denied = require_destructive_management()
    if denied: return denied
    payload, error = _json_object()
    if error: return error
    if payload: return api_error("Body must be empty", 400)
    conn = db()
    ident = models.VaultIdentity.__table__
    owner_id = current_identity_id()
    row = conn.execute(select(ident.c.zkp_key_commitment).where(ident.c.id == owner_id).with_for_update()).first()
    if not row:
        conn.rollback(); return api_error("Vault not found", 404)
    if row.zkp_key_commitment is not None:
        conn.rollback(); return api_error("A ZK key commitment is already registered", 409)
    # 31 bytes: strictly below the BN254 modulus, so it is a field element as is.
    salt = secrets.token_bytes(31)
    conn.execute(update(ident).where(ident.c.id == owner_id).values(zkp_vault_salt=salt, updated_at=func.now()))
    conn.commit()
    return jsonify({"vault_salt": salt.hex()})


@app.post("/api/zkp/key-commitment")
def zkp_key_commitment_enroll():
    """Step 2 of enrollment (step-up gated): store the browser-computed
    Poseidon2(DS_KEY, zk_root, vault_salt). The server cannot check it
    against the key (that would need the key); a wrong value only locks
    this vault out of its own v4 proofs. See docs/ZKP_BINDING.md."""
    denied = require_destructive_management()
    if denied: return denied
    payload, error = _json_object()
    if error: return error
    if set(payload) != {"key_commitment"}: return api_error("Body must contain only key_commitment", 400)
    commitment = _parse_zkp_key_commitment(payload["key_commitment"])
    if commitment is None: return api_error("Invalid key_commitment", 400)
    conn = db()
    ident = models.VaultIdentity.__table__
    owner_id = current_identity_id()
    row = conn.execute(select(ident.c.zkp_key_commitment, ident.c.zkp_vault_salt)
                       .where(ident.c.id == owner_id).with_for_update()).first()
    if not row:
        conn.rollback(); return api_error("Vault not found", 404)
    if row.zkp_key_commitment is not None:
        conn.rollback(); return api_error("A ZK key commitment is already registered", 409)
    if row.zkp_vault_salt is None:
        conn.rollback(); return api_error("Request a salt first", 409)
    conn.execute(update(ident).where(ident.c.id == owner_id).values(zkp_key_commitment=commitment, updated_at=func.now()))
    conn.commit()
    LOG.info('event="zkp_key_commitment_enrolled" client="%s"', _client_log_id())
    return jsonify({"registered": True})


def _refund_zkp_challenge(challenge_id, identity_id):
    """Undo a claim when the verifier itself was unavailable (missing
    artifacts or timeout), so the user is not charged a challenge for a
    server-side outage. Only ever called after this request claimed it."""
    table = models.ZkpChallenge.__table__
    conn = db()
    conn.execute(update(table).where(
        (table.c.challenge_id == challenge_id) & (table.c.identity_id == identity_id)
        & (table.c.session_id_hash == _sid_hash(session.sid))
    ).values(consumed_at=None))
    conn.commit()


def _claim_zkp_challenge(challenge_id, identity_id):
    """Atomically claim a challenge (single UPDATE ... RETURNING, matching
    _take_challenge()'s existing pattern above): consumed exactly once,
    with no SELECT-then-UPDATE race between two concurrent submissions of
    the same challenge_id. Consuming happens BEFORE proof verification so
    single use stays race-free; an invalid proof spends the challenge, but
    a verifier outage refunds it (_refund_zkp_challenge)."""
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
    """ZK-proof-gated manual transaction creation, circuit v4 only.

    The proof's statement is filled from server rows (challenge, record id,
    schema, this vault's key commitment and salt), and the stored record is
    built from the proof's own ciphertext/mac outputs, so the ciphertext is
    exactly the proven one and was produced under the vault's registered
    key. v2 records remain readable; v2 and v3 submissions are refused.
    See docs/ZKP_BINDING.md."""
    denied = require_access()
    if denied: return denied
    owner_id = current_identity_id()
    payload, error = _json_object()
    if error: return error
    required = {"challenge_id", "blind_index", "proof", "public_inputs"}
    if not required <= set(payload) <= required | {"meta"}:
        return api_error("Invalid manual transaction submission", 400)
    challenge_id, blind, proof_hex, public_inputs = (
        payload["challenge_id"], payload["blind_index"], payload["proof"], payload["public_inputs"])
    # Optional client sealed box with the fields the circuit does not cover
    # (id, date, account). Opaque to the server and NOT proven; stored
    # after the proven part. See docs/ZKP_BINDING.md "UI behavior".
    meta_hex = payload.get("meta", "")
    if not isinstance(meta_hex, str) or (meta_hex and (
            not MIN_SEALED_HEX_LENGTH <= len(meta_hex) <= MAX_SEALED_HEX_LENGTH - zkp_verifier.PROVEN_RECORD_HEX
            or len(meta_hex) % 2 or not _is_lower_hex(meta_hex))):
        return api_error("Invalid record", 400)
    if not isinstance(challenge_id, str) or not challenge_id or len(challenge_id) > 128:
        return api_error("Invalid manual transaction submission", 400)
    if not isinstance(blind, str) or not _LOWER_HEX_64.fullmatch(blind):
        return api_error("Invalid record", 400)
    if not isinstance(proof_hex, str) or not _LOWER_HEX.fullmatch(proof_hex) or len(proof_hex) % 2:
        return api_error("Unable to validate the encrypted record.", 400)
    try:
        public_inputs = zkp_verifier.validate_public_inputs(public_inputs)
    except zkp_verifier.ZkpVerificationError:
        return api_error("Unable to validate the encrypted record.", 400)

    # Checked before claiming, so a vault that never enrolled does not burn
    # challenges.
    key = _zkp_vault_key(db(), owner_id)
    db().commit()
    if key is None:
        return api_error("This vault has no registered ZK key commitment", 409)

    claimed = _claim_zkp_challenge(challenge_id, owner_id)
    if claimed is None:
        LOG.warning('event="zkp_challenge_rejected" client="%s"', _client_log_id())
        return api_error("Unable to validate the encrypted record.", 400)
    if claimed["circuit_version"] != zkp_verifier.CIRCUIT_VERSION or claimed["schema_version"] != zkp_verifier.SCHEMA_VERSION:
        LOG.warning('event="zkp_context_mismatch" client="%s"', _client_log_id())
        return api_error("Unable to validate the encrypted record.", 400)

    # The client never chooses the statement: the first five public inputs
    # must equal what the server builds from its own rows.
    expected = zkp_verifier.expected_server_inputs(
        challenge=bytes(claimed["challenge"]), record_id=bytes(claimed["record_id"]),
        key_commitment=key[0], vault_salt=key[1])
    if public_inputs[:zkp_verifier.SERVER_INPUT_COUNT] != expected:
        LOG.warning('event="zkp_context_mismatch" client="%s"', _client_log_id())
        return api_error("Unable to validate the encrypted record.", 400)

    try:
        proof_bytes = bytes.fromhex(proof_hex)
        result = zkp_verifier.verify_proof(proof_bytes, public_inputs)
    except zkp_verifier.CircuitArtifactsUnavailable:
        _refund_zkp_challenge(challenge_id, owner_id)
        LOG.warning('event="zkp_verifier_unavailable" client="%s"', _client_log_id())
        return api_error("Encrypted-record validation is temporarily unavailable", 503)
    except (zkp_verifier.ZkpVerificationError, ValueError):
        LOG.warning('event="zkp_proof_malformed" client="%s"', _client_log_id())
        return api_error("Unable to validate the encrypted record.", 400)

    if not result.valid:
        LOG.warning(
            'event="zkp_proof_invalid" client="%s" duration_ms="%d"',
            _client_log_id(), int(result.duration_seconds * 1000),
        )
        return api_error("Unable to validate the encrypted record.", 400)

    sealed = zkp_verifier.sealed_from_outputs(bytes(claimed["record_id"]), public_inputs) + meta_hex
    commitment = zkp_verifier.commitment_from_outputs(public_inputs)
    table = models.Record.__table__
    conn = db()
    blocked = _vault_write_guard(conn, owner_id)
    if blocked: return blocked
    stmt = pg_insert(table).values(
        identity_id=owner_id, blind_index=blind, sealed=sealed, bytes=len(sealed) // 2, stored_at=date.today(),
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
    # Pagination to prevent OOM with large datasets (max 100k records)
    try:
        limit = min(int(request.args.get("limit", "1000")), 5000)
        offset = max(int(request.args.get("offset", "0")), 0)
    except ValueError:
        return api_error("Invalid pagination parameters", 400)
    table = models.Record.__table__
    # Get total count for pagination metadata
    total = db().execute(
        select(func.count()).select_from(table).where(
            table.c.identity_id == current_identity_id()
        )
    ).scalar() or 0
    rows = db().execute(select(
        table.c.id, table.c.blind_index, table.c.sealed,
        table.c.commitment, table.c.circuit_version,
    ).where(
        table.c.identity_id == current_identity_id()
    ).order_by(table.c.id).limit(limit).offset(offset)).mappings().all()
    records = []
    for row in rows:
        record = {"id": row["id"], "blind_index": row["blind_index"], "sealed": row["sealed"]}
        if row["commitment"] is not None:
            record["commitment"] = row["commitment"]
            record["circuit_version"] = row["circuit_version"]
        records.append(record)
    return jsonify({"records": records, "total": total, "limit": limit, "offset": offset})

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
    return jsonify({"record_count":total,"size_histogram":[dict(r) for r in sizes],"write_days":[{"d": r["d"].isoformat(), "n": r["n"]} for r in days],"sample":[dict(r) for r in sample],"columns":["id","blind_index","sealed","bytes","stored_at"]})

@app.delete("/api/records")
def reset():
    denied=require_destructive_management()
    if denied: return denied
    table = models.Record.__table__
    owner_id = current_identity_id()
    conn=db()
    blocked = _vault_write_guard(conn, owner_id)
    if blocked: return blocked
    conn.execute(delete(table).where(table.c.identity_id == owner_id))
    # The reset is followed by a new passphrase, i.e. a new vault key, so the
    # old key's ZK commitment would lock the vault out of v4 proofs. Clear it
    # (and its salt); the new key re-enrolls with a fresh step-up.
    ident = models.VaultIdentity.__table__
    conn.execute(update(ident).where(ident.c.id == owner_id).values(zkp_key_commitment=None, zkp_vault_salt=None))
    conn.commit()
    LOG.info('event="vault_records_deleted" client="%s"', _client_log_id())
    return jsonify({"reset":True})

@app.get("/api/passkeys/status")
def passkey_status():
    table = models.PasskeyCredential.__table__
    count=db().execute(select(func.count()).select_from(table).where(
        table.c.identity_id == current_identity_id()
    )).scalar_one()
    return jsonify({"passkey_required":auth_required(),"authenticated":authenticated(),"has_usable_passkey":count>0,
                    "bootstrap_needed":count==0})

@app.post("/api/passkeys/bootstrap/options")
def bootstrap_options():
    """First-time passkey enrollment. Only allowed when no passkeys exist
    for the current identity. This is the bootstrap flow for new deployments.

    SECURITY: Requires VAULT_BOOTSTRAP_TOKEN. In production (VAULT_ENV=production),
    the token is MANDATORY - bootstrap is refused entirely if not configured.
    This prevents unauthorized first-enrollment on uninitialized vaults.
    The token must be provided in the request body as {"bootstrap_token": "..."}.
    """
    # Verify bootstrap token (prevents unauthorized first-enrollment)
    bootstrap_token = os.environ.get("VAULT_BOOTSTRAP_TOKEN")
    is_production = os.environ.get("VAULT_ENV") == "production"
    if is_production and not bootstrap_token:
        # Fail closed in production: no token configured = no bootstrap allowed
        LOG.error('event="bootstrap_refused_no_token_configured" client="%s"', _client_log_id())
        return api_error(
            "Bootstrap not configured. Set VAULT_BOOTSTRAP_TOKEN (or VAULT_BOOTSTRAP_TOKEN_SECRET) "
            "to enable first-passkey enrollment.", 503
        )
    if bootstrap_token:
        payload, error = _json_object()
        if error: return error
        provided = payload.get("bootstrap_token", "")
        # Use constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(str(provided), bootstrap_token):
            LOG.warning('event="bootstrap_token_mismatch" client="%s"', _client_log_id())
            return api_error("Invalid bootstrap token", 403)
    owner_id = current_identity_id()
    table = models.PasskeyCredential.__table__
    count = db().execute(select(func.count()).select_from(table).where(
        table.c.identity_id == owner_id)).scalar_one()
    if count > 0:
        return api_error("Bootstrap not available: passkeys already enrolled", 403)
    ident = identity(owner_id)
    if ident is None:
        return api_error("Account is unavailable", 401)
    options = generate_registration_options(
        rp_id=RP_ID, rp_name=RP_NAME,
        user_id=bytes(ident["user_handle"]),
        user_name=f"vault-{owner_id}",
        challenge=_new_challenge("registration", owner_id),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED),
        attestation=AttestationConveyancePreference.NONE)
    return app.response_class(options_to_json(options), mimetype="application/json")

@app.post("/api/passkeys/bootstrap/verify")
def bootstrap_verify():
    """Verify bootstrap registration. Only allowed when no passkeys exist.
    Does not require prior authentication (this IS the first authentication).
    Requires VAULT_BOOTSTRAP_TOKEN. In production, bootstrap is refused
    entirely if the token is not configured."""
    # Verify bootstrap token (same as bootstrap_options)
    bootstrap_token = os.environ.get("VAULT_BOOTSTRAP_TOKEN")
    is_production = os.environ.get("VAULT_ENV") == "production"
    if is_production and not bootstrap_token:
        LOG.error('event="bootstrap_refused_no_token_configured" client="%s"', _client_log_id())
        return api_error("Bootstrap not configured.", 503)
    payload, error = _json_object()
    if error: return error
    if bootstrap_token:
        provided = payload.get("bootstrap_token", "")
        if not secrets.compare_digest(str(provided), bootstrap_token):
            LOG.warning('event="bootstrap_token_mismatch" client="%s"', _client_log_id())
            return api_error("Invalid bootstrap token", 403)
    owner_id = current_identity_id()
    table = models.PasskeyCredential.__table__
    count = db().execute(select(func.count()).select_from(table).where(
        table.c.identity_id == owner_id)).scalar_one()
    if count > 0:
        return api_error("Bootstrap not available: passkeys already enrolled", 403)
    challenge_row = _take_challenge("registration", owner_id)
    if challenge_row is None:
        return api_error("Passkey ceremony could not be verified", 400)
    challenge = challenge_row["challenge"]
    # payload already parsed above for token check
    credential = payload.get("credential"); label = payload.get("label", "Passkey")
    if not isinstance(credential, dict) or not isinstance(label, str) or not label.strip() or len(label.strip()) > MAX_LABEL_LENGTH:
        return api_error("Passkey registration could not be verified", 400)
    label = label.strip()
    conn = db()
    try:
        result = verify_registration_response(
            credential=credential, expected_challenge=challenge,
            expected_rp_id=RP_ID, expected_origin=ORIGIN,
            require_user_verification=True)
        conn.execute(insert(table).values(
            identity_id=owner_id, credential_id=result.credential_id,
            credential_public_key=result.credential_public_key,
            sign_count=result.sign_count,
            transports=(credential.get("response") or {}).get("transports", []),
            device_type=str(result.credential_device_type),
            backed_up=bool(result.credential_backed_up), label=label,
        ))
        identity_table = models.VaultIdentity.__table__
        conn.execute(update(identity_table).where(identity_table.c.id == owner_id).values(
            passkey_required=True, updated_at=func.now()))
        _audit_event("PASSKEY_REGISTERED", credential_id=result.credential_id,
                     detail={"label": label, "bootstrap": True})
        conn.commit()
    except IntegrityError:
        conn.rollback(); return api_error("Passkey registration conflict", 409)
    except (WebAuthnException, ValueError, KeyError, TypeError):
        conn.rollback()
        LOG.warning('event="authentication_failure" category="bootstrap_verification" client="%s"', _client_log_id())
        return api_error("Passkey registration could not be verified", 400)
    _rotate_session(identity_id=owner_id, vault_unlocked=True)
    LOG.info('event="passkey_registered" category="bootstrap" client="%s"', _client_log_id())
    return jsonify({"verified": True, "csrf_token": session["csrf_token"]})

@app.post("/api/passkeys/register/options")
def register_options():
    denied=require_client_vault_open() or require_recent_reauth()
    if denied: return denied
    owner_id = current_identity_id()
    table = models.PasskeyCredential.__table__
    ident=identity(owner_id); credentials=db().execute(select(table.c.credential_id).where(table.c.identity_id==owner_id)).mappings().all()
    if ident is None:
        return api_error("Account is unavailable", 401)
    options=generate_registration_options(rp_id=RP_ID,rp_name=RP_NAME,user_id=bytes(ident["user_handle"]),user_name=f"vault-{owner_id}",challenge=_new_challenge("registration", owner_id),exclude_credentials=[PublicKeyCredentialDescriptor(id=bytes(r["credential_id"])) for r in credentials],authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,user_verification=UserVerificationRequirement.REQUIRED),attestation=AttestationConveyancePreference.NONE)
    return app.response_class(options_to_json(options),mimetype="application/json")

@app.post("/api/passkeys/register/verify")
def register_verify():
    denied=require_client_vault_open() or require_recent_reauth()
    if denied: return denied
    owner_id = current_identity_id()
    challenge_row=_take_challenge("registration", owner_id)
    if challenge_row is None: return api_error("Passkey ceremony could not be verified",400)
    challenge = challenge_row["challenge"]
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
            identity_id=owner_id, credential_id=result.credential_id, credential_public_key=result.credential_public_key,
            sign_count=result.sign_count, transports=(credential.get("response") or {}).get("transports", []),
            device_type=str(result.credential_device_type), backed_up=bool(result.credential_backed_up), label=label,
        ))
        identity_table = models.VaultIdentity.__table__
        conn.execute(update(identity_table).where(identity_table.c.id==owner_id).values(passkey_required=True, updated_at=func.now()))
        _audit_event("PASSKEY_REGISTERED", credential_id=result.credential_id, detail={"label": label})
        conn.commit()
    except IntegrityError:
        conn.rollback(); return api_error("Passkey registration conflict",409)
    except (WebAuthnException,ValueError,KeyError,TypeError):
        conn.rollback()
        LOG.warning('event="authentication_failure" category="registration_verification" client="%s"', _client_log_id())
        return api_error("Passkey registration could not be verified",400)
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
    if not rows: return api_error("Passkey sign-in is unavailable",409)
    options=generate_authentication_options(rp_id=RP_ID,challenge=_new_challenge("authentication", bound_identity_id),allow_credentials=[PublicKeyCredentialDescriptor(id=bytes(r["credential_id"])) for r in rows],user_verification=UserVerificationRequirement.REQUIRED)
    return app.response_class(options_to_json(options),mimetype="application/json")

@app.post("/api/passkeys/login/verify")
def login_verify():
    # Check for account lockout before processing
    payload_check, _ = _json_object()
    # We need credential_id to check lockout, but do a preliminary check
    # using IP-based rate limiting (already in place via _rate_group)

    challenge_row=_take_challenge("authentication")
    if challenge_row is None: return api_error("Passkey ceremony could not be verified",400)
    challenge = challenge_row["challenge"]
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
    row=db().execute(select(table).where(table.c.credential_id==credential_id_bytes)).mappings().first()
    if row is None: return api_error("Passkey authentication could not be verified",400)
    if challenge_row["identity_id"] is not None and row["identity_id"] != challenge_row["identity_id"]:
        return api_error("Passkey authentication could not be verified",400)

    # Account lockout: check for 5+ failures in last 15 minutes
    if _is_account_locked(row["identity_id"]):
        LOG.warning('event="account_locked" identity="%s" client="%s"', row["identity_id"], _client_log_id())
        return api_error("Account temporarily locked due to failed attempts. Try again in 30 minutes.", 423)

    if _sign_count_regressed(credential, row["sign_count"]):
        _audit_event("SUSPICIOUS_COUNTER_EVENT", credential_id=row["credential_id"], detail={"stored_sign_count": row["sign_count"]}, identity_id=row["identity_id"])
        db().commit()
        LOG.warning('event="suspicious_counter_event" client="%s"', _client_log_id())
    try:
        result=verify_authentication_response(credential=credential,expected_challenge=challenge,expected_rp_id=RP_ID,expected_origin=ORIGIN,credential_public_key=bytes(row["credential_public_key"]),credential_current_sign_count=row["sign_count"],require_user_verification=True)
    except (WebAuthnException,ValueError,KeyError,TypeError):
        conn=db(); _audit_event("PASSKEY_AUTH_FAILURE", credential_id=row["credential_id"], identity_id=row["identity_id"]); conn.commit()
        LOG.warning('event="authentication_failure" category="assertion_verification" client="%s"', _client_log_id())
        return api_error("Passkey authentication could not be verified",400)
    conn=db(); conn.execute(update(table).where(table.c.id==row["id"]).values(sign_count=result.new_sign_count,device_type=str(result.credential_device_type),backed_up=bool(result.credential_backed_up),last_used_at=func.now()))
    _audit_event("PASSKEY_AUTH_SUCCESS", credential_id=row["credential_id"], identity_id=row["identity_id"])
    # Clear any lockout by logging a success (resets the failure window)
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
    conn=db(); cur=conn.execute(update(table).where((table.c.identity_id==current_identity_id())&(table.c.credential_id==credential_id_bytes)).values(label=label.strip())); conn.commit()
    return jsonify({"renamed":True}) if cur.rowcount else api_error("Unknown passkey",404)

@app.delete("/api/passkeys/<credential_id>")
def remove_passkey(credential_id):
    denied=require_client_vault_open() or require_recent_reauth()
    if denied: return denied
    if not _valid_credential_id(credential_id): return api_error("Unknown passkey",404)
    try:
        credential_id_bytes=base64url_to_bytes(credential_id)
    except Exception:
        return api_error("Unknown passkey",404)
    table = models.PasskeyCredential.__table__
    conn=db()
    owner_id = current_identity_id()
    count=conn.execute(select(func.count()).select_from(table).where(table.c.identity_id==owner_id)).scalar_one()
    if auth_required() and count<=1: return api_error("Disable protection before removing the final passkey",409)
    cur=conn.execute(delete(table).where((table.c.identity_id==owner_id)&(table.c.credential_id==credential_id_bytes)))
    if cur.rowcount: _audit_event("PASSKEY_REMOVED", credential_id=credential_id_bytes)
    conn.commit()
    if cur.rowcount: LOG.info('event="passkey_removed" client="%s"', _client_log_id())
    return jsonify({"removed":True}) if cur.rowcount else api_error("Unknown passkey",404)

@app.post("/api/passkeys/disable")
def disable_passkeys():
    denied=require_client_vault_open() or require_recent_reauth()
    if denied: return denied
    payload,error=_json_object()
    if error: return error
    if payload!={"confirm_unlocked":True}: return api_error("Unlocked-vault confirmation is required",400)
    if AUTH_POLICY=="required": return api_error("Authentication is required by deployment policy",409)
    owner_id = current_identity_id()
    table = models.VaultIdentity.__table__
    conn=db(); conn.execute(update(table).where(table.c.id==owner_id).values(passkey_required=False, updated_at=func.now()))
    _audit_event("PASSKEY_PROTECTION_DISABLED")
    conn.commit()
    _rotate_session(identity_id=owner_id,vault_unlocked=True)
    LOG.info('event="passkey_protection_disabled" client="%s"', _client_log_id())
    return jsonify({"disabled":True,"csrf_token":session["csrf_token"]})


# ---------- Incident response ----------

# ---------- KDF salt management ----------

@app.get("/api/security/dashboard")
def security_dashboard():
    """Security dashboard: recent events, failed logins, active sessions.
    Requires authentication."""
    denied = require_access()
    if denied: return denied
    identity_id = current_identity_id()
    if not identity_id:
        return api_error("No identity", 403)
    conn = db()
    table = models.AuditEvent.__table__

    # Recent security events (last 24h)
    since = func.now() - text("INTERVAL '24 hours'")
    recent = conn.execute(
        select(table.c.event_type, func.count().label("count"))
        .where(table.c.identity_id == identity_id, table.c.occurred_at >= since)
        .group_by(table.c.event_type)
    ).all()

    # Failed logins (last 7d)
    week_ago = func.now() - text("INTERVAL '7 days'")
    failed = conn.execute(
        select(func.count().label("count"))
        .where(
            table.c.identity_id == identity_id,
            table.c.event_type == "PASSKEY_AUTH_FAILURE",
            table.c.occurred_at >= week_ago,
        )
    ).scalar() or 0

    # Unacknowledged suspicious events
    suspicious = conn.execute(
        select(table.c.id, table.c.event_type, table.c.occurred_at, table.c.detail)
        .where(
            table.c.identity_id == identity_id,
            table.c.event_type.in_(["SUSPICIOUS_COUNTER_EVENT", "UNUSUAL_ACTIVITY_DETECTED"]),
            table.c.acknowledged_at.is_(None),
        )
        .order_by(table.c.occurred_at.desc())
        .limit(10)
    ).mappings().all()

    # Active sessions count
    sess_table = models.ServerSession.__table__
    active_sessions = conn.execute(
        select(func.count().label("count"))
        .where(sess_table.c.identity_id == identity_id)
    ).scalar() or 0

    return jsonify({
        "recent_events_24h": [{"type": r.event_type, "count": r.count} for r in recent],
        "failed_logins_7d": failed,
        "unacknowledged_suspicious": [
            {
                "id": s["id"],
                "type": s["event_type"],
                "at": s["occurred_at"].isoformat() if s["occurred_at"] else None,
                "detail": s["detail"],
            }
            for s in suspicious
        ],
        "active_sessions": active_sessions,
    })


@app.get("/api/kdf/salts")
def get_kdf_salts():
    """Get the KDF salts for the current identity.
    
    Returns 404 if no salts are set. The client must explicitly generate
    (POST /api/kdf/salts/generate) or migrate (POST /api/kdf/salts/migrate)
    salts. This prevents accidental salt generation during backup restore,
    which would cause salt mismatch.
    """
    denied = require_access()
    if denied: return denied
    identity_id = current_identity_id()
    if not identity_id:
        return api_error("No identity", 403)
    table = models.VaultIdentity.__table__
    conn = db()
    row = conn.execute(
        select(table.c.kdf_salt_enc, table.c.kdf_salt_idx, table.c.kdf_version)
        .where(table.c.id == identity_id)
    ).first()
    if not row:
        return api_error("Identity not found", 404)
    if row.kdf_salt_enc is None or row.kdf_salt_idx is None:
        return api_error(
            "No salts configured. Use POST /api/kdf/salts/generate for new vault, "
            "or POST /api/kdf/salts/migrate to set specific salts (e.g., from backup).",
            404
        )
    salt_enc = bytes(row.kdf_salt_enc)
    salt_idx = bytes(row.kdf_salt_idx)
    return jsonify({
        "salt_enc": salt_enc.hex(),
        "salt_idx": salt_idx.hex(),
        "kdf_version": row.kdf_version,
    })


@app.post("/api/kdf/salts/generate")
def generate_kdf_salts():
    """Generate new random KDF salts for the current identity.
    
    Only allowed when no salts are set AND no records exist. If records exist
    but no salts, use POST /api/kdf/salts/migrate instead to preserve
    readability of existing records.
    """
    denied = require_access()
    if denied: return denied
    identity_id = current_identity_id()
    if not identity_id:
        return api_error("No identity", 403)
    table = models.VaultIdentity.__table__
    conn = db()
    row = conn.execute(
        select(table.c.kdf_salt_enc, table.c.kdf_salt_idx)
        .where(table.c.id == identity_id)
    ).first()
    if not row:
        return api_error("Identity not found", 404)
    if row.kdf_salt_enc is not None:
        return api_error("Salts already set. Use /migrate to change.", 409)
    # Check for existing records (would become unreadable)
    record_table = models.Record.__table__
    record_count = conn.execute(
        select(func.count()).select_from(record_table).where(
            record_table.c.identity_id == identity_id
        )
    ).scalar() or 0
    if record_count > 0:
        return api_error(
            "Records exist but no salts set. Use POST /api/kdf/salts/migrate "
            "with your current salts to preserve readability.", 409
        )
    import secrets
    salt_enc = secrets.token_bytes(16)
    salt_idx = secrets.token_bytes(16)
    conn.execute(
        update(table)
        .where(table.c.id == identity_id)
        .values(kdf_salt_enc=salt_enc, kdf_salt_idx=salt_idx, kdf_version=3, updated_at=func.now())
    )
    conn.commit()
    LOG.info('event="kdf_salts_generated" kdf_version=3 client="%s"', _client_log_id())
    return jsonify({
        "salt_enc": salt_enc.hex(),
        "salt_idx": salt_idx.hex(),
        "kdf_version": 3,
        "generated": True,
    })


@app.post("/api/kdf/salts/migrate")
def migrate_kdf_salts():
    """Migrate from browser-local salts to server salts, or set salts from backup.
    
    The client provides salts. The server stores them as the canonical salts.
    
    Two cases:
    1. Legacy migration: records exist but no server salts. Sets the client's
       current salts so existing records remain readable.
    2. Backup restore: no records exist yet, but salts were auto-generated during
       unlock. Allows overwriting with backup's salts (with explicit `force` flag).
    
    This is a one-time operation per identity, unless `force` is used for the
    empty-vault restore case.
    """
    denied = require_access()
    if denied: return denied
    identity_id = current_identity_id()
    if not identity_id:
        return api_error("No identity", 403)
    payload, error = _json_object()
    if error: return error
    salt_enc_hex = payload.get("salt_enc")
    salt_idx_hex = payload.get("salt_idx")
    force = payload.get("force", False)
    if not salt_enc_hex or not salt_idx_hex:
        return api_error("salt_enc and salt_idx required", 400)
    # kdf_version is REQUIRED and stored in the same UPDATE as the salts.
    # Salts without their KDF version make the next unlock derive different
    # keys (docs/CLOUD_RUN_TROUBLESHOOTING.md, bug D). No default: the only
    # client (importBackup) always sends it.
    kdf_version = payload.get("kdf_version")
    if type(kdf_version) is not int or kdf_version not in KDF_VERSIONS:
        return api_error("kdf_version required: one of 1, 2, 3", 400)
    try:
        salt_enc = bytes.fromhex(salt_enc_hex)
        salt_idx = bytes.fromhex(salt_idx_hex)
        if len(salt_enc) != 16 or len(salt_idx) != 16:
            raise ValueError("Invalid salt length")
    except (ValueError, TypeError):
        return api_error("Invalid salt format (must be 32 hex chars)", 400)
    
    table = models.VaultIdentity.__table__
    conn = db()
    row = conn.execute(
        select(table.c.kdf_salt_enc, table.c.kdf_salt_idx)
        .where(table.c.id == identity_id)
    ).first()
    if not row:
        return api_error("Identity not found", 404)
    if row.kdf_salt_enc is not None and not force:
        return api_error("Salts already set. Use force=true to overwrite (empty vault only).", 409)
    if row.kdf_salt_enc is not None and force:
        # Only allow force-overwrite if no records exist (fresh vault restore)
        record_table = models.Record.__table__
        record_count = conn.execute(
            select(func.count()).select_from(record_table).where(
                record_table.c.identity_id == identity_id
            )
        ).scalar() or 0
        if record_count > 0:
            return api_error(
                "Cannot overwrite salts: records exist. This would make them unreadable.", 409
            )
        LOG.warning('event="kdf_salts_force_overwritten" client="%s"', _client_log_id())

    values = dict(kdf_salt_enc=salt_enc, kdf_salt_idx=salt_idx, kdf_version=kdf_version, updated_at=func.now())
    if row.kdf_salt_enc is not None and force:
        # New salts on an empty vault mean a new vault key; the old key's ZK
        # commitment is stale. Clearing it only disables v4 proofs until the
        # new key re-enrolls (which needs a passkey step-up).
        values.update(zkp_key_commitment=None, zkp_vault_salt=None)
    conn.execute(update(table).where(table.c.id == identity_id).values(**values))
    conn.commit()
    LOG.info('event="kdf_salts_migrated" kdf_version=%d client="%s"', kdf_version, _client_log_id())
    return jsonify({"migrated": True})


@app.get("/api/audit/events")
def list_audit_events():
    """List audit events for incident response. Requires authentication."""
    denied = require_access()
    if denied: return denied
    # Query params: event_type, limit (default 50, max 200), offset
    event_type = request.args.get("event_type")
    try:
        limit = min(int(request.args.get("limit", "50")), 200)
        offset = max(int(request.args.get("offset", "0")), 0)
    except ValueError:
        return api_error("Invalid limit or offset", 400)
    table = models.AuditEvent.__table__
    identity_id = current_identity_id()
    if not identity_id:
        return api_error("No identity", 403)
    # Always scope to the current identity (tenant isolation)
    query = select(table).where(table.c.identity_id == identity_id).order_by(table.c.occurred_at.desc()).limit(limit).offset(offset)
    if event_type:
        query = query.where(table.c.event_type == event_type)
    rows = db().execute(query).mappings().all()
    events = []
    for row in rows:
        events.append({
            "id": row["id"],
            "occurred_at": row["occurred_at"].isoformat() if row["occurred_at"] else None,
            "event_type": row["event_type"],
            "client_ref": row["client_ref"],
            "client_ip": row["client_ip"],  # null unless VAULT_IP_LOGGING=on
            "acknowledged_at": row["acknowledged_at"].isoformat() if row["acknowledged_at"] else None,
            "acknowledged_by": row["acknowledged_by"],
            "detail": row["detail"],
        })
    return jsonify({"events": events, "limit": limit, "offset": offset})


@app.post("/api/audit/events/<int:event_id>/acknowledge")
def acknowledge_audit_event(event_id):
    """Mark an audit event as reviewed. Creates an INCIDENT_ACKNOWLEDGED audit trail entry."""
    denied = require_access()
    if denied: return denied
    table = models.AuditEvent.__table__
    conn = db()
    identity_id = current_identity_id()
    # Verify the event exists AND belongs to this identity (tenant isolation)
    existing = conn.execute(
        select(table.c.id).where(
            table.c.id == event_id,
            table.c.identity_id == identity_id,
        )
    ).first()
    if not existing:
        return api_error("Event not found", 404)
    # Mark as acknowledged (scoped to this identity)
    conn.execute(
        update(table)
        .where(table.c.id == event_id, table.c.identity_id == identity_id)
        .values(acknowledged_at=func.now(), acknowledged_by=identity_id)
    )
    _audit_event("INCIDENT_ACKNOWLEDGED", detail={"acknowledged_event_id": event_id})
    conn.commit()
    LOG.info('event="incident_acknowledged" event_id=%d client="%s"', event_id, _client_log_id())
    return jsonify({"acknowledged": True, "event_id": event_id})


# ------------------------------------------------------------------
# Recovery key mechanism
# ------------------------------------------------------------------

@app.post("/api/recovery/setup")
def recovery_setup():
    """Store an encrypted recovery blob.
    
    The client generates a random 256-bit recovery key, encrypts the vault
    seed with it, and sends only the ciphertext (blob) to the server.
    The server never sees the recovery key or the plaintext seed.
    
    The client displays the recovery key to the user ONCE as a mnemonic.
    If the user loses their passphrase, they can enter the recovery key
    to decrypt the seed and set a new passphrase.
    """
    denied = require_access()
    if denied: return denied
    identity_id = current_identity_id()
    if not identity_id:
        return api_error("No identity", 403)
    
    data = request.get_json(force=True, silent=True) or {}
    blob_hex = data.get("recovery_blob")
    if not blob_hex or not isinstance(blob_hex, str):
        return api_error("Missing recovery_blob", 400)
    try:
        blob = bytes.fromhex(blob_hex)
    except ValueError:
        return api_error("Invalid recovery_blob format", 400)
    if len(blob) < 32 or len(blob) > 1024:
        return api_error("Invalid recovery_blob length", 400)
    
    table = models.VaultIdentity.__table__
    conn = db()
    # Only allow setup if not already set (prevent overwrite without explicit delete)
    row = conn.execute(
        select(table.c.recovery_blob).where(table.c.id == identity_id)
    ).first()
    if row and row.recovery_blob is not None:
        return api_error("Recovery already set up. Delete existing recovery first.", 409)
    
    conn.execute(
        update(table)
        .where(table.c.id == identity_id)
        .values(recovery_blob=blob, recovery_created_at=func.now(), updated_at=func.now())
    )
    conn.commit()
    LOG.info('event="recovery_setup" client="%s"', _client_log_id())
    return jsonify({"ok": True})


@app.get("/api/recovery/blob")
def recovery_get_blob():
    """Retrieve the encrypted recovery blob.
    
    Requires passkey authentication (not just session). The blob is useless
    without the recovery key, which the server never sees.
    """
    # Bug L: this used to check session["passkey_authenticated"], which
    # nothing set and the server session store cannot hold, so it always
    # returned 403. The gate is now the existing destructive-management
    # check: a registered passkey, a passkey-authenticated session, and a
    # WebAuthn assertion within VAULT_STEPUP_WINDOW_SECONDS. A user who
    # forgot the passphrase can still pass it with their passkey.
    denied = require_destructive_management()
    if denied: return denied
    identity_id = current_identity_id()
    if not identity_id:
        return api_error("No identity", 403)
    
    table = models.VaultIdentity.__table__
    conn = db()
    row = conn.execute(
        select(table.c.recovery_blob).where(table.c.id == identity_id)
    ).first()
    if not row or row.recovery_blob is None:
        return api_error("No recovery blob set up", 404)
    
    LOG.info('event="recovery_blob_accessed" client="%s"', _client_log_id())
    return jsonify({"recovery_blob": row.recovery_blob.hex()})


@app.post("/api/recovery/delete")
def recovery_delete():
    """Delete the recovery blob. Requires passkey authentication."""
    denied = require_destructive_management()  # same gate as the blob fetch (bug L)
    if denied: return denied
    identity_id = current_identity_id()
    if not identity_id:
        return api_error("No identity", 403)
    
    table = models.VaultIdentity.__table__
    conn = db()
    conn.execute(
        update(table)
        .where(table.c.id == identity_id)
        .values(recovery_blob=None, recovery_created_at=None, updated_at=func.now())
    )
    conn.commit()
    LOG.info('event="recovery_deleted" client="%s"', _client_log_id())
    return jsonify({"ok": True})


@app.get("/api/recovery/status")
def recovery_status():
    """Whether a recovery blob exists (no blob content). Session access only,
    so the UI can show the state without a passkey step-up."""
    denied = require_access()
    if denied: return denied
    table = models.VaultIdentity.__table__
    blob = db().execute(select(table.c.recovery_blob).where(table.c.id == current_identity_id())).scalar()
    return jsonify({"set_up": blob is not None})


# ------------------------------------------------------------------
# Vault rekey: atomic re-encryption under new keys (bug M, K)
# ------------------------------------------------------------------
# Design and crash-safety notes: docs/RECOVERY.md "Re-encryption (rekey)".

_LIVE_DIGEST_SQL = text(
    "SELECT count(*), coalesce(encode(sha256(convert_to(string_agg("
    "blind_index || ':' || md5(sealed), ',' ORDER BY blind_index), 'UTF8')), 'hex'), '') "
    "FROM records WHERE identity_id = :owner"
)


def _live_snapshot(conn, owner_id):
    count, digest = conn.execute(_LIVE_DIGEST_SQL, {"owner": owner_id}).one()
    return int(count), digest


def _active_rekey(conn, owner_id, rekey_id):
    rekeys = models.VaultRekey.__table__
    if not isinstance(rekey_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", rekey_id):
        return None
    return conn.execute(select(rekeys).where(
        (rekeys.c.id == rekey_id) & (rekeys.c.identity_id == owner_id)
        & (rekeys.c.expires_at > time.time()))).mappings().first()


@app.post("/api/vault/rekey/begin")
def rekey_begin():
    """Start a rekey. Requires a recent passkey assertion (like the recovery
    blob fetch). Replaces any earlier unfinished rekey of this vault."""
    denied = require_destructive_management()
    if denied: return denied
    owner_id = current_identity_id()
    payload, error = _json_object()
    if error: return error
    if payload: return api_error("Body must be empty", 400)
    conn = db()
    ident = models.VaultIdentity.__table__
    row = conn.execute(select(ident.c.kdf_salt_enc).where(ident.c.id == owner_id).with_for_update()).first()
    if not row or row.kdf_salt_enc is None:
        conn.rollback(); return api_error("Vault has no salts to replace", 409)
    rekeys = models.VaultRekey.__table__
    conn.execute(delete(rekeys).where(rekeys.c.identity_id == owner_id))
    count, digest = _live_snapshot(conn, owner_id)
    now = time.time()
    rekey_id = secrets.token_urlsafe(32)
    conn.execute(insert(rekeys).values(id=rekey_id, identity_id=owner_id, base_count=count,
                                       base_digest=digest, created_at=now, expires_at=now + REKEY_TTL_SECONDS))
    conn.commit()
    LOG.info('event="vault_rekey_begin" records=%d client="%s"', count, _client_log_id())
    return jsonify({"rekey_id": rekey_id, "record_count": count, "expires_in": REKEY_TTL_SECONDS})


@app.post("/api/vault/rekey/records")
def rekey_stage_records():
    """Stage one chunk of re-encrypted records. Same shape and limits as
    POST /api/records plus old_blind_index (the live record it replaces)."""
    denied = require_access()
    if denied: return denied
    owner_id = current_identity_id()
    payload, error = _json_object()
    if error: return error
    if set(payload) != {"rekey_id", "records"}: return api_error("Body must contain rekey_id and records", 400)
    rows = payload["records"]
    if not isinstance(rows, list): return api_error("records must be a list", 400)
    if len(rows) > MAX_RECORDS_PER_BATCH: return api_error("Record batch is too large", 413)
    validated, seen, seen_old = [], set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"blind_index", "old_blind_index", "sealed"}:
            return api_error("Invalid record", 400)
        blind, old, sealed = row["blind_index"], row["old_blind_index"], row["sealed"]
        if not isinstance(blind, str) or not _LOWER_HEX_64.fullmatch(blind): return api_error("Invalid record", 400)
        if not isinstance(old, str) or not _LOWER_HEX_64.fullmatch(old): return api_error("Invalid record", 400)
        if blind in seen or old in seen_old: return api_error("Duplicate record in batch", 400)
        if not isinstance(sealed, str) or not MIN_SEALED_HEX_LENGTH <= len(sealed) <= MAX_SEALED_HEX_LENGTH or len(sealed) % 2 or not _is_lower_hex(sealed):
            return api_error("Invalid record", 400)
        seen.add(blind); seen_old.add(old); validated.append((blind, old, sealed, len(sealed) // 2))
    conn = db()
    rk = _active_rekey(conn, owner_id, payload["rekey_id"])
    if not rk:
        conn.rollback(); return api_error("No active rekey with this id", 404)
    staged = models.VaultRekeyRecord.__table__
    have = conn.execute(select(func.count()).select_from(staged).where(staged.c.rekey_id == rk["id"])).scalar_one()
    if have + len(validated) > rk["base_count"]:
        conn.rollback(); return api_error("More records staged than the vault holds", 409)
    if validated:
        try:
            conn.execute(insert(staged), [
                {"rekey_id": rk["id"], "blind_index": b, "old_blind_index": o, "sealed": s_, "bytes": n}
                for b, o, s_, n in validated])
            conn.commit()
        except IntegrityError:
            conn.rollback(); return api_error("Record already staged", 409)
    return jsonify({"staged": have + len(validated)})


@app.post("/api/vault/rekey/commit")
def rekey_commit():
    """Swap in the staged records, new salts, KDF version and recovery blob
    in ONE transaction, then end every other session of this vault."""
    denied = require_access()
    if denied: return denied
    owner_id = current_identity_id()
    payload, error = _json_object()
    if error: return error
    keys = set(payload)
    if not {"rekey_id", "salt_enc", "salt_idx", "kdf_version"} <= keys or keys - {"rekey_id", "salt_enc", "salt_idx", "kdf_version", "recovery_blob", "zkp_key_commitment"}:
        return api_error("Invalid rekey commit", 400)
    salt_enc, salt_idx, version = payload["salt_enc"], payload["salt_idx"], payload["kdf_version"]
    for salt in (salt_enc, salt_idx):
        if not isinstance(salt, str) or not re.fullmatch(r"[0-9a-f]{32}", salt):
            return api_error("Salts must be 32 lowercase hex characters", 400)
    if salt_enc == salt_idx: return api_error("Salts must differ", 400)
    if type(version) is not int or version not in KDF_VERSIONS: return api_error("Invalid kdf_version", 400)
    blob_hex = payload.get("recovery_blob")
    if blob_hex is not None:
        if not isinstance(blob_hex, str) or not 64 <= len(blob_hex) <= 2048 or len(blob_hex) % 2 or not _is_lower_hex(blob_hex):
            return api_error("Invalid recovery_blob", 400)
    new_zkp_commitment = None
    if "zkp_key_commitment" in payload:
        new_zkp_commitment = _parse_zkp_key_commitment(payload["zkp_key_commitment"])
        if new_zkp_commitment is None: return api_error("Invalid zkp_key_commitment", 400)
    conn = db()
    ident = models.VaultIdentity.__table__
    row = conn.execute(select(ident.c.recovery_blob, ident.c.kdf_salt_enc, ident.c.zkp_key_commitment)
                       .where(ident.c.id == owner_id).with_for_update()).first()
    rk = _active_rekey(conn, owner_id, payload["rekey_id"])
    if not row or not rk:
        conn.rollback(); return api_error("No active rekey with this id", 404)
    # The ZK key commitment is derived from the vault key, so a rekey must
    # replace it in this same transaction (same salt, new key), exactly when
    # one is registered.
    if (row.zkp_key_commitment is None) != (new_zkp_commitment is None):
        conn.rollback()
        return api_error("zkp_key_commitment is required exactly when the vault has a registered ZK key commitment", 400)
    if (row.recovery_blob is None) != (blob_hex is None):
        conn.rollback()
        return api_error("recovery_blob is required exactly when the vault has a recovery key", 400)
    rekeys = models.VaultRekey.__table__
    count, digest = _live_snapshot(conn, owner_id)
    if (count, digest) != (rk["base_count"], rk["base_digest"]):
        conn.execute(delete(rekeys).where(rekeys.c.id == rk["id"])); conn.commit()
        return api_error("The vault changed during re-encryption. Nothing was changed; start again.", 409)
    staged = models.VaultRekeyRecord.__table__
    records = models.Record.__table__
    staged_count = conn.execute(select(func.count()).select_from(staged).where(staged.c.rekey_id == rk["id"])).scalar_one()
    matched = conn.execute(select(func.count()).select_from(staged.join(
        records, (records.c.identity_id == owner_id) & (records.c.blind_index == staged.c.old_blind_index)
    )).where(staged.c.rekey_id == rk["id"])).scalar_one()
    if staged_count != count or matched != count:
        conn.rollback()
        return api_error("The re-encrypted set does not replace every record exactly once. Nothing was changed.", 409)
    # Public ZK commitments (not secrets) follow their record to its new index.
    carried = conn.execute(select(staged.c.blind_index, records.c.commitment, records.c.circuit_version).select_from(
        staged.join(records, (records.c.identity_id == owner_id) & (records.c.blind_index == staged.c.old_blind_index))
    ).where((staged.c.rekey_id == rk["id"]) & records.c.commitment.is_not(None)
            # A v4 record's ciphertext was bound to the OLD key; once the
            # browser re-seals it under the new key the v4 tag no longer
            # describes it, so it is not carried over.
            & (records.c.circuit_version != zkp_verifier.CIRCUIT_VERSION))).all()
    conn.execute(delete(records).where(records.c.identity_id == owner_id))
    conn.execute(insert(records).from_select(
        ["identity_id", "blind_index", "sealed", "bytes", "stored_at"],
        select(literal(owner_id, type_=records.c.identity_id.type), staged.c.blind_index, staged.c.sealed, staged.c.bytes, func.current_date())
        .where(staged.c.rekey_id == rk["id"])))
    for blind, commitment, circuit in carried:
        conn.execute(update(records).where((records.c.identity_id == owner_id) & (records.c.blind_index == blind))
                     .values(commitment=commitment, circuit_version=circuit))
    values = dict(kdf_salt_enc=bytes.fromhex(salt_enc), kdf_salt_idx=bytes.fromhex(salt_idx),
                  kdf_version=version, updated_at=func.now())
    if blob_hex is not None:
        values.update(recovery_blob=bytes.fromhex(blob_hex), recovery_created_at=func.now())
    if new_zkp_commitment is not None:
        values.update(zkp_key_commitment=new_zkp_commitment)
    conn.execute(update(ident).where(ident.c.id == owner_id).values(**values))
    conn.execute(delete(rekeys).where(rekeys.c.id == rk["id"]))
    sessions = models.ServerSession.__table__
    conn.execute(update(sessions).where(
        (sessions.c.identity_id == owner_id) & (sessions.c.session_id_hash != _sid_hash(session.sid))
        & sessions.c.revoked_at.is_(None)).values(revoked_at=time.time()))
    conn.commit()
    session["vault_unlocked"] = False
    LOG.info('event="vault_rekey_commit" records=%d client="%s"', count, _client_log_id())
    return jsonify({"rekeyed": True, "records": count})


@app.post("/api/vault/rekey/abort")
def rekey_abort():
    """Discard this vault's unfinished rekey, if any. The live vault was never
    touched, so this only unblocks writes before the TTL expires."""
    denied = require_access()
    if denied: return denied
    payload, error = _json_object()
    if error: return error
    if payload: return api_error("Body must be empty", 400)
    rekeys = models.VaultRekey.__table__
    conn = db()
    owner_id = current_identity_id()
    # Same lock as commit (FOR UPDATE): an abort waits for an in-progress
    # commit and then finds nothing to delete, so writes never interleave
    # with a commit (bug P).
    ident = models.VaultIdentity.__table__
    conn.execute(select(ident.c.id).where(ident.c.id == owner_id).with_for_update())
    gone = conn.execute(delete(rekeys).where(rekeys.c.identity_id == owner_id)).rowcount
    conn.commit()
    return jsonify({"aborted": bool(gone)})


# Kept last so every route above is registered before the dev server starts.
if __name__ == "__main__":
    if PRODUCTION:
        raise RuntimeError("Production must run app:app through the supported Gunicorn service")
    host=os.environ.get("VAULT_HOST","127.0.0.1")
    if AUTH_POLICY=="optional" and host not in {"127.0.0.1","::1","localhost"}: raise RuntimeError("Optional authentication may bind only to loopback")
    print(f"vault demo  ->  {ORIGIN}")
    app.run(host=host,port=int(os.environ.get("VAULT_PORT","5000")),debug=False)
