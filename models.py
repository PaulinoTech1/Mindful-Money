"""SQLAlchemy models for the vault's PostgreSQL-backed data layer.

Table shapes mirror the SQLite schema this replaces (see git history of
app.py's old _migrate()) with deliberate type upgrades where a naive port
would introduce a new bug -- see comments below, not a style preference.

Single-vault design is unchanged: vault_identity has exactly one row (id=1,
enforced below), never a users table. No multi-user, no admin roles.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    Double,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class VaultIdentity(Base):
    __tablename__ = "vault_identity"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Raw bytes, not base64url text: never serialized on its own, only
    # decoded back to bytes for WebAuthn's user_id parameter.
    user_handle: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    passkey_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())

    __table_args__ = (CheckConstraint("id = 1", name="ck_vault_identity_singleton"),)


class Record(Base):
    __tablename__ = "records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    blind_index: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # Hex text, not BYTEA: arrives from and returns to the client as a hex
    # JSON string unchanged: no library expects raw bytes here.
    sealed: Mapped[str] = mapped_column(Text, nullable=False)
    bytes_len: Mapped[int] = mapped_column("bytes", Integer, nullable=False)
    # Day granularity only, matching the old datetime('now','start of day')
    # truncation -- this only ever drives a GROUP BY write-day histogram.
    stored_at: Mapped[dt.date] = mapped_column(Date, nullable=False)


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identity_id: Mapped[int] = mapped_column(
        ForeignKey("vault_identity.id", ondelete="CASCADE"), nullable=False
    )
    # Raw bytes: the webauthn library already hands these back as bytes
    # (result.credential_id / result.credential_public_key).
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    credential_public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # BigInteger, not Integer: WebAuthn signCount is unsigned 32-bit
    # (up to ~4.29B); Postgres INTEGER is signed 32-bit (max ~2.15B).
    # SQLite's dynamic typing hid this; Postgres will not.
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    transports: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    device_type: Mapped[str | None] = mapped_column(Text)
    backed_up: Mapped[bool | None] = mapped_column(Boolean)
    label: Mapped[str] = mapped_column(String(80), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    last_used_at: Mapped[dt.datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class ServerSession(Base):
    __tablename__ = "server_sessions"

    # Epoch-float columns below (not TIMESTAMPTZ) deliberately: every one
    # of these is compared against time.time() throughout app.py's
    # security-critical session logic. Converting to datetimes would force
    # conversions through that code for no benefit.
    session_id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_token: Mapped[str] = mapped_column(Text, nullable=False)
    # Deliberately unconstrained, matching the original schema: a session
    # can be (and in tests, is) created via session_transaction() before
    # vault_identity's singleton row is guaranteed to exist.
    identity_id: Mapped[int | None] = mapped_column(Integer)
    authenticated_at: Mapped[float | None] = mapped_column(Double)
    vault_unlocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active_ceremony_id: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[float] = mapped_column(Double, nullable=False)
    last_seen_at: Mapped[float] = mapped_column(Double, nullable=False)
    expires_at: Mapped[float] = mapped_column(Double, nullable=False, index=True)
    revoked_at: Mapped[float | None] = mapped_column(Double)


class WebAuthnChallenge(Base):
    __tablename__ = "webauthn_challenges"

    ceremony_id: Mapped[str] = mapped_column(Text, primary_key=True)
    session_id_hash: Mapped[str] = mapped_column(
        ForeignKey("server_sessions.session_id_hash"), nullable=False, index=True
    )
    identity_id: Mapped[int | None] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(
        Enum(
            "registration",
            "authentication",
            name="webauthn_ceremony_kind",
            native_enum=False,
            create_constraint=True,
        ),
        nullable=False,
    )
    # Raw bytes: never leaves the server, only round-trips through
    # expected_challenge= on the server's own verification call.
    challenge: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[float] = mapped_column(Double, nullable=False)
    expires_at: Mapped[float] = mapped_column(Double, nullable=False)
    consumed_at: Mapped[float | None] = mapped_column(Double)


class RateLimit(Base):
    __tablename__ = "rate_limits"

    bucket_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    # BigInteger, not Integer: these are raw Unix epoch seconds. SQLite's
    # INTEGER is already 64-bit; a naive Postgres INTEGER (32-bit, max
    # Jan 2038) would introduce a new ceiling that didn't exist before.
    window_start: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    occurred_at: Mapped[dt.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    event_type: Mapped[str] = mapped_column(
        Enum(
            # No LOGIN_SUCCESS/LOGIN_FAILURE: this app has no login
            # mechanism separate from passkey authentication, so those
            # would just duplicate PASSKEY_AUTH_SUCCESS/FAILURE below.
            "PASSKEY_REGISTERED",
            "PASSKEY_REMOVED",
            "PASSKEY_AUTH_SUCCESS",
            "PASSKEY_AUTH_FAILURE",
            "PASSKEY_PROTECTION_DISABLED",
            "SESSION_REVOKED",
            "SUSPICIOUS_COUNTER_EVENT",
            name="audit_event_type",
            native_enum=False,
            create_constraint=True,
        ),
        nullable=False,
        index=True,
    )
    identity_id: Mapped[int | None] = mapped_column(
        ForeignKey("vault_identity.id", ondelete="SET NULL")
    )
    # Same HMAC-truncated scheme as app.py's _client_log_id(), not a raw
    # IP address -- matches the app's existing privacy convention for the
    # identical purpose (rate-limit bucketing).
    client_ref: Mapped[str] = mapped_column(String(12), nullable=False)
    credential_id: Mapped[bytes | None] = mapped_column(LargeBinary)
    # Never contains secrets, challenges, session tokens, or private keys.
    detail: Mapped[dict | None] = mapped_column(JSONB)
