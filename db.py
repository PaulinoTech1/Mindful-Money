"""Flask request-scoped SQLAlchemy engine/session lifecycle.

Mirrors the old app.py pattern (_connect() / db() / _close()) almost
exactly: a lazily-created, request-scoped connection stored on Flask's
`g`, disposed in app teardown. The one thing this replaces beyond a
straight driver swap is documented on _ensure_identity() below.
"""

from __future__ import annotations

import os
import secrets

from flask import g
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

import models

_DEFAULT_URL = "postgresql+psycopg://vault:vault_dev_only_password@localhost:5432/vault_dev"
_url = os.environ.get("VAULT_DATABASE_URL", _DEFAULT_URL)
_engine = None
_SessionFactory = None


def _ensure_bound() -> None:
    global _engine, _SessionFactory
    if _engine is None:
        _engine = create_engine(_url, pool_pre_ping=True, pool_size=5, max_overflow=10, future=True)
        _SessionFactory = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False, future=True)


def get_engine():
    _ensure_bound()
    return _engine


def db() -> Session:
    if "db" not in g:
        _ensure_bound()
        g.db = _SessionFactory()
        _seed_identity(g.db)
    return g.db


def init_app(app) -> None:
    @app.teardown_appcontext
    def _close(exc):
        sess = g.pop("db", None)
        if sess is not None:
            if exc is not None:
                sess.rollback()
            sess.close()


def rebind(url: str) -> None:
    """Test-only: repoint subsequent db()/get_engine() calls at a different database."""
    global _engine, _SessionFactory, _url
    if _engine is not None:
        _engine.dispose()
    _url, _engine, _SessionFactory = url, None, None


def _seed_identity(session: Session) -> None:
    """Idempotently create the single vault_identity row if it's missing.

    The old SQLite _migrate() ran a full CREATE TABLE script (schema DDL,
    now Alembic's job) on every request, which also had the side effect
    of self-healing this singleton row if it was ever missing. That
    self-healing behavior is relied on implicitly (e.g. tests that GET
    /api/passkeys/status purely to guarantee the row exists before
    mutating it directly), so it's preserved here as a cheap per-request
    idempotent upsert on first DB access, rather than dropped along with
    the DDL.
    """
    stmt = (
        pg_insert(models.VaultIdentity.__table__)
        .values(id=1, user_handle=secrets.token_bytes(32))
        .on_conflict_do_nothing(index_elements=["id"])
    )
    session.execute(stmt)
    session.commit()
