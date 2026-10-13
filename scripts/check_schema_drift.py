"""Fail if models.py and the Alembic migrations disagree (bugs O and R).

Run against a FRESH database that has had `alembic upgrade head` applied:
    VAULT_DATABASE_URL=... python scripts/check_schema_drift.py
Compares types and server defaults too. Prints only the diff, never the URL.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alembic.autogenerate import compare_metadata  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import models  # noqa: E402

engine = create_engine(os.environ["VAULT_DATABASE_URL"])
with engine.connect() as conn:
    ctx = MigrationContext.configure(conn, opts={"compare_type": True, "compare_server_default": True})
    diff = compare_metadata(ctx, models.Base.metadata)
engine.dispose()
if diff:
    print("Schema drift between models.py and migrations:")
    for d in diff:
        print("  ", d)
    sys.exit(1)
print("No schema drift (compare_type and compare_server_default on).")
