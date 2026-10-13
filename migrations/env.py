import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

import models

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Same env var app.py/db.py read, so migrations always target whatever
# database the app itself is currently pointed at -- dev, test, or prod.
_db_url = os.environ.get("VAULT_DATABASE_URL", "").strip()
if not _db_url:
    # Fail fast and loudly. A missing or empty URL (for example a failed
    # `gcloud secrets versions access` inside $(...)) must never let Alembic
    # guess a target. The message never echoes the value.
    raise SystemExit(
        "VAULT_DATABASE_URL is empty or unset. Refusing to run migrations. "
        "See docs/RUNBOOK.md 'Database migrations' (use the UNPOOLED Neon URL)."
    )
if "://" not in _db_url or not _db_url.startswith("postgresql+psycopg://"):
    raise SystemExit(
        "VAULT_DATABASE_URL must start with postgresql+psycopg:// (the image ships "
        "psycopg 3 only). Value not shown. See docs/RUNBOOK.md 'Database migrations'."
    )
if _db_url.count("postgresql+psycopg://") != 1:
    raise SystemExit(
        "VAULT_DATABASE_URL contains the driver prefix more than once (see the "
        "2026-10-13 incident in docs/CLOUD_RUN_TROUBLESHOOTING.md). Value not shown."
    )
from sqlalchemy.engine import make_url as _make_url
if "-pooler" in (_make_url(_db_url).host or ""):
    raise SystemExit(
        "VAULT_DATABASE_URL points at the Neon pooler host. DDL must use the "
        "UNPOOLED connection string. See docs/RUNBOOK.md 'Database migrations'."
    )
# configparser treats % as interpolation; escape so URL-encoded passwords survive.
config.set_main_option("sqlalchemy.url", _db_url.replace("%", "%%"))

target_metadata = models.Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata, compare_type=True
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
