"""add honeypot and lockout event types

Revision ID: d5e6f7a8b9c0
Revises: c4d9e3f2a1b6
Create Date: 2026-10-11 00:00:00.000000

Adds HONEYPOT_HIT, ACCOUNT_LOCKED, and STEP_UP_REQUIRED to the
audit_event_type CHECK constraint.

Note: SQLAlchemy's Enum with create_constraint=True generates a CHECK
constraint. The exact name varies by SQLAlchemy version. This migration
drops any existing constraint on event_type and recreates it.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, None] = "c4d9e3f2a1b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NEW_VALUES = (
    "'PASSKEY_REGISTERED', 'PASSKEY_REMOVED', 'PASSKEY_AUTH_SUCCESS', "
    "'PASSKEY_AUTH_FAILURE', 'PASSKEY_PROTECTION_DISABLED', "
    "'SESSION_REVOKED', 'SUSPICIOUS_COUNTER_EVENT', "
    "'UNUSUAL_ACTIVITY_DETECTED', 'INCIDENT_ACKNOWLEDGED', "
    "'HONEYPOT_HIT', 'ACCOUNT_LOCKED', 'STEP_UP_REQUIRED'"
)

OLD_VALUES = (
    "'PASSKEY_REGISTERED', 'PASSKEY_REMOVED', 'PASSKEY_AUTH_SUCCESS', "
    "'PASSKEY_AUTH_FAILURE', 'PASSKEY_PROTECTION_DISABLED', "
    "'SESSION_REVOKED', 'SUSPICIOUS_COUNTER_EVENT', "
    "'UNUSUAL_ACTIVITY_DETECTED', 'INCIDENT_ACKNOWLEDGED'"
)


def _drop_event_type_constraints():
    """Drop any CHECK constraint on audit_events.event_type, regardless of name."""
    conn = op.get_bind()
    # Find all check constraints on the event_type column
    result = conn.execute(sa.text("""
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'audit_events'::regclass
        AND contype = 'c'
        AND pg_get_constraintdef(oid) LIKE '%event_type%'
    """))
    for row in result:
        conname = row[0]
        op.execute(sa.text(f'ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS "{conname}"'))


def upgrade() -> None:
    _drop_event_type_constraints()
    op.execute(sa.text(
        "ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check "
        f"CHECK (event_type IN ({NEW_VALUES}))"
    ))


def downgrade() -> None:
    _drop_event_type_constraints()
    op.execute(sa.text(
        "ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check "
        f"CHECK (event_type IN ({OLD_VALUES}))"
    ))
