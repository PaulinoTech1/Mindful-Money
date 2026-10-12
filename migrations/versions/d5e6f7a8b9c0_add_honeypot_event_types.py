"""add honeypot and lockout event types

Revision ID: d5e6f7a8b9c0
Revises: c4d9e3f2a1b6
Create Date: 2026-10-11 00:00:00.000000

Adds HONEYPOT_HIT, ACCOUNT_LOCKED, and STEP_UP_REQUIRED to the
audit_event_type CHECK constraint.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, None] = "c4d9e3f2a1b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The CHECK constraint needs to be dropped and recreated with new values.
    # Get the constraint name first.
    conn = op.get_bind()
    # Drop old constraint
    op.execute(sa.text(
        "ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS "
        "audit_events_event_type_check"
    ))
    # Recreate with new values
    op.execute(sa.text(
        "ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check "
        "CHECK (event_type IN ("
        "'PASSKEY_REGISTERED', 'PASSKEY_REMOVED', 'PASSKEY_AUTH_SUCCESS', "
        "'PASSKEY_AUTH_FAILURE', 'PASSKEY_PROTECTION_DISABLED', "
        "'SESSION_REVOKED', 'SUSPICIOUS_COUNTER_EVENT', "
        "'UNUSUAL_ACTIVITY_DETECTED', 'INCIDENT_ACKNOWLEDGED', "
        "'HONEYPOT_HIT', 'ACCOUNT_LOCKED', 'STEP_UP_REQUIRED'"
        "))"
    ))


def downgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS "
        "audit_events_event_type_check"
    ))
    op.execute(sa.text(
        "ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check "
        "CHECK (event_type IN ("
        "'PASSKEY_REGISTERED', 'PASSKEY_REMOVED', 'PASSKEY_AUTH_SUCCESS', "
        "'PASSKEY_AUTH_FAILURE', 'PASSKEY_PROTECTION_DISABLED', "
        "'SESSION_REVOKED', 'SUSPICIOUS_COUNTER_EVENT', "
        "'UNUSUAL_ACTIVITY_DETECTED', 'INCIDENT_ACKNOWLEDGED'"
        "))"
    ))
