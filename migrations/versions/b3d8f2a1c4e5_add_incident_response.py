"""add incident response and opt-in IP logging to audit events

Revision ID: b3d8f2a1c4e5
Revises: 9c1e4a7b2d10
Create Date: 2026-10-11 00:00:00.000000

Adds incident response capabilities to the audit trail:
- acknowledged_at/acknowledged_by columns for marking events as reviewed
- client_ip column for opt-in full IP logging (null by default)
- New event types: UNUSUAL_ACTIVITY_DETECTED, INCIDENT_ACKNOWLEDGED
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "b3d8f2a1c4e5"
down_revision: Union[str, Sequence[str], None] = "9c1e4a7b2d10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add incident response columns
    op.add_column(
        "audit_events",
        sa.Column("acknowledged_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "audit_events",
        sa.Column("acknowledged_by", sa.Integer(), nullable=True),
    )
    # Opt-in IP logging: null unless VAULT_IP_LOGGING=on
    op.add_column(
        "audit_events",
        sa.Column("client_ip", sa.String(45), nullable=True),
    )
    op.create_foreign_key(
        "fk_audit_events_acknowledged_by",
        "audit_events",
        "vault_identity",
        ["acknowledged_by"],
        ["id"],
        ondelete="SET NULL",
    )
    # Add new event types to the CHECK constraint
    # Note: The event_type column uses a CHECK constraint (not a native PG enum),
    # so we drop and recreate the constraint with the expanded value list.
    # This mirrors the approach in d5e6f7a8b9c0_add_honeypot_event_types.py.
    conn = op.get_bind()
    result = conn.execute(sa.text("""
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'audit_events'::regclass
        AND contype = 'c'
        AND pg_get_constraintdef(oid) LIKE '%event_type%'
    """))
    for row in result:
        op.execute(sa.text(f'ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS "{row[0]}"'))
    op.execute(sa.text(
        "ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check "
        "CHECK (event_type IN ("
        "'PASSKEY_REGISTERED', 'PASSKEY_REMOVED', 'PASSKEY_AUTH_SUCCESS', "
        "'PASSKEY_AUTH_FAILURE', 'PASSKEY_PROTECTION_DISABLED', "
        "'SESSION_REVOKED', 'SUSPICIOUS_COUNTER_EVENT', "
        "'UNUSUAL_ACTIVITY_DETECTED', 'INCIDENT_ACKNOWLEDGED'"
        "))"
    ))


def downgrade() -> None:
    op.drop_constraint(
        "fk_audit_events_acknowledged_by", "audit_events", type_="foreignkey"
    )
    op.drop_column("audit_events", "client_ip")
    op.drop_column("audit_events", "acknowledged_by")
    op.drop_column("audit_events", "acknowledged_at")
    # Note: PostgreSQL cannot remove enum values; they remain but are unused
