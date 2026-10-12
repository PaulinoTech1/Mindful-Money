"""add performance indexes

Revision ID: e1f2a3b4c5d6
Revises: d5e6f7a8b9c0
Create Date: 2026-10-12 00:00:00.000000

Adds missing indexes identified in performance audit:
- audit_events.identity_id (for lockout check, dashboard queries)
- Composite index on (identity_id, occurred_at) for time-range queries
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e1f2a3b4c5d6"
down_revision: Union[str, None] = "d5e6f7a8b9c0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_audit_events_identity_id",
        "audit_events",
        ["identity_id"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_audit_events_identity_occurred",
        "audit_events",
        ["identity_id", "occurred_at"],
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_identity_occurred", "audit_events", if_exists=True)
    op.drop_index("ix_audit_events_identity_id", "audit_events", if_exists=True)
