"""add recovery blob to vault_identity

Revision ID: f1a2b3c4d5e6
Revises: e1f2a3b4c5d6
Create Date: 2026-10-12 00:00:00.000000

Adds an encrypted recovery blob for the recovery key mechanism.
The blob contains the vault seed encrypted with the recovery key.
The server never sees the recovery key or the plaintext seed.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "e1f2a3b4c5d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vault_identity",
        sa.Column("recovery_blob", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "vault_identity",
        sa.Column("recovery_created_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vault_identity", "recovery_created_at")
    op.drop_column("vault_identity", "recovery_blob")
