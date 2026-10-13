"""add vault rekey staging tables

Revision ID: a7b8c9d0e1f2
Revises: f1a2b3c4d5e6
Create Date: 2026-10-13 00:00:00.000000

Staging for atomic vault re-encryption (recovery with a new passphrase).
Re-encrypted records are uploaded in chunks to vault_rekey_records and
swapped into records with the new salts in one transaction. The server
stores only opaque ciphertext and blind indexes, as in records.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a7b8c9d0e1f2"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vault_rekeys",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("identity_id", sa.Integer(),
                  sa.ForeignKey("vault_identity.id", ondelete="CASCADE"), nullable=False),
        sa.Column("base_count", sa.Integer(), nullable=False),
        sa.Column("base_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.Double(), nullable=False),
        sa.Column("expires_at", sa.Double(), nullable=False),
        sa.UniqueConstraint("identity_id", name="vault_rekeys_identity_id_key"),
    )
    op.create_index("ix_vault_rekeys_expires_at", "vault_rekeys", ["expires_at"])
    op.create_table(
        "vault_rekey_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rekey_id", sa.String(length=64),
                  sa.ForeignKey("vault_rekeys.id", ondelete="CASCADE"), nullable=False),
        sa.Column("blind_index", sa.String(length=64), nullable=False),
        sa.Column("old_blind_index", sa.String(length=64), nullable=False),
        sa.Column("sealed", sa.Text(), nullable=False),
        sa.Column("bytes", sa.Integer(), nullable=False),
        sa.UniqueConstraint("rekey_id", "blind_index", name="uq_rekey_records_blind_index"),
        sa.UniqueConstraint("rekey_id", "old_blind_index", name="uq_rekey_records_old_blind_index"),
    )
    op.create_index("ix_vault_rekey_records_rekey_id", "vault_rekey_records", ["rekey_id"])


def downgrade() -> None:
    op.drop_index("ix_vault_rekey_records_rekey_id", table_name="vault_rekey_records")
    op.drop_table("vault_rekey_records")
    op.drop_index("ix_vault_rekeys_expires_at", table_name="vault_rekeys")
    op.drop_table("vault_rekeys")
