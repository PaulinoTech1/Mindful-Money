"""add KDF salts to vault_identity for server-side salt storage

Revision ID: c4d9e3f2a1b6
Revises: b3d8f2a1c4e5
Create Date: 2026-10-11 00:00:00.000000

Stores per-identity KDF salts server-side so clients can retrieve them
after authentication. Salts are not secret, just unique. This fixes the
data-recovery problem where browser-localStorage salts were lost if the
browser data was cleared.

For existing identities, salts are NULL. The client will generate random
salts, store them via the API, and migrate existing records.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c4d9e3f2a1b6"
down_revision: Union[str, Sequence[str], None] = "b3d8f2a1c4e5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vault_identity",
        sa.Column("kdf_salt_enc", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "vault_identity",
        sa.Column("kdf_salt_idx", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "vault_identity",
        sa.Column("kdf_version", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("vault_identity", "kdf_version")
    op.drop_column("vault_identity", "kdf_salt_idx")
    op.drop_column("vault_identity", "kdf_salt_enc")
