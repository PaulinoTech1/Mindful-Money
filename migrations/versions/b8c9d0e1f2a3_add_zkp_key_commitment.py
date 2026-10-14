"""add zkp key commitment and vault salt to vault_identity

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-10-14 00:00:00.000000

ZK proof v4 binds the prover's key to a commitment registered per vault
(docs/ZKP_BINDING.md). Both columns are nullable and public: the salt is
server-generated randomness and the commitment is a Poseidon2 hash of a
248-bit browser-only secret. Additive only; existing rows stay NULL until
the vault enrolls, so this migration is safe to run before the app deploy.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b8c9d0e1f2a3"
down_revision: Union[str, Sequence[str], None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("vault_identity", sa.Column("zkp_key_commitment", sa.LargeBinary(), nullable=True))
    op.add_column("vault_identity", sa.Column("zkp_vault_salt", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column("vault_identity", "zkp_vault_salt")
    op.drop_column("vault_identity", "zkp_key_commitment")
