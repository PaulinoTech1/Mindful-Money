"""add tenant ownership to encrypted records and ZKP challenges

Revision ID: 9c1e4a7b2d10
Revises: 7f3c9a1e2b6d
Create Date: 2026-09-03 00:00:00.000000

Existing ciphertext is assigned to identity 1, the legacy compatibility
tenant. No encrypted payload or blind index is rewritten.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "9c1e4a7b2d10"
down_revision: Union[str, Sequence[str], None] = "7f3c9a1e2b6d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Establish identity_id as the database-enforced tenant boundary."""
    op.drop_constraint("ck_vault_identity_singleton", "vault_identity", type_="check")

    op.add_column("records", sa.Column("identity_id", sa.Integer(), nullable=True))
    op.execute("UPDATE records SET identity_id = 1 WHERE identity_id IS NULL")
    op.alter_column("records", "identity_id", nullable=False)
    op.create_foreign_key(
        "fk_records_identity_id_vault_identity",
        "records",
        "vault_identity",
        ["identity_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint("records_blind_index_key", "records", type_="unique")
    op.create_unique_constraint(
        "uq_records_identity_blind_index", "records", ["identity_id", "blind_index"]
    )
    op.create_index(op.f("ix_records_identity_id"), "records", ["identity_id"], unique=False)

    op.add_column("zkp_challenges", sa.Column("identity_id", sa.Integer(), nullable=True))
    op.execute(
        """
        UPDATE zkp_challenges AS z
        SET identity_id = COALESCE(
            (SELECT s.identity_id FROM server_sessions AS s
             WHERE s.session_id_hash = z.session_id_hash),
            1
        )
        WHERE z.identity_id IS NULL
        """
    )
    op.alter_column("zkp_challenges", "identity_id", nullable=False)
    op.create_foreign_key(
        "fk_zkp_challenges_identity_id_vault_identity",
        "zkp_challenges",
        "vault_identity",
        ["identity_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        op.f("ix_zkp_challenges_identity_id"), "zkp_challenges", ["identity_id"], unique=False
    )


def downgrade() -> None:
    """Restore the legacy shape when tenant data is compatible with it.

    Creating the old global uniqueness and singleton constraints first makes
    this fail safely instead of discarding data if more than one tenant exists.
    """
    op.drop_index(op.f("ix_zkp_challenges_identity_id"), table_name="zkp_challenges")
    op.drop_constraint(
        "fk_zkp_challenges_identity_id_vault_identity", "zkp_challenges", type_="foreignkey"
    )
    op.drop_column("zkp_challenges", "identity_id")

    op.drop_index(op.f("ix_records_identity_id"), table_name="records")
    op.drop_constraint("uq_records_identity_blind_index", "records", type_="unique")
    op.create_unique_constraint("records_blind_index_key", "records", ["blind_index"])
    op.drop_constraint("fk_records_identity_id_vault_identity", "records", type_="foreignkey")
    op.drop_column("records", "identity_id")

    op.create_check_constraint("ck_vault_identity_singleton", "vault_identity", "id = 1")
