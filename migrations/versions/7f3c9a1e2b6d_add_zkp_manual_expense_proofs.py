"""add zkp manual expense proof support

Revision ID: 7f3c9a1e2b6d
Revises: 42d39aa9055a
Create Date: 2026-09-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '7f3c9a1e2b6d'
down_revision: Union[str, Sequence[str], None] = '42d39aa9055a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('records', sa.Column('commitment', sa.String(length=64), nullable=True))
    op.add_column('records', sa.Column('circuit_version', sa.String(length=40), nullable=True))
    op.create_table(
        'zkp_challenges',
        sa.Column('challenge_id', sa.Text(), nullable=False),
        sa.Column('session_id_hash', sa.String(length=64), nullable=False),
        sa.Column('challenge', sa.LargeBinary(), nullable=False),
        sa.Column('record_id', sa.LargeBinary(), nullable=False),
        sa.Column(
            'purpose',
            sa.Enum('manual_expense_create', name='zkp_challenge_purpose', native_enum=False, create_constraint=True),
            nullable=False,
        ),
        sa.Column('circuit_version', sa.String(length=40), nullable=False),
        sa.Column('schema_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.Double(), nullable=False),
        sa.Column('expires_at', sa.Double(), nullable=False),
        sa.Column('consumed_at', sa.Double(), nullable=True),
        sa.ForeignKeyConstraint(['session_id_hash'], ['server_sessions.session_id_hash']),
        sa.PrimaryKeyConstraint('challenge_id'),
    )
    op.create_index(op.f('ix_zkp_challenges_session_id_hash'), 'zkp_challenges', ['session_id_hash'], unique=False)
    op.create_index(op.f('ix_zkp_challenges_expires_at'), 'zkp_challenges', ['expires_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_zkp_challenges_expires_at'), table_name='zkp_challenges')
    op.drop_index(op.f('ix_zkp_challenges_session_id_hash'), table_name='zkp_challenges')
    op.drop_table('zkp_challenges')
    op.drop_column('records', 'circuit_version')
    op.drop_column('records', 'commitment')
