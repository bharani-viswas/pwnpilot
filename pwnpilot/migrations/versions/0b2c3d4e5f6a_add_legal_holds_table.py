"""add_legal_holds_table

Revision ID: 0b2c3d4e5f6a
Revises: 9a1b2c3d4e5f
Create Date: 2026-04-19 10:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0b2c3d4e5f6a'
down_revision: Union[str, Sequence[str], None] = '9a1b2c3d4e5f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - Add legal_holds table for retention governance."""
    # Create LegalHold table for legal hold storage and compliance
    op.create_table('legal_holds',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('engagement_id', sa.String(length=36), nullable=False),
    sa.Column('holder', sa.String(length=256), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('placed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('released_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('released_by', sa.String(length=256), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('engagement_id', name='uq_legal_holds_engagement_id')
    )
    with op.batch_alter_table('legal_holds', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_legal_holds_engagement_id'), ['engagement_id'], unique=True)
        batch_op.create_index(batch_op.f('ix_legal_holds_placed_at'), ['placed_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_legal_holds_released_at'), ['released_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema - Drop legal_holds table."""
    with op.batch_alter_table('legal_holds', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_legal_holds_released_at'))
        batch_op.drop_index(batch_op.f('ix_legal_holds_placed_at'))
        batch_op.drop_index(batch_op.f('ix_legal_holds_engagement_id'))
    op.drop_table('legal_holds')
