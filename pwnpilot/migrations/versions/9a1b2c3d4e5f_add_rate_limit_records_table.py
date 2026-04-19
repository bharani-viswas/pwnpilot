"""add_rate_limit_records_table

Revision ID: 9a1b2c3d4e5f
Revises: 8f2a1c3b4d5e
Create Date: 2026-04-19 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a1b2c3d4e5f'
down_revision: Union[str, Sequence[str], None] = '8f2a1c3b4d5e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - Add rate_limit_records table for policy engine."""
    # Create RateLimitRecord table for persistent rate limiting
    op.create_table('rate_limit_records',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('engagement_id', sa.String(length=36), nullable=False),
    sa.Column('action_class', sa.String(length=64), nullable=False),
    sa.Column('timestamp', sa.Float(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('rate_limit_records', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_rate_limit_records_engagement_id'), ['engagement_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_rate_limit_records_action_class'), ['action_class'], unique=False)
        batch_op.create_index(batch_op.f('ix_rate_limit_records_timestamp'), ['timestamp'], unique=False)
        batch_op.create_index(
            'ix_rate_limit_records_composite',
            ['engagement_id', 'action_class'],
            unique=False
        )


def downgrade() -> None:
    """Downgrade schema - Drop rate_limit_records table."""
    with op.batch_alter_table('rate_limit_records', schema=None) as batch_op:
        batch_op.drop_index('ix_rate_limit_records_composite')
        batch_op.drop_index(batch_op.f('ix_rate_limit_records_timestamp'))
        batch_op.drop_index(batch_op.f('ix_rate_limit_records_action_class'))
        batch_op.drop_index(batch_op.f('ix_rate_limit_records_engagement_id'))
    op.drop_table('rate_limit_records')
