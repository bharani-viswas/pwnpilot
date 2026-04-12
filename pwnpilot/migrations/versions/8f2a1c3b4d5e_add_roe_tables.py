"""add_roe_tables

Revision ID: 8f2a1c3b4d5e
Revises: 7c9029fd340a
Create Date: 2026-04-12 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8f2a1c3b4d5e'
down_revision: Union[str, Sequence[str], None] = '7c9029fd340a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create ROEFile table (immutable storage of ROE YAML files)
    op.create_table('roe_files',
    sa.Column('roe_id', sa.String(length=36), nullable=False),
    sa.Column('filename', sa.String(length=255), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('content_yaml', sa.Text(), nullable=False),
    sa.Column('uploaded_by', sa.String(length=255), nullable=False),
    sa.Column('uploaded_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
    sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
    sa.PrimaryKeyConstraint('roe_id')
    )
    with op.batch_alter_table('roe_files', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_roe_files_content_hash'), ['content_hash'], unique=False)
        batch_op.create_index(batch_op.f('ix_roe_files_uploaded_at'), ['uploaded_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_roe_files_is_active'), ['is_active'], unique=False)

    # Create EngagementPolicy table (derived policies from ROE for engagements)
    op.create_table('engagement_policies',
    sa.Column('policy_id', sa.String(length=36), nullable=False),
    sa.Column('engagement_id', sa.String(length=36), nullable=False),
    sa.Column('roe_id', sa.String(length=36), nullable=False),
    sa.Column('scope_cidrs', sa.Text(), nullable=False),  # JSON array
    sa.Column('scope_domains', sa.Text(), nullable=False),  # JSON array
    sa.Column('scope_urls', sa.Text(), nullable=False),  # JSON array
    sa.Column('excluded_ips', sa.Text(), nullable=False),  # JSON array
    sa.Column('restricted_actions', sa.Text(), nullable=False),  # JSON array
    sa.Column('max_iterations', sa.Integer(), nullable=False),
    sa.Column('max_retries', sa.Integer(), nullable=False),
    sa.Column('timeout_seconds', sa.Integer(), nullable=False),
    sa.Column('cloud_allowed', sa.Boolean(), nullable=False),
    sa.Column('confidence_score', sa.Float(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('policy_id'),
    sa.ForeignKeyConstraint(['engagement_id'], ['engagements.engagement_id'], ),
    sa.ForeignKeyConstraint(['roe_id'], ['roe_files.roe_id'], ),
    )
    with op.batch_alter_table('engagement_policies', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_engagement_policies_engagement_id'), ['engagement_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_engagement_policies_roe_id'), ['roe_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_engagement_policies_created_at'), ['created_at'], unique=False)

    # Create ROEApprovalRecord table (immutable approval audit trail)
    op.create_table('roe_approval_records',
    sa.Column('approval_id', sa.String(length=36), nullable=False),
    sa.Column('engagement_id', sa.String(length=36), nullable=False),
    sa.Column('roe_id', sa.String(length=36), nullable=False),
    sa.Column('approved_by', sa.String(length=255), nullable=False),
    sa.Column('approved_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('password_verified', sa.Boolean(), nullable=False),
    sa.Column('session_id', sa.String(length=255), nullable=False),
    sa.Column('nonce_token_hash', sa.String(length=64), nullable=False),
    sa.PrimaryKeyConstraint('approval_id')
    )
    with op.batch_alter_table('roe_approval_records', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_roe_approval_records_engagement_id'), ['engagement_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_roe_approval_records_roe_id'), ['roe_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_roe_approval_records_approved_at'), ['approved_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_roe_approval_records_approved_by'), ['approved_by'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    # Drop ROEApprovalRecord table
    with op.batch_alter_table('roe_approval_records', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_roe_approval_records_approved_by'))
        batch_op.drop_index(batch_op.f('ix_roe_approval_records_approved_at'))
        batch_op.drop_index(batch_op.f('ix_roe_approval_records_roe_id'))
        batch_op.drop_index(batch_op.f('ix_roe_approval_records_engagement_id'))
    op.drop_table('roe_approval_records')

    # Drop EngagementPolicy table
    with op.batch_alter_table('engagement_policies', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_engagement_policies_created_at'))
        batch_op.drop_index(batch_op.f('ix_engagement_policies_roe_id'))
        batch_op.drop_index(batch_op.f('ix_engagement_policies_engagement_id'))
    op.drop_table('engagement_policies')

    # Drop ROEFile table
    with op.batch_alter_table('roe_files', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_roe_files_is_active'))
        batch_op.drop_index(batch_op.f('ix_roe_files_uploaded_at'))
        batch_op.drop_index(batch_op.f('ix_roe_files_content_hash'))
    op.drop_table('roe_files')
