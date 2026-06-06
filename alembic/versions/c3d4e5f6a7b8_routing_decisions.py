"""routing decisions (ontology resolver audit trail)

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
"""
from alembic import op
import sqlalchemy as sa

revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'routing_decisions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=128), nullable=False),
        sa.Column('framework', sa.String(length=64), nullable=False),
        sa.Column('control_id', sa.String(length=128), nullable=False),
        sa.Column('asset_type', sa.String(length=64), nullable=True),
        sa.Column('asset_id', sa.String(length=256), nullable=True),
        sa.Column('plane', sa.String(length=64), nullable=False),
        sa.Column('strategy_type', sa.String(length=32), nullable=False),
        sa.Column('module', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('executed', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('dry_run', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('skipped', sa.JSON(), nullable=True),
        sa.Column('finding_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_routing_tenant_control', 'routing_decisions', ['tenant_id', 'control_id'])
    op.create_index('ix_routing_decisions_tenant_id', 'routing_decisions', ['tenant_id'])
    op.create_index('ix_routing_decisions_control_id', 'routing_decisions', ['control_id'])


def downgrade():
    op.drop_table('routing_decisions')
