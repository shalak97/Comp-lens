"""control attestations (full framework coverage)

Revision ID: a1b2c3d4e5f6
Revises: 6ba0888e21c1
"""
from alembic import op
import sqlalchemy as sa

revision = 'a1b2c3d4e5f6'
down_revision = '6ba0888e21c1'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'control_attestations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=128), nullable=False),
        sa.Column('framework', sa.String(length=64), nullable=False),
        sa.Column('control_id', sa.String(length=128), nullable=False),
        sa.Column('status', sa.Enum('compliant', 'non_compliant', 'not_applicable',
                                    'in_progress', 'not_assessed', name='attestationstatus'),
                  nullable=False),
        sa.Column('owner', sa.String(length=128), nullable=True),
        sa.Column('approver', sa.String(length=128), nullable=True),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('evidence_ref', sa.String(length=512), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'framework', 'control_id', name='uq_attestation'),
    )
    op.create_index('ix_attestation_tenant_fw', 'control_attestations', ['tenant_id', 'framework'])
    op.create_index('ix_control_attestations_tenant_id', 'control_attestations', ['tenant_id'])
    op.create_index('ix_control_attestations_framework', 'control_attestations', ['framework'])
    op.create_index('ix_control_attestations_control_id', 'control_attestations', ['control_id'])


def downgrade():
    op.drop_table('control_attestations')
    sa.Enum(name='attestationstatus').drop(op.get_bind(), checkfirst=True)
