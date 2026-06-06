"""evidence document signatures (chain of custody)

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-01-15
"""
from alembic import op
import sqlalchemy as sa

revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('evidence_documents') as b:
        b.add_column(sa.Column('signature', sa.String(length=128), nullable=True))
        b.add_column(sa.Column('signed_at', sa.DateTime(timezone=True), nullable=True))


def downgrade():
    with op.batch_alter_table('evidence_documents') as b:
        b.drop_column('signed_at')
        b.drop_column('signature')
