"""evidence graph (documents + concept hits)

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
"""
from alembic import op
import sqlalchemy as sa

revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'evidence_documents',
        sa.Column('doc_id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=128), nullable=False),
        sa.Column('name', sa.String(length=512), nullable=False),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('content_hash', sa.String(length=64), nullable=False),
        sa.Column('char_count', sa.Integer(), nullable=False),
        sa.Column('source_type', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=True),
        sa.Column('model', sa.String(length=64), nullable=True),
        sa.Column('prompt_version', sa.String(length=64), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('doc_id'),
        sa.UniqueConstraint('tenant_id', 'content_hash', name='uq_evidence_doc_hash'),
    )
    op.create_index('ix_evidence_docs_tenant', 'evidence_documents', ['tenant_id'])
    op.create_index('ix_evidence_documents_content_hash', 'evidence_documents', ['content_hash'])
    op.create_table(
        'evidence_concept_hits',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=128), nullable=False),
        sa.Column('doc_id', sa.String(length=36), nullable=False),
        sa.Column('concept_id', sa.String(length=64), nullable=False),
        sa.Column('quote', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('confirmed', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_evidence_hits_tenant', 'evidence_concept_hits', ['tenant_id'])
    op.create_index('ix_evidence_hits_doc', 'evidence_concept_hits', ['doc_id'])
    op.create_index('ix_evidence_concept_hits_concept_id', 'evidence_concept_hits', ['concept_id'])


def downgrade():
    op.drop_table('evidence_concept_hits')
    op.drop_table('evidence_documents')
