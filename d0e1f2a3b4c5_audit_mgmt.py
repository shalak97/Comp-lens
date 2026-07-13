"""audit management: audits, audit_controls, evidence_requests

Revision ID: d0e1f2a3b4c5
Revises: b8c9d0e1f2a3
"""
import sqlalchemy as sa

from alembic import op

revision = "d0e1f2a3b4c5"
down_revision = "b8c9d0e1f2a3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audits",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), index=True),
        sa.Column("name", sa.String(256)),
        sa.Column("framework", sa.String(64)),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("auditor", sa.String(256), nullable=True),
        sa.Column("status", sa.String(32), server_default="planning"),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "audit_controls",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("audit_id", sa.String(64), index=True),
        sa.Column("tenant_id", sa.String(128), index=True),
        sa.Column("control_id", sa.String(64)),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("review_state", sa.String(32), server_default="not_started"),
        sa.Column("auto_status", sa.String(32), nullable=True),
        sa.Column("owner", sa.String(128), nullable=True),
        sa.Column("evidence_ref", sa.String(512), nullable=True),
        sa.Column("reviewer_note", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "audit_evidence_requests",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("audit_id", sa.String(64), index=True),
        sa.Column("tenant_id", sa.String(128), index=True),
        sa.Column("control_id", sa.String(64), nullable=True),
        sa.Column("title", sa.String(512)),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("assignee", sa.String(128), nullable=True),
        sa.Column("state", sa.String(32), server_default="open"),
        sa.Column("response_note", sa.Text(), nullable=True),
        sa.Column("evidence_ref", sa.String(512), nullable=True),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("audit_evidence_requests")
    op.drop_table("audit_controls")
    op.drop_table("audits")
