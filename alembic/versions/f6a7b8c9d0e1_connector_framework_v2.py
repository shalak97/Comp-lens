"""connector framework v2: sync state + evidence items

Revision ID: f6a7b8c9d0e1
Revises: d4e5f6a7b8c9
"""
from alembic import op
import sqlalchemy as sa

revision = "f6a7b8c9d0e1"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "connector_sync_state",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), index=True, server_default="default"),
        sa.Column("connector_key", sa.String(64), index=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(24), server_default="never"),
        sa.Column("mode", sa.String(16), server_default="demo"),
        sa.Column("evidence_count", sa.Integer(), server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.UniqueConstraint("tenant_id", "connector_key", name="uq_sync_tenant_connector"),
    )
    op.create_table(
        "connector_evidence_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), index=True, server_default="default"),
        sa.Column("connector_key", sa.String(64), index=True),
        sa.Column("category", sa.String(24), server_default=""),
        sa.Column("evidence_type", sa.String(64), index=True),
        sa.Column("title", sa.String(256), server_default=""),
        sa.Column("status", sa.String(16), server_default="info"),
        sa.Column("mode", sa.String(16), server_default="demo"),
        sa.Column("signals", sa.JSON()),
        sa.Column("controls", sa.JSON()),
        sa.Column("collected_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("connector_evidence_items")
    op.drop_table("connector_sync_state")
