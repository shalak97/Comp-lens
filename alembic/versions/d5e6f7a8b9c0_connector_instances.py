"""configured connector instances (labeled connections)

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
"""
import sqlalchemy as sa

from alembic import op

revision = "d5e6f7a8b9c0"
down_revision = "c4d5e6f7a8b9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "connector_instances",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False, server_default="default"),
        sa.Column("connector_key", sa.String(64), nullable=False),
        sa.Column("label", sa.String(200), nullable=False, server_default=""),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(32), nullable=True),
        sa.Column("last_mode", sa.String(16), nullable=True),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("evidence_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_connector_instances_tenant", "connector_instances", ["tenant_id"])
    op.create_index("ix_connector_instances_connector_key", "connector_instances", ["connector_key"])


def downgrade() -> None:
    op.drop_index("ix_connector_instances_connector_key", table_name="connector_instances")
    op.drop_index("ix_connector_instances_tenant", table_name="connector_instances")
    op.drop_table("connector_instances")
