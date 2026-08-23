"""posture_history: append-only valid-time control-status log

Keeps the timeline of control-status transitions per cell so posture can be
reconstructed "as of" any date (the bitemporal spine gap). Posture stays the
materialized current view; this is the append-only history beside it.

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
"""
import sqlalchemy as sa

from alembic import op

revision = "f2a3b4c5d6e7"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "posture_history",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("control_id", sa.String(128), nullable=False),
        sa.Column("source_system", sa.String(64), nullable=False),
        sa.Column("asset_id", sa.String(256), nullable=True),
        sa.Column("asset_key", sa.String(256), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False, server_default="medium"),
        sa.Column("finding_id", sa.String(36), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_posture_history_key", "posture_history",
                    ["tenant_id", "control_id", "source_system", "asset_key"])
    op.create_index("ix_posture_history_valid", "posture_history",
                    ["tenant_id", "valid_from"])


def downgrade() -> None:
    op.drop_index("ix_posture_history_valid", table_name="posture_history")
    op.drop_index("ix_posture_history_key", table_name="posture_history")
    op.drop_table("posture_history")
