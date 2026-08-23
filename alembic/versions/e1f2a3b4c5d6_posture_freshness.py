"""posture freshness: cadence + next_validation

Give each materialized posture row an explicit freshness guarantee — the
validation cadence and the timestamp at which the row goes stale — so a control
status becomes a control claim with an expiry (the KSI next_validation property).

Revision ID: e1f2a3b4c5d6
Revises: d5e6f7a8b9c0
"""
import sqlalchemy as sa

from alembic import op

revision = "e1f2a3b4c5d6"
down_revision = "d5e6f7a8b9c0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "posture",
        sa.Column("cadence", sa.String(32), nullable=False, server_default="monthly"),
    )
    op.add_column(
        "posture",
        sa.Column("next_validation", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("posture", "next_validation")
    op.drop_column("posture", "cadence")
