"""grc platform attestations table

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
"""
from alembic import op
import sqlalchemy as sa

revision = "a2b3c4d5e6f7"
down_revision = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "grc_attestations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), index=True),
        sa.Column("platform", sa.String(32), index=True),
        sa.Column("external_test_id", sa.String(128)),
        sa.Column("external_control_ref", sa.String(128)),
        sa.Column("comp_lens_control_id", sa.String(64), nullable=True, index=True),
        sa.Column("status", sa.String(32)),
        sa.Column("freshness_days", sa.Integer(), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="0.5"),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("grc_attestations")
