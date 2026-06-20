"""ai system PETs table

Revision ID: f1a2b3c4d5e6
Revises: e1a2b3c4d5e6
"""
from alembic import op
import sqlalchemy as sa

revision = "f1a2b3c4d5e6"
down_revision = "e1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_system_pets",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), index=True),
        sa.Column("system_id", sa.String(64), index=True),
        sa.Column("pet", sa.String(64)),
        sa.Column("params_json", sa.Text(), nullable=True),
        sa.Column("data_sensitivity", sa.String(32), server_default="pii"),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("ai_system_pets")
