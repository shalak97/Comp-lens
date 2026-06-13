"""link vendors to connectors (telemetry chain)

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
"""
from alembic import op
import sqlalchemy as sa

revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tprm_vendors",
                  sa.Column("linked_connector_key", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("tprm_vendors", "linked_connector_key")
