"""sign merkle anchors (tamper-evidence for the transparency log)

Revision ID: c4d5e6f7a8b9
Revises: a2b3c4d5e6f7
"""
from alembic import op
import sqlalchemy as sa

revision = "c4d5e6f7a8b9"
down_revision = "a2b3c4d5e6f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("merkle_anchors",
                  sa.Column("signature", sa.String(128), nullable=True))


def downgrade() -> None:
    op.drop_column("merkle_anchors", "signature")
