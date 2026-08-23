"""findings.framework_version: pin the framework revision per assertion

Drift-proofing (failure mode #4): record which revision of a framework each
finding was assessed under, so a later framework revision does not silently
reinterpret past assertions.

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
"""
import sqlalchemy as sa

from alembic import op

revision = "a3b4c5d6e7f8"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("framework_version", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "framework_version")
