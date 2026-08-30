"""schedule lease columns for multi-replica safety

The background runner is one thread per process, so every replica found the
same due schedules and ran them simultaneously: duplicate connector calls,
duplicate trend snapshots, and concurrent writes to the same posture rows.
Claiming a schedule is now a single conditional UPDATE against these columns,
so exactly one replica wins regardless of how many are running.

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
"""
import sqlalchemy as sa

from alembic import op

revision = "d6e7f8a9b0c1"
down_revision = "c5d6e7f8a9b0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("schedules", sa.Column("locked_by", sa.String(64), nullable=True))
    op.add_column("schedules",
                  sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
    # Existing rows are unlocked by default (NULL), which is the claimable state.


def downgrade() -> None:
    op.drop_column("schedules", "locked_until")
    op.drop_column("schedules", "locked_by")
