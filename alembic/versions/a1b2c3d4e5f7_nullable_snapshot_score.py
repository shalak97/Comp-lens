"""compliance snapshot score is nullable

An empty or entirely not-applicable estate has no compliance score. It used to
be recorded as 0.0, which is indistinguishable from "we assessed everything and
nothing passed" — and on the trend chart it drew a line crashing to zero
whenever an estate went dark, which is the opposite of what happened.

Revision ID: a1b2c3d4e5f7
Revises: e2f3a4b5c6d7
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a1b2c3d4e5f7"
down_revision = "e2f3a4b5c6d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("compliance_snapshots") as batch:
        batch.alter_column("score", existing_type=sa.Float(), nullable=True)


def downgrade() -> None:
    # Rows written while the column was nullable carry a real NULL meaning "not
    # assessable". Going back to NOT NULL has to put something there, and 0.0
    # is the value this migration exists to stop meaning two things — so the
    # downgrade is lossy by necessity, and says so rather than pretending.
    op.execute("UPDATE compliance_snapshots SET score = 0.0 WHERE score IS NULL")
    with op.batch_alter_table("compliance_snapshots") as batch:
        batch.alter_column("score", existing_type=sa.Float(), nullable=False)
