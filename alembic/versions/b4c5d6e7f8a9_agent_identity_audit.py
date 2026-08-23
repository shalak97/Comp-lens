"""agent identity + append-only agent-decision log

"Which agent acted under whose authorization" (the L5 governance gap). Every
autonomous action is attributed to a verifiable agent identity and recorded in an
append-only, hash-chained log so the trail is tamper-evident.

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
"""
import sqlalchemy as sa

from alembic import op

revision = "b4c5d6e7f8a9"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_identities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("model", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("name", "kind", name="uq_agent_name_kind"),
    )
    op.create_table(
        "agent_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("agent_id", sa.String(36), nullable=False),
        sa.Column("agent_name", sa.String(128), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.String(256), nullable=True),
        sa.Column("on_behalf_of", sa.String(128), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("outcome", sa.String(32), nullable=False, server_default="done"),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=True),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_actions_tenant", "agent_actions", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_agent_actions_tenant", table_name="agent_actions")
    op.drop_table("agent_actions")
    op.drop_table("agent_identities")
