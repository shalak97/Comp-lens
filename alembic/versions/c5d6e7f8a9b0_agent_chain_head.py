"""signed head pointer for the agent-action chain

Hash-chaining alone cannot detect truncation: deleting the newest agent action
leaves every survivor's prev_hash still resolvable, so the chain verified as
clean. Recording where the chain is supposed to end — and how many entries it
should hold — makes removing or replacing the tail detectable. The row is
HMAC-signed with the server-side evidence signing key so an attacker with
database write access but no key cannot repair it after tampering.

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
"""
import sqlalchemy as sa

from alembic import op

revision = "c5d6e7f8a9b0"
down_revision = "b4c5d6e7f8a9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_chain_heads",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("head_hash", sa.String(64), nullable=False),
        sa.Column("action_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("signature", sa.String(128), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Existing agent_actions rows predate the head. They are deliberately NOT
    # back-filled: a head synthesised from data that may already have been
    # tampered with would attest to whatever the table currently says. Those
    # tenants verify with issues=["no_recorded_head"] until their next action
    # establishes a real tip.


def downgrade() -> None:
    op.drop_table("agent_chain_heads")
