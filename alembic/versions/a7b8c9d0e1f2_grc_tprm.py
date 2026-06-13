"""GRC risk register + TPRM vendor lifecycle

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
"""
from alembic import op
import sqlalchemy as sa

revision = "a7b8c9d0e1f2"
down_revision = "f6a7b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "grc_risks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), index=True, server_default="default"),
        sa.Column("title", sa.String(256)),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(64), server_default="operational"),
        sa.Column("owner", sa.String(128), nullable=True),
        sa.Column("likelihood", sa.Integer(), server_default="3"),
        sa.Column("impact", sa.Integer(), server_default="3"),
        sa.Column("treatment", sa.String(32), server_default="mitigate"),
        sa.Column("status", sa.String(32), server_default="identified"),
        sa.Column("residual_likelihood", sa.Integer(), nullable=True),
        sa.Column("residual_impact", sa.Integer(), nullable=True),
        sa.Column("linked_control", sa.String(64), nullable=True),
        sa.Column("linked_vendor_id", sa.String(64), nullable=True),
        sa.Column("review_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "tprm_vendors",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), index=True, server_default="default"),
        sa.Column("name", sa.String(256)),
        sa.Column("category", sa.String(64), nullable=True),
        sa.Column("contact_email", sa.String(256), nullable=True),
        sa.Column("stage", sa.String(32), server_default="onboarding"),
        sa.Column("risk_tier", sa.String(32), server_default="medium"),
        sa.Column("assessment_state", sa.String(32), server_default="not_started"),
        sa.Column("data_access", sa.String(64), nullable=True),
        sa.Column("has_dpa", sa.Boolean(), server_default=sa.false()),
        sa.Column("has_soc2", sa.Boolean(), server_default=sa.false()),
        sa.Column("assessment_score", sa.Float(), nullable=True),
        sa.Column("next_review", sa.DateTime(timezone=True), nullable=True),
        sa.Column("onboarded_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("tprm_vendors")
    op.drop_table("grc_risks")
