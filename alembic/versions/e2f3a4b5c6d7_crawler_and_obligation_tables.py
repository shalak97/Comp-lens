"""crawler and obligation tables: crawl_targets, crawl_results, obligation_dispatches

Revision ID: e2f3a4b5c6d7
Revises: d6e7f8a9b0c1

Three tables were declared in the models and never given a migration, so they
exist in every test run — which builds the schema with create_all() straight
from those models — and in no production database, which is built by alembic.

This is the second time it has happened: e1a2b3c4d5e6 says the same thing about
the audit tables, discovered when "every /audits call hit 'no such table:
audits'". Nothing was checking, so it happened again.

The failure is quieter this time, which is worse. Both readers of these tables
sit behind `except Exception:` and degrade to a neutral answer — trust
telemetry reports "no drift" and an empty follow-through lane — so in
production the crawler and obligation planes report nothing happening rather
than failing. An estate whose vendor trust pages are changing under it looks
identical to one where nothing has moved.

tests/test_migration_drift.py, added alongside this migration, compares the
migrated schema against the models so the class cannot recur silently.
"""
import sqlalchemy as sa

from alembic import op

revision = "e2f3a4b5c6d7"
down_revision = "d6e7f8a9b0c1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "crawl_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), index=True, server_default="default"),
        sa.Column("kind", sa.String(24), index=True, server_default="advisory"),
        sa.Column("name", sa.String(256), server_default=""),
        sa.Column("url", sa.String(2048), server_default=""),
        sa.Column("domain", sa.String(256), index=True, server_default=""),
        sa.Column("linked_vendor_id", sa.String(64), nullable=True),
        sa.Column("linked_framework", sa.String(64), nullable=True),
        sa.Column("min_interval_hours", sa.Integer(), server_default="24"),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true()),
        sa.Column("last_hash", sa.String(64), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "crawl_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), index=True, server_default="default"),
        sa.Column("target_id", sa.String(36), index=True, server_default=""),
        sa.Column("status", sa.String(24), server_default="ok"),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column("excerpt", sa.Text(), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("error", sa.String(512), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), index=True),
    )
    op.create_table(
        "obligation_dispatches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), index=True, server_default="default"),
        sa.Column("control_id", sa.String(128), index=True, server_default=""),
        sa.Column("procedure", sa.String(48), index=True, server_default=""),
        sa.Column("status", sa.String(24), server_default="done"),
        sa.Column("severity", sa.String(16), server_default="medium"),
        sa.Column("detail", sa.Text(), server_default=""),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("finding_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), index=True),
    )


def downgrade() -> None:
    op.drop_table("obligation_dispatches")
    op.drop_table("crawl_results")
    op.drop_table("crawl_targets")
