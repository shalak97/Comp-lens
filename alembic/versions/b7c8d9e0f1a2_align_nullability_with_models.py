"""Align database nullability with the ORM models.

84 columns across 17 tables are declared NOT NULL by the models and created
NULLABLE by the migrations. The application therefore assumes an invariant the
database does not enforce, and nothing caught it: CI builds the test schema
with ``Base.metadata.create_all()`` (which honours the models) while production
runs the migrations (which do not). Every test sees the strict schema; only
production has the loose one.

This is the second half of a gap found in iteration 7. The parity test written
then compares table and column NAMES only —

    {c["name"] for c in insp.get_columns(t)}

— so nullability and indexes were invisible to it. The test is extended in the
same change that adds this migration, and it fails without it.

Backfill policy, which is the whole risk of this migration:

  * 65 columns declare a default. Their NULLs are backfilled from that declared
    default before the constraint is applied, so the migration is safe on a
    populated database. A timestamp column is backfilled with CURRENT_TIMESTAMP.
  * 19 columns declare no default. These are identifiers, names and foreign
    keys — audits.tenant_id, audit_controls.audit_id, tprm_vendors.name. They
    are NOT backfilled, because there is no value that is not an invention. If
    real NULLs exist the ALTER fails loudly, which is the correct outcome: a
    null tenant id on an audit record is missing data that needs a human
    decision, not a placeholder.

batch_alter_table is used throughout because SQLite cannot ALTER a column in
place; it rebuilds the table instead. On PostgreSQL it emits a plain ALTER.

Revision ID: b7c8d9e0f1a2
Revises: a1b2c3d4e5f7
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "b7c8d9e0f1a2"
down_revision = "a1b2c3d4e5f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── backfill first: a constraint applied to existing NULLs would fail ──
    op.execute("UPDATE agent_actions SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.execute("UPDATE agent_chain_heads SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL")
    op.execute("UPDATE agent_identities SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.execute("UPDATE ai_system_pets SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.execute("UPDATE ai_system_pets SET data_sensitivity = 'pii' WHERE data_sensitivity IS NULL")
    op.execute("UPDATE audit_controls SET review_state = 'not_started' WHERE review_state IS NULL")
    op.execute("UPDATE audit_controls SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL")
    op.execute("UPDATE audit_evidence_requests SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.execute("UPDATE audit_evidence_requests SET state = 'open' WHERE state IS NULL")
    op.execute("UPDATE audit_evidence_requests SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL")
    op.execute("UPDATE audits SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.execute("UPDATE audits SET status = 'planning' WHERE status IS NULL")
    op.execute("UPDATE audits SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL")
    op.execute("UPDATE connector_evidence_items SET category = '' WHERE category IS NULL")
    op.execute("UPDATE connector_evidence_items SET collected_at = CURRENT_TIMESTAMP WHERE collected_at IS NULL")
    op.execute("UPDATE connector_evidence_items SET controls = '[]' WHERE controls IS NULL")
    op.execute("UPDATE connector_evidence_items SET mode = 'demo' WHERE mode IS NULL")
    op.execute("UPDATE connector_evidence_items SET signals = '{}' WHERE signals IS NULL")
    op.execute("UPDATE connector_evidence_items SET status = 'info' WHERE status IS NULL")
    op.execute("UPDATE connector_evidence_items SET tenant_id = 'default' WHERE tenant_id IS NULL")
    op.execute("UPDATE connector_evidence_items SET title = '' WHERE title IS NULL")
    op.execute("UPDATE connector_instances SET config = '{}' WHERE config IS NULL")
    op.execute("UPDATE connector_instances SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.execute("UPDATE connector_sync_state SET evidence_count = 0 WHERE evidence_count IS NULL")
    op.execute("UPDATE connector_sync_state SET mode = 'demo' WHERE mode IS NULL")
    op.execute("UPDATE connector_sync_state SET status = 'never' WHERE status IS NULL")
    op.execute("UPDATE connector_sync_state SET tenant_id = 'default' WHERE tenant_id IS NULL")
    op.execute("UPDATE crawl_results SET fetched_at = CURRENT_TIMESTAMP WHERE fetched_at IS NULL")
    op.execute("UPDATE crawl_results SET meta = '{}' WHERE meta IS NULL")
    op.execute("UPDATE crawl_results SET status = 'ok' WHERE status IS NULL")
    op.execute("UPDATE crawl_results SET target_id = '' WHERE target_id IS NULL")
    op.execute("UPDATE crawl_results SET tenant_id = 'default' WHERE tenant_id IS NULL")
    op.execute("UPDATE crawl_targets SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.execute("UPDATE crawl_targets SET domain = '' WHERE domain IS NULL")
    op.execute("UPDATE crawl_targets SET enabled = 1 WHERE enabled IS NULL")
    op.execute("UPDATE crawl_targets SET kind = 'advisory' WHERE kind IS NULL")
    op.execute("UPDATE crawl_targets SET min_interval_hours = 24 WHERE min_interval_hours IS NULL")
    op.execute("UPDATE crawl_targets SET name = '' WHERE name IS NULL")
    op.execute("UPDATE crawl_targets SET tenant_id = 'default' WHERE tenant_id IS NULL")
    op.execute("UPDATE crawl_targets SET url = '' WHERE url IS NULL")
    op.execute("UPDATE grc_risks SET category = 'operational' WHERE category IS NULL")
    op.execute("UPDATE grc_risks SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.execute("UPDATE grc_risks SET impact = 3 WHERE impact IS NULL")
    op.execute("UPDATE grc_risks SET likelihood = 3 WHERE likelihood IS NULL")
    op.execute("UPDATE grc_risks SET status = 'identified' WHERE status IS NULL")
    op.execute("UPDATE grc_risks SET treatment = 'mitigate' WHERE treatment IS NULL")
    op.execute("UPDATE grc_risks SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL")
    op.execute("UPDATE obligation_dispatches SET control_id = '' WHERE control_id IS NULL")
    op.execute("UPDATE obligation_dispatches SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.execute("UPDATE obligation_dispatches SET detail = '' WHERE detail IS NULL")
    op.execute("UPDATE obligation_dispatches SET meta = '{}' WHERE meta IS NULL")
    op.execute("UPDATE obligation_dispatches SET procedure = '' WHERE procedure IS NULL")
    op.execute("UPDATE obligation_dispatches SET severity = 'medium' WHERE severity IS NULL")
    op.execute("UPDATE obligation_dispatches SET status = 'done' WHERE status IS NULL")
    op.execute("UPDATE obligation_dispatches SET tenant_id = 'default' WHERE tenant_id IS NULL")
    op.execute("UPDATE posture_history SET recorded_at = CURRENT_TIMESTAMP WHERE recorded_at IS NULL")
    op.execute("UPDATE posture_history SET valid_from = CURRENT_TIMESTAMP WHERE valid_from IS NULL")
    op.execute("UPDATE routing_decisions SET skipped = '[]' WHERE skipped IS NULL")
    op.execute("UPDATE tprm_vendors SET assessment_state = 'not_started' WHERE assessment_state IS NULL")
    op.execute("UPDATE tprm_vendors SET has_dpa = 0 WHERE has_dpa IS NULL")
    op.execute("UPDATE tprm_vendors SET has_soc2 = 0 WHERE has_soc2 IS NULL")
    op.execute("UPDATE tprm_vendors SET onboarded_at = CURRENT_TIMESTAMP WHERE onboarded_at IS NULL")
    op.execute("UPDATE tprm_vendors SET risk_tier = 'medium' WHERE risk_tier IS NULL")
    op.execute("UPDATE tprm_vendors SET stage = 'onboarding' WHERE stage IS NULL")
    op.execute("UPDATE tprm_vendors SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL")

    # ── then tighten the constraints ──
    with op.batch_alter_table("agent_actions") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)

    with op.batch_alter_table("agent_chain_heads") as batch:
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)

    with op.batch_alter_table("agent_identities") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)

    with op.batch_alter_table("ai_system_pets") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("data_sensitivity", existing_type=sa.String(32), nullable=False)
        batch.alter_column("pet", existing_type=sa.String(64), nullable=False)
        batch.alter_column("system_id", existing_type=sa.String(64), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)

    with op.batch_alter_table("audit_controls") as batch:
        batch.alter_column("audit_id", existing_type=sa.String(64), nullable=False)
        batch.alter_column("control_id", existing_type=sa.String(64), nullable=False)
        batch.alter_column("review_state", existing_type=sa.String(32), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)

    with op.batch_alter_table("audit_evidence_requests") as batch:
        batch.alter_column("audit_id", existing_type=sa.String(64), nullable=False)
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("state", existing_type=sa.String(32), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)
        batch.alter_column("title", existing_type=sa.String(512), nullable=False)
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)

    with op.batch_alter_table("audits") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("framework", existing_type=sa.String(64), nullable=False)
        batch.alter_column("name", existing_type=sa.String(256), nullable=False)
        batch.alter_column("status", existing_type=sa.String(32), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)

    with op.batch_alter_table("connector_evidence_items") as batch:
        batch.alter_column("category", existing_type=sa.String(24), nullable=False)
        batch.alter_column("collected_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("connector_key", existing_type=sa.String(64), nullable=False)
        batch.alter_column("controls", existing_type=sa.JSON, nullable=False)
        batch.alter_column("evidence_type", existing_type=sa.String(64), nullable=False)
        batch.alter_column("mode", existing_type=sa.String(16), nullable=False)
        batch.alter_column("signals", existing_type=sa.JSON, nullable=False)
        batch.alter_column("status", existing_type=sa.String(16), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)
        batch.alter_column("title", existing_type=sa.String(256), nullable=False)

    with op.batch_alter_table("connector_instances") as batch:
        batch.alter_column("config", existing_type=sa.JSON, nullable=False)
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)

    with op.batch_alter_table("connector_sync_state") as batch:
        batch.alter_column("connector_key", existing_type=sa.String(64), nullable=False)
        batch.alter_column("evidence_count", existing_type=sa.Integer, nullable=False)
        batch.alter_column("mode", existing_type=sa.String(16), nullable=False)
        batch.alter_column("status", existing_type=sa.String(24), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)

    with op.batch_alter_table("crawl_results") as batch:
        batch.alter_column("fetched_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("meta", existing_type=sa.JSON, nullable=False)
        batch.alter_column("status", existing_type=sa.String(24), nullable=False)
        batch.alter_column("target_id", existing_type=sa.String(36), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)

    with op.batch_alter_table("crawl_targets") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("domain", existing_type=sa.String(256), nullable=False)
        batch.alter_column("enabled", existing_type=sa.Boolean, nullable=False)
        batch.alter_column("kind", existing_type=sa.String(24), nullable=False)
        batch.alter_column("min_interval_hours", existing_type=sa.Integer, nullable=False)
        batch.alter_column("name", existing_type=sa.String(256), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)
        batch.alter_column("url", existing_type=sa.String(2048), nullable=False)

    with op.batch_alter_table("grc_risks") as batch:
        batch.alter_column("category", existing_type=sa.String(64), nullable=False)
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("impact", existing_type=sa.Integer, nullable=False)
        batch.alter_column("likelihood", existing_type=sa.Integer, nullable=False)
        batch.alter_column("status", existing_type=sa.String(32), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)
        batch.alter_column("title", existing_type=sa.String(256), nullable=False)
        batch.alter_column("treatment", existing_type=sa.String(32), nullable=False)
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)

    with op.batch_alter_table("obligation_dispatches") as batch:
        batch.alter_column("control_id", existing_type=sa.String(128), nullable=False)
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("detail", existing_type=sa.Text, nullable=False)
        batch.alter_column("meta", existing_type=sa.JSON, nullable=False)
        batch.alter_column("procedure", existing_type=sa.String(48), nullable=False)
        batch.alter_column("severity", existing_type=sa.String(16), nullable=False)
        batch.alter_column("status", existing_type=sa.String(24), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)

    with op.batch_alter_table("posture_history") as batch:
        batch.alter_column("recorded_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("valid_from", existing_type=sa.DateTime(timezone=True), nullable=False)

    with op.batch_alter_table("routing_decisions") as batch:
        batch.alter_column("skipped", existing_type=sa.JSON, nullable=False)

    with op.batch_alter_table("tprm_vendors") as batch:
        batch.alter_column("assessment_state", existing_type=sa.String(32), nullable=False)
        batch.alter_column("has_dpa", existing_type=sa.Boolean, nullable=False)
        batch.alter_column("has_soc2", existing_type=sa.Boolean, nullable=False)
        batch.alter_column("name", existing_type=sa.String(256), nullable=False)
        batch.alter_column("onboarded_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("risk_tier", existing_type=sa.String(32), nullable=False)
        batch.alter_column("stage", existing_type=sa.String(32), nullable=False)
        batch.alter_column("tenant_id", existing_type=sa.String(128), nullable=False)
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)


def downgrade() -> None:
    """Deliberately a no-op.

    Relaxing a NOT NULL is always safe in the abstract, but reversing this
    migration would restore a schema the application's own type annotations say
    cannot happen. If a downgrade is ever genuinely needed, write it against the
    specific columns involved rather than reopening all 84.
    """
