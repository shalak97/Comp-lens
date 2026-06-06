"""Centralized configuration. All secrets come from environment variables.

Never hardcode credentials. On AWS, prefer IAM roles over access keys where
possible (EC2 instance profile / ECS task role) so no AWS keys are needed.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── App ──
    app_name: str = "Comp-Lens GRC Platform"
    app_env: str = Field(default="local")  # local | staging | production
    log_level: str = Field(default="INFO")
    request_timeout_seconds: int = Field(default=15)
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])

    # Gate the synthetic DEMO connector. Defaults OFF in production so nobody
    # can fabricate "pass" evidence against a real compliance database.
    enable_demo_connector: Optional[bool] = Field(default=None)

    # Auto-create tables on startup (dev convenience). In production this is
    # forced off — use Alembic migrations instead.
    auto_create_tables: Optional[bool] = Field(default=None)

    # DB connection pool (ignored for SQLite)
    db_pool_size: int = Field(default=5)
    db_max_overflow: int = Field(default=10)

    # External-call retry
    retry_attempts: int = Field(default=3)

    # ── Policy engine ──
    # "builtin" = in-process rule catalog; "opa" = delegate to an OPA server.
    policy_engine: str = Field(default="builtin")
    opa_url: Optional[str] = Field(default=None)            # e.g. http://opa:8181
    evidence_signing_key: Optional[str] = Field(default=None)  # HMAC key for evidence chain of custody
    opa_decision_path: str = Field(default="/v1/data/complens/decision")

    # ── Policy engine ──
    # "rules" = built-in Python rule catalog; "opa" = Open Policy Agent server.
    policy_engine: str = Field(default="rules")
    opa_url: str = Field(default="http://localhost:8181")
    opa_package: str = Field(default="compliance")

    # ── Legacy integration ──
    # Named legacy data sources (SQL/SOAP/file/LDAP), configured server-side so
    # clients can only reference them by name (never pass raw URLs/queries).
    # Provide EITHER inline JSON or a path to a JSON file.
    legacy_sources_json: Optional[str] = Field(default=None)
    legacy_sources_file: Optional[str] = Field(default=None)

    # ── Scheduler (continuous assessments) ──
    enable_scheduler: bool = Field(default=False)   # background thread; off in tests
    scheduler_interval_seconds: int = Field(default=60)

    # ── Notifications ──
    notify_on_status: str = Field(default="fail")   # which finding status triggers alerts
    notify_slack_webhook: Optional[str] = Field(default=None)
    notify_generic_webhook: Optional[str] = Field(default=None)
    smtp_host: Optional[str] = Field(default=None)
    smtp_port: int = Field(default=587)
    smtp_user: Optional[str] = Field(default=None)
    smtp_password: Optional[str] = Field(default=None)
    notify_email_to: Optional[str] = Field(default=None)
    notify_email_from: Optional[str] = Field(default=None)

    def demo_enabled(self) -> bool:
        if self.enable_demo_connector is not None:
            return self.enable_demo_connector
        return not self.is_production

    def autocreate_enabled(self) -> bool:
        if self.auto_create_tables is not None:
            return self.auto_create_tables
        return not self.is_production

    # ── Database ──
    # Local default is SQLite; production should set DATABASE_URL to Postgres:
    #   postgresql+psycopg://user:pass@host:5432/complens
    database_url: str = Field(default="sqlite:///./complens.db")

    # ── Evidence store ──
    # If S3 is configured, evidence goes to S3; otherwise local files.
    evidence_backend: str = Field(default="local")  # local | s3
    evidence_local_path: str = Field(default="./evidence_store")
    evidence_s3_bucket: Optional[str] = Field(default=None)
    evidence_s3_prefix: str = Field(default="evidence/")

    # ── AWS ──
    aws_region: str = Field(default="us-east-1")
    aws_access_key_id: Optional[str] = Field(default=None)
    aws_secret_access_key: Optional[str] = Field(default=None)

    # ── Azure ──
    azure_tenant_id: Optional[str] = Field(default=None)
    azure_client_id: Optional[str] = Field(default=None)
    azure_client_secret: Optional[str] = Field(default=None)
    azure_subscription_id: Optional[str] = Field(default=None)

    # ── GCP ──
    gcp_project_id: Optional[str] = Field(default=None)
    gcp_credentials_json: Optional[str] = Field(default=None)  # raw JSON or path

    # ── Okta ──
    okta_org_url: Optional[str] = Field(default=None)
    okta_api_token: Optional[str] = Field(default=None)

    # ── GitHub ──
    github_token: Optional[str] = Field(default=None)
    github_org: Optional[str] = Field(default=None)

    # ── GitLab ──
    gitlab_url: str = Field(default="https://gitlab.com")
    gitlab_token: Optional[str] = Field(default=None)

    # ── Jira ──
    jira_url: Optional[str] = Field(default=None)
    jira_email: Optional[str] = Field(default=None)
    jira_api_token: Optional[str] = Field(default=None)

    # ── ServiceNow ──
    servicenow_instance: Optional[str] = Field(default=None)
    servicenow_user: Optional[str] = Field(default=None)
    servicenow_password: Optional[str] = Field(default=None)

    # ── Slack ──
    slack_bot_token: Optional[str] = Field(default=None)

    # ── SSH / Linux ──
    ssh_default_user: str = Field(default="ubuntu")
    ssh_key_path: Optional[str] = Field(default=None)

    # ── Qualys ──
    qualys_api_url: Optional[str] = Field(default=None)
    qualys_user: Optional[str] = Field(default=None)
    qualys_password: Optional[str] = Field(default=None)

    # ── CrowdStrike ──
    crowdstrike_client_id: Optional[str] = Field(default=None)
    crowdstrike_client_secret: Optional[str] = Field(default=None)
    crowdstrike_base_url: str = Field(default="https://api.crowdstrike.com")

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
