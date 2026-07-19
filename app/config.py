"""Centralized configuration. All secrets come from environment variables.

Never hardcode credentials. On AWS, prefer IAM roles over access keys where
possible (EC2 instance profile / ECS task role) so no AWS keys are needed.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── App ──
    app_name: str = "Comp-Lens GRC Platform"
    app_env: str = Field(default="local")  # local | staging | production
    log_level: str = Field(default="INFO")
    request_timeout_seconds: int = Field(default=15)
    # Secure by default: no cross-origin access. The bundled dashboard is
    # same-origin and needs none; set an explicit allowlist for real integrators.
    cors_origins: list[str] = Field(default_factory=list)
    # Interactive API docs (/docs, /redoc, /openapi.json) are served outside
    # production; set true to expose them in production too (discloses the full
    # API surface, so keep it off unless you mean it).
    expose_api_docs: bool = Field(default=False)

    # Production hardening
    rate_limit_per_minute: int = Field(default=120)
    # Trusted reverse-proxy hop count for rate-limit client-ip resolution. 0 keeps
    # the socket peer (safe default); set to 1 behind Render so anonymous requests
    # are keyed on the real client ip from X-Forwarded-For. Only set when actually
    # behind that many trusted proxies — otherwise the header is spoofable.
    trusted_proxy_hops: int = Field(default=0)
    enable_hsts: bool = Field(default=True)

    # Gate the synthetic DEMO connector. Defaults OFF in production so nobody
    # can fabricate "pass" evidence against a real compliance database.
    enable_demo_connector: bool | None = Field(default=None)

    # Auto-create tables on startup (dev convenience). In production this is
    # forced off — use Alembic migrations instead.
    auto_create_tables: bool | None = Field(default=None)

    # DB connection pool (ignored for SQLite)
    db_pool_size: int = Field(default=5)
    db_max_overflow: int = Field(default=10)

    # External-call retry
    retry_attempts: int = Field(default=3)

    # ── Policy engine ──
    # "builtin" = in-process rule catalog; "opa" = delegate to an OPA server.
    # opa_url unset (None) keeps OPA delegation OFF; set it to enable OPA.
    policy_engine: str = Field(default="builtin")
    opa_url: str | None = Field(default=None)            # e.g. http://opa:8181
    opa_package: str = Field(default="compliance")
    opa_decision_path: str = Field(default="/v1/data/complens/decision")
    evidence_signing_key: str | None = Field(default=None)  # HMAC key for evidence chain of custody

    # ── Legacy integration ──
    # Named legacy data sources (SQL/SOAP/file/LDAP), configured server-side so
    # clients can only reference them by name (never pass raw URLs/queries).
    # Provide EITHER inline JSON or a path to a JSON file.
    legacy_sources_json: str | None = Field(default=None)
    legacy_sources_file: str | None = Field(default=None)

    # ── Scheduler (continuous assessments) ──
    enable_scheduler: bool = Field(default=False)   # background thread; off in tests
    scheduler_interval_seconds: int = Field(default=60)

    # ── Notifications ──
    notify_on_status: str = Field(default="fail")   # which finding status triggers alerts
    notify_slack_webhook: str | None = Field(default=None)
    notify_generic_webhook: str | None = Field(default=None)
    smtp_host: str | None = Field(default=None)
    smtp_port: int = Field(default=587)
    smtp_user: str | None = Field(default=None)
    smtp_password: str | None = Field(default=None)
    notify_email_to: str | None = Field(default=None)
    notify_email_from: str | None = Field(default=None)

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
    evidence_s3_bucket: str | None = Field(default=None)
    evidence_s3_prefix: str = Field(default="evidence/")

    # ── AWS ──
    aws_region: str = Field(default="us-east-1")
    aws_access_key_id: str | None = Field(default=None)
    aws_secret_access_key: str | None = Field(default=None)

    # ── Azure ──
    azure_tenant_id: str | None = Field(default=None)
    azure_client_id: str | None = Field(default=None)
    azure_client_secret: str | None = Field(default=None)
    azure_subscription_id: str | None = Field(default=None)

    # ── GCP ──
    gcp_project_id: str | None = Field(default=None)
    gcp_credentials_json: str | None = Field(default=None)  # raw JSON or path

    # ── Okta ──
    okta_org_url: str | None = Field(default=None)
    okta_api_token: str | None = Field(default=None)

    # ── GitHub ──
    github_token: str | None = Field(default=None)
    github_org: str | None = Field(default=None)

    # ── GitLab ──
    gitlab_url: str = Field(default="https://gitlab.com")
    gitlab_token: str | None = Field(default=None)

    # ── Jira ──
    jira_url: str | None = Field(default=None)
    jira_email: str | None = Field(default=None)
    jira_api_token: str | None = Field(default=None)

    # ── ServiceNow ──
    servicenow_instance: str | None = Field(default=None)
    servicenow_user: str | None = Field(default=None)
    servicenow_password: str | None = Field(default=None)

    # ── Slack ──
    slack_bot_token: str | None = Field(default=None)

    # ── SSH / Linux ──
    ssh_default_user: str = Field(default="ubuntu")
    ssh_key_path: str | None = Field(default=None)

    # ── Qualys ──
    qualys_api_url: str | None = Field(default=None)
    qualys_user: str | None = Field(default=None)
    qualys_password: str | None = Field(default=None)

    # ── CrowdStrike ──
    crowdstrike_client_id: str | None = Field(default=None)
    crowdstrike_client_secret: str | None = Field(default=None)
    crowdstrike_base_url: str = Field(default="https://api.crowdstrike.com")

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
