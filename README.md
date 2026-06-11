# Comp-Lens — GRC Compliance-as-Code Platform

Vendor-agnostic cybersecurity GRC automation. Assess controls across cloud,
identity, code, endpoint, ticketing, on-prem, and SaaS systems through real API
connectors. Collect immutable evidence, generate findings with remediation, and
track compliance — all behind a clean FastAPI backend with PostgreSQL
persistence.

## Capabilities

- **Multi-framework crosswalk** — every control maps to NIST, ISO 27001, SOC 2,
  and CIS; `/summary?framework=ISO27001` scores against one framework.
- **Exceptions / waivers + finding lifecycle** — accept risk with an approver
  and expiry (`/waivers`); active waivers drop failures from the score. Findings
  carry a lifecycle (open → in_progress → resolved → risk_accepted), updatable
  via `PATCH /findings/{id}`.
- **Scheduled / continuous assessments** — define recurring assessment sets
  (`/schedules`); a background runner executes due ones, or trigger via
  `POST /schedules/{id}/run` from an external cron (free-tier friendly). Each run
  captures a compliance snapshot.
- **Reports** — `/reports/csv` and `/reports/pdf` produce audit packages
  (PDF via reportlab) including framework mappings.
- **Notifications** — new failing findings dispatch to Slack, a generic webhook,
  and/or email (SMTP), gated by `NOTIFY_ON_STATUS`.
- **Asset discovery + bulk assess** — `/inventory/discover` enumerates a
  connector's assets; `/assessments/bulk` runs one control across all of them.
- **Trend history + drift detection** — `/trends` returns the score series;
  `/drift` reports pass→fail regressions and fail→pass recoveries per asset.
- **Legacy systems** — talk to mainframes, legacy databases, SOAP services,
  flat-file/SFTP exports, and LDAP directories that have no REST API. Sources
  are configured server-side and referenced by name (`source_system="LEGACY"`,
  `params={"source": "mainframe-hr"}`); a `field_map` normalizes their records
  into the same control fields. Clients never pass connection strings or
  queries, so there's no SSRF/SQL-injection surface. See
  `legacy_sources.example.json` and `GET /legacy/sources`.

## Architecture

```
                    FastAPI (app/main.py)
                           │
                AssessmentService (orchestration)
                           │
        ┌──────────────────┼───────────────────┐
        │                  │                    │
  ConnectorRegistry   PolicyEngine        EvidenceStore
   (12 connectors)   (control catalog)   (S3 / local, hashed)
        │                  │                    │
        └──────────────────┴───────────────────┘
                           │
                  PostgreSQL (findings,
                  evidence metadata, jobs,
                  idempotency keys)
```

Every connector implements one contract (`collect_telemetry`) and **normalizes**
vendor data into the fields the policy rules expect. That is what makes the
platform vendor-agnostic: adding a new system is one new connector class.

## Connector maturity

| Connector | Category | Maturity | Notes |
|-----------|----------|----------|-------|
| **DEMO** | testing | stable | Synthetic telemetry, no creds. Use for the dashboard demo. |
| **AWS** | cloud | production-ready* | boto3: IAM MFA, S3 encryption/public-access, CloudTrail |
| **Okta** | identity | production-ready* | REST: MFA factors, stale accounts |
| **GitHub** | code | production-ready* | REST: branch protection, secret scanning |
| **SSH/Linux** | on-prem | production-ready* | paramiko: disk encryption, auditd |
| **Jira** | ticketing | production-ready* | REST v3: change approval |
| Azure | identity/cloud | beta | Graph API; test against your tenant |
| GCP | cloud | beta | google-cloud-storage; test against your project |
| GitLab | code | beta | REST v4; mirrors GitHub connector |
| Slack | SaaS | beta | Web API; channel privacy as exposure proxy |
| ServiceNow | ticketing | beta | Table API; change approval |
| Qualys | vuln | beta | VM API; critical vuln counts |
| CrowdStrike | endpoint | beta | Falcon Spotlight; critical vuln counts |

\* *production-ready = correct, tested logic; validate against your account's
permissions before relying on results. beta = correct API patterns but needs
testing against your real tenant since auth/fields vary.*

## Quick start (local, no credentials)

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
# open http://localhost:8000/docs
```

Run a demo assessment (uses the DEMO connector — no creds):

```bash
curl -X POST http://localhost:8000/assessments \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"acme","control_id":"SC-7","source_system":"DEMO","asset_id":"my-bucket"}'
```

Force a failure to see remediation:

```bash
curl -X POST http://localhost:8000/assessments \
  -H "Content-Type: application/json" \
  -d '{"control_id":"SC-28","source_system":"DEMO","params":{"fail":true}}'
```

## Using real connectors

1. Copy `.env.example` to `.env`.
2. Fill in credentials for the systems you want (only those).
3. Set `source_system` to the connector id (AWS, OKTA, GITHUB, SSH, JIRA, ...).
4. `asset_id` identifies what to assess (an IAM username, an "owner/repo", a
   host, an issue key, etc. — see each connector's docstring).

Example — real AWS S3 public-access check:

```bash
curl -X POST http://localhost:8000/assessments \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"acme","control_id":"SC-7","source_system":"AWS","asset_id":"my-real-bucket"}'
```

## Control catalog

| Control | Title | Connectors |
|---------|-------|------------|
| AC-2-7 | Privileged account MFA | AWS, Okta, Azure, DEMO |
| AC-2-3 | Disable inactive accounts | AWS, Okta, DEMO |
| CM-3 | Change control approval | Jira, ServiceNow, DEMO |
| SC-28 | Encryption at rest | AWS, GCP, DEMO |
| SC-7 | No public exposure | AWS, GCP, Slack, DEMO |
| AU-2 | Audit logging enabled | AWS, SSH, DEMO |
| RA-5 | Vulnerability remediation | Qualys, CrowdStrike, DEMO |
| SA-15-BRANCH | Branch protection | GitHub, GitLab, DEMO |
| SA-15-SECRETS | Secret scanning | GitHub, DEMO |
| SC-28-HOST | Host disk encryption | SSH, DEMO |

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Service info, connectors, controls |
| GET | `/health/live`, `/health/ready` | Probes |
| GET | `/controls` | Control catalog |
| GET | `/connectors` | Connectors + live health |
| POST | `/assessments` | Run one control assessment |
| POST | `/assessment-jobs` | Run a batch |
| GET | `/findings?tenant_id=` | List findings |
| GET | `/summary?tenant_id=` | Compliance score |

## Authentication & tenant authorization

Data/assessment routes require an `X-API-Key`; keys are **scoped to tenants**.
Health/meta routes stay public.

- Off by default (no keys configured) → local dev / DEMO work freely.
- Enable with `COMP_LENS_API_KEYS`, entries separated by `;`:
  ```
  COMP_LENS_API_KEYS="reporter:acme,globex ; admin:*"
  ```
  `*` = admin (all tenants). A scoped key may only touch its tenants — a
  request for any other tenant returns **403**. Wrong key → 403, missing → 401.
  Keys compared in constant time.

This closes the gap where any valid key could read/write any tenant. For
SSO/JWT, swap `require_principal` for an OIDC check that returns a `Principal`.

## Database migrations

Production must NOT auto-create tables (it's off when `APP_ENV=production`).
Use Alembic:
```bash
alembic upgrade head        # apply schema
alembic revision --autogenerate -m "change"   # after model edits
```
Locally, tables auto-create on startup for convenience.

## Tests

```bash
pytest -q   # 152 tests, uses DEMO connector
```

## Deploy on AWS free tier

The cleanest fit for a tool that assesses AWS is to run it **inside AWS** with
an IAM role — then it needs no AWS keys at all.

**Option A — EC2 (t2.micro / t3.micro, free 12 months):**

1. Launch an Amazon Linux 2023 / Ubuntu instance.
2. Create an IAM role with `SecurityAudit` + `IAMReadOnlyAccess`, attach it to
   the instance (Actions → Security → Modify IAM role). No keys needed.
3. On the instance:
   ```bash
   sudo dnf install -y python3.11 git   # or apt on Ubuntu
   git clone https://github.com/shalak97/Comp-lens.git && cd Comp-lens
   pip install -r requirements.txt
   cp .env.example .env   # set APP_ENV=production, AWS_REGION, etc.
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```
4. Open port 8000 in the security group (or put Nginx/ALB in front).
5. For PostgreSQL, use **RDS db.t3.micro** (free tier) and set `DATABASE_URL`.
6. For evidence, set `EVIDENCE_BACKEND=s3` and `EVIDENCE_S3_BUCKET=...` with
   versioning + Object Lock enabled for true immutability.

**Option B — Docker (any host):**

```bash
docker compose up --build      # API + PostgreSQL
```

**Production hardening checklist:**
- Run behind HTTPS (ALB / Nginx + certbot).
- Set `CORS_ORIGINS` to your frontend URL, not `*`.
- Use RDS PostgreSQL, not SQLite.
- Use S3 evidence with Object Lock.
- Store secrets in AWS Secrets Manager / SSM Parameter Store, inject as env.
- Run behind auth (add an API key / JWT middleware before exposing publicly).
- Use Alembic for schema migrations instead of `init_db()` auto-create.

## Security notes

- No secrets are committed. All credentials come from environment variables.
- Prefer IAM roles over static AWS keys wherever the app runs on AWS.
- Evidence records carry a SHA-256 hash of the telemetry for tamper detection.

## License

MIT

## Connector Architecture

Comp-Lens has a two-layer connector system:

* **Registry (live telemetry)** — `app/connectors/*.py` classes implementing
  `BaseConnector` (healthcheck + per-control `collect_telemetry`). Used by the
  assessment engine.
* **Marketplace framework v2** — `app/connectors/catalog.py` defines 44
  connectors across 8 categories (cloud, identity, devops, itsm, security,
  grc, saas, endpoint) with auth method, required env vars, and the evidence
  types each produces. `app/connectors/framework.py` provides status, test,
  sync, and normalized evidence with multi-framework control mappings
  (NIST 800-53, ISO 27001:2022, NIST CSF, SOC 2, CIS v8, GDPR, ISO 42001 /
  NIST AI RMF) from `app/data/connector_control_map.json`.

Modes are honest: `connected` (creds valid, live), `demo` (realistic synthetic
evidence — works with zero credentials), `not_configured`, `error`.

Endpoints: `GET /connectors/catalog`, `GET /connectors/status`,
`GET /connectors/{name}`, `POST /connectors/{name}/test`,
`POST /connectors/{name}/sync`, `GET /connectors/{name}/evidence`,
`GET /evidence/by-connector/{name}`.

Setup: set the env vars listed per connector in the catalog (names are shown
in the dashboard marketplace; values are never logged or returned). With no
credentials, every connector still tests and syncs in demo mode.
