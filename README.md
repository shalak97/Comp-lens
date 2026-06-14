# Comp-Lens 2.0 — GRC + TPRM Compliance-as-Code

A GRC and third-party risk management platform where live connector evidence actually flows into your risk scores.

Most compliance tools are scoreboards. Comp-Lens is a connected system: connectors collect evidence → evidence satisfies controls → controls mitigate risks → risks link to vendors. When evidence goes stale or a connector breaks, residual risk climbs automatically. When you fix a failing control, your score moves.

**Live demo:** https://comp-lens-2-0.onrender.com/dashboard  
*(Hosted on Render free tier — give it 30–60 seconds to wake from sleep on first load)*

---

## What it does

### Live telemetry chain
A risk's residual score is not hand-typed. It is derived from the strength of the control that mitigates it, which is derived from whether a connector is actively syncing fresh evidence for that control. Sync Okta → AC-2 is evidenced → the risk linked to AC-2 drops from inherent to residual. Evidence goes stale → residual climbs back. The math is transparent and explainable.

### Trust graph
One view connecting vendors → connectors → controls → risks with typed edges (`operates`, `evidences`, `mitigates`, `owns`). Controls with no live evidence render faded. Rotating 3D canvas, drag/scroll/click to inspect any node.

### Knowledge graph
Documents and connectors both feeding evidence into controls — the full picture of what proves your controls, in one place.

### GRC risk register
Risks as first-class objects: likelihood × impact scoring, inherent vs computed residual, treatment decisions (mitigate / accept / transfer / avoid), owner, review cadence.

### TPRM vendor lifecycle
Vendors move through onboarding → assessment → active → offboarding. Each vendor links to a connector (inheriting its live posture), holds an assessment score, and flags DPA gaps when handling PII/PHI/financial data without a data processing agreement.

### Connected intelligence
- **Blast Radius simulator** — pre-loads your actual failing controls, runs the cascade, lets you log the result as a risk, file a waiver, or jump to remediation
- **Remediation optimizer** — fix queue built from your real open findings, ranked by leverage (risk reduction ÷ effort), each row links back to the simulator
- **Waivers** — shows which failing controls are and aren't covered, lets you file one directly from an uncovered failure

### Connector marketplace
44 connectors across 8 categories. 16 backed by production read-only API integrations to real third-party services (plus internal demo and AI-governance connectors). The remaining connectors are catalog-ready with demo evidence while awaiting live implementation. All connectors are locked to demo by default — live calls require an explicit allowlist.

---

## Tech stack

| Layer | Tech |
|---|---|
| API | FastAPI, Python 3.11 |
| Database | PostgreSQL (Alembic migrations) |
| ORM | SQLAlchemy 2.0 |
| Auth | HMAC-safe API key, tenant-scoped |
| Deployment | Docker, Render |
| Tests | pytest, 136 passing |
| Dashboard | Single-file HTML/JS, no framework |

---

## Connectors

### Cloud
| Connector | Status |
|---|---|
| AWS Security Hub | ✅ implemented |
| AWS IAM | ✅ implemented |
| AWS Config | ✅ implemented |
| Azure Defender | ✅ implemented |
| GCP Security Command Center | ✅ implemented |
| GCP IAM | ✅ implemented |

### Identity
| Connector | Status |
|---|---|
| Okta | ✅ implemented |
| Microsoft Entra ID | ✅ implemented |
| Google Workspace | demo |
| OneLogin | demo |
| Ping Identity | demo |

### DevOps
| Connector | Status |
|---|---|
| GitHub | ✅ implemented |
| GitLab | ✅ implemented |
| Bitbucket | demo |
| Jenkins | demo |
| SonarQube | demo |
| Snyk | demo |

### ITSM
| Connector | Status |
|---|---|
| Jira | ✅ implemented |
| ServiceNow | ✅ implemented |
| Freshservice | demo |

### Security
| Connector | Status |
|---|---|
| CrowdStrike Falcon | ✅ implemented |
| Qualys VMDR | ✅ implemented |
| Tenable | demo |
| Wiz | demo |
| Prisma Cloud | demo |
| SentinelOne | demo |
| Splunk | demo |
| Microsoft Sentinel | demo |

### SaaS
| Connector | Status |
|---|---|
| Slack | ✅ implemented |
| Microsoft 365 | demo |
| Google Drive | demo |
| Confluence | demo |
| SharePoint | demo |

### Endpoint
| Connector | Status |
|---|---|
| SSH / Linux | ✅ implemented |
| Windows Server | demo |
| Database Audit | demo |

### GRC
| Connector | Status |
|---|---|
| OneTrust | demo |
| Archer | demo |
| ServiceNow GRC | demo |
| Vanta | demo |
| Drata | demo |
| Secureframe | demo |

All implemented connectors are **read-only**. They make the minimum API calls necessary to assess specific controls — no bulk exports, no write operations.

---

## Running your own instance

### Prerequisites
- Python 3.11+
- PostgreSQL database (Neon free tier works)
- Docker (for Render deploy)

### Local setup

```bash
git clone https://github.com/shalak97/Comp-lens-2.0.git
cd Comp-lens-2.0
pip install -r requirements.txt

# set required env vars
export DATABASE_URL="postgresql+psycopg://user:pass@host/db"
export EVIDENCE_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export COMP_LENS_API_KEYS="yourkey:default"
export APP_ENV=development

# run migrations
alembic upgrade head

# start
uvicorn app.main:app --reload --port 8000
```

Dashboard: http://localhost:8000/dashboard  
API docs: http://localhost:8000/docs

### Deploy to Render

1. Fork this repo
2. Create a new Render web service pointing at your fork
3. Render will use `render.yaml` — it provisions a free PostgreSQL database automatically
4. Set the required env vars in Render → your service → Environment:

```
EVIDENCE_SIGNING_KEY    <generate with: python -c "import secrets; print(secrets.token_urlsafe(32))">
COMP_LENS_API_KEYS      yourkey:default
APP_ENV                 production
```

---

## Connecting a real service

All connectors are locked to demo by default. To enable live calls for a specific connector:

**Step 1 — Set the safety env vars on your deployment:**
```
LIVE_CONNECTORS_ENABLED=true
LIVE_CONNECTORS_ALLOWLIST=OKTA,GITHUB    # only listed connectors go live
```

**Step 2 — Add that connector's credentials (read-only token):**

```bash
# Okta (read-only SSWS token)
OKTA_ORG_URL=https://dev-123456.okta.com
OKTA_API_TOKEN=00abc...

# GitHub (read-only PAT: repo:read + read:org)
GITHUB_TOKEN=ghp_...

# AWS (SecurityAudit + IAMReadOnly policy)
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1

# Jira
JIRA_URL=https://yourorg.atlassian.net
JIRA_EMAIL=you@company.com
JIRA_API_TOKEN=...

# Azure / Entra ID
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...

# GitLab
GITLAB_TOKEN=...
GITLAB_GROUP=your-group

# Slack
SLACK_BOT_TOKEN=xoxb-...

# ServiceNow
SERVICENOW_INSTANCE=yourorg.service-now.com
SERVICENOW_USER=...
SERVICENOW_PASSWORD=...

# CrowdStrike
CROWDSTRIKE_CLIENT_ID=...
CROWDSTRIKE_CLIENT_SECRET=...

# Qualys
QUALYS_PLATFORM_URL=...
QUALYS_USER=...
QUALYS_PASSWORD=...

# SSH
SSH_HOST=...
SSH_USER=...
SSH_PRIVATE_KEY=...

# GCP
GCP_PROJECT_ID=...
GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
```

**Always use read-only, minimally-scoped tokens.** The safety guardrails enforce read-only at the framework level, but a narrowly-scoped token is your outermost protection.

Your credentials stay on your deployment — they are never sent to the demo instance.

---

## Security

- **Auth**: API key required for all non-public endpoints. Set `COMP_LENS_API_KEYS=key:tenant` (comma-separated for multiple). Unset = auth disabled (development only, app warns).
- **Connector safety**: three-layer guardrail system — global kill-switch, per-connector allowlist, read-only method enforcement. All fail-closed (no live calls by default).
- **SQL injection**: all queries via SQLAlchemy ORM with bound parameters. No raw/f-string SQL anywhere.
- **Secret exposure**: connector credentials are presence-checked via env vars only — never returned in API responses.
- **Evidence signing**: documents are HMAC-signed. Set `EVIDENCE_SIGNING_KEY` to a real secret in production.
- **SSRF protection**: URL-fetching service blocks private/loopback/metadata IPs, resolves all addresses, disables auto-redirects, caps size and time.
- **Tenant isolation**: every data endpoint is scoped to a tenant; cross-tenant requests return 403.

Known hardening items (acceptable for current stage, worth improving):
- No rate limiting
- CORS defaults to `*` — set `CORS_ORIGINS` to your dashboard URL in production
- SSH connector uses `AutoAddPolicy` (host-key not verified)

---

## Running tests

```bash
export DATABASE_URL="sqlite+pysqlite:////tmp/test.db"
export APP_ENV=test
export EVIDENCE_SIGNING_KEY=ci
export ENABLE_SCHEDULER=false

alembic upgrade head
pytest tests/ -q
```

136 tests across connectors, GRC risk register, TPRM, trust graph, coverage intelligence, evidence signing, and auth.

---

## API

89 routes across 8 tag groups. Full interactive docs at `/docs` when running.

Key endpoints:

```
GET  /dashboard              → dashboard UI
GET  /summary                → compliance score, findings breakdown
GET  /controls               → automated control catalog
GET  /findings               → open findings with severity and source
GET  /connectors/status      → all 44 connectors with live/demo/not-configured state
GET  /connectors/safety      → safety guardrail state (mode, allowlist)
POST /connectors/{key}/sync  → sync a connector (demo or live depending on creds + allowlist)
POST /connectors/{key}/test  → healthcheck a connector
GET  /trust/graph            → full vendor→connector→control→risk graph
GET  /trust/risk-telemetry   → per-risk inherent vs live-computed residual
GET  /grc/risks              → risk register
POST /grc/risks              → create risk
GET  /tprm/vendors           → vendor list with lifecycle stage and risk
POST /tprm/vendors           → create vendor (link to a connector key for live posture)
GET  /simulate               → blast radius: which controls cascade from a failure
GET  /remediation            → prioritized fix queue ranked by leverage
```

---

## Dashboard

Single-file `dashboard.html` — no build step, no framework, no CDN dependencies. 15 tabs:

**Posture** — Overview · Controls · Findings · Frameworks  
**Evidence** — Connectors · Knowledge Graph · Evidence Docs  
**Intelligence** — Blast Radius · Remediation · Trends · AI Inventory · Waivers  
**Risk & Vendors** — Risk Register · Vendors (TPRM) · Trust Graph

Connects to your API automatically. Falls back to realistic demo data if the API is unreachable. To run your own instance, upload to repo root and run the `wire-dashboard` GitHub Actions workflow.

---

## Frameworks supported

NIST SP 800-53 Rev 5 (1,196 controls), ISO/IEC 27001:2022 (93 controls), SOC 2, CIS Controls, ISO 42001 (AI governance), NIST AI RMF, EU AI Act.

---

## License

MIT — fork it, extend it, use it. If you build something interesting on top of this, I'd genuinely like to hear about it.

---

*Built solo. Feedback welcome — especially from practitioners in GRC, security engineering, or risk management.*
