# Comp-Lens 2.0 — Compliance as Code<img width="2680" height="1800" alt="image" src="https://github.com/user-attachments/assets/e0b4c609-73e4-47cb-8bf1-d4c1e4e4ad8f" />


Open-source GRC platform where live connector evidence flows into risk scores, policies are YAML files that run in CI, and every AI system's privacy risk is computed — not hand-typed.

**Live demo:** https://comp-lens-2-0.onrender.com/dashboard  
*(Render free tier — allow 30–60 seconds to wake on first load)*  
**GitHub:** https://github.com/shalak97/Comp-lens-2.0  
**License:** MIT

---

## What makes it different

Most GRC tools are compliance scorecards. You enter numbers and it shows you numbers. Comp-Lens derives its numbers from live evidence:

- A connector syncs from Okta → AC-2 is evidenced → the risk linked to AC-2 drops from inherent to residual
- Evidence goes stale → residual climbs back automatically  
- A policy evaluates to `fail` → that decision becomes a finding in the same stream scanners write to → blast radius picks it up → remediation ranks it
- An AI system with weak k-anonymity (k=2) handling PHI data → the engine computes a high residual privacy risk → the risk register gets a linked entry automatically

The math is transparent, the flow is connected, and there are no hand-typed compliance checkboxes.

---

## Architecture

```
Connectors (18 production) ──► Evidence store ──► Control assessments
                                                          │
                     Policy engine (YAML, AST-safe) ──────┤
                     Threat intel (CISA KEV / EPSS) ───────┤
                     AI governance (PET assessment) ────────┤
                                                            ▼
                                              Findings + Risk register
                                                            │
                              Blast radius ◄────────────────┤
                              Remediation ◄─────────────────┤
                              Audits ◄──────────────────────┘
```

**Backend:** FastAPI (Python 3.11), PostgreSQL (SQLAlchemy / Alembic), Pydantic v2  
**Dashboard:** Single-file vanilla JS — no framework, instant load  
**Resilience:** `ResilientClient` — retries, exponential backoff, 429 handling, circuit breaker, SSRF guard, credential redaction  
**Tests:** 203 passing

---

## Features

### Compliance as code

Policies are YAML files in `policies/`. They live in git, go through PRs, and run in CI.

```yaml
control: SC-28
severity: high
frameworks:
  NIST: [SC-28]
  ISO27001: [A.8.24]
params:
  max_scan_age_days: 30
rules:
  - id: all_storage_encrypted
    when: "all(storage, 'encryption_at_rest == true')"
    else_fail: "One or more data stores are not encrypted at rest"
    severity: high
  - id: scan_freshness
    when: "scan_age_days < max_scan_age_days"
    severity: medium
severity_escalation:
  - when: "any(storage, 'public == true and encryption_at_rest == false')"
    severity: critical
obligations:
  on_fail: [open_jira_ticket, notify_security_slack]
```

The policy engine supports: multi-rule policies, parameterized thresholds, quantifiers over collections (`all(buckets, 'encrypted == true')`), dynamic severity escalation, policy composition (`requires: [AC-2, IA-2]`), and obligations. Expressions run through a strict AST allowlist — `eval()` is never called.

```bash
complens-policy test
# Policy tests: 14/14 passed

complens-policy eval --control SC-28 --evidence '{"storage": [{"encryption_at_rest": false}]}'
# SC-28 FAIL (critical) · open_jira_ticket, notify_security_slack
```

### Live evidence pipeline

`POST /v1/events?source=prowler` — ingest findings from any scanner. Comp-Lens normalizes to a canonical format and evaluates against policies. Evidence is signed (HMAC-SHA256) and chained into a Merkle transparency log.

### Blast radius simulator

Given failing controls, propagate the cascade through the dependency graph. The BFS uses `collections.deque` (O(1) per step). Cascade nodes are enriched with external threat intelligence — a failing RA-5 with actively-exploited CVEs shows real-world exploitation pressure, not just a status badge.

### Threat intelligence (free, no API keys)

Three live feeds — all free, no registration:

| Feed | What it provides |
|------|-----------------|
| CISA KEV | 1,200+ actively-exploited CVEs, ransomware flags |
| EPSS (FIRST.org) | Exploit probability scores per CVE |
| NVD / NIST | CVE severity and CVSS scores |

Cached 6 hours. Falls back to a seed of real famous CVEs (Log4Shell, MOVEit, PAN-OS, regreSSHion) if the feed is unreachable.

### AI governance

Track AI/ML systems with their privacy-enhancing technologies. Residual privacy risk is computed dynamically from data sensitivity and PET parameters — not hand-entered.

**PET assessment:**

| Technology | What's assessed |
|-----------|----------------|
| Differential privacy | ε budget (ε < 1 = strong, ε > 10 = weak) |
| Homomorphic encryption | Scheme (CKKS/BFV/BGV/TFHE = fully homomorphic, Paillier = partial) |
| k-Anonymity | k value (k ≥ 10 strong, k < 3 weak) |
| Federated learning | Raw data never centralised |
| Secure MPC | No party sees raw inputs |
| Synthetic data | No real subjects in training |
| Data minimisation | Scope-limited collection |

```
PHI data + no PETs           → residual 80 (critical)
PHI data + DP ε=0.5 + CKKS  → residual 6  (low, floored — no PET is absolute)
```

EU AI Act risk tiers map to their specific obligations and compute coverage gaps from the system's governance booleans.

### GRC + TPRM

- **Risk register** — likelihood × impact scoring, inherent vs. residual, treatment decisions (mitigate / accept / transfer / avoid), owner, review cadence. Visualised as a 5×5 risk matrix heatmap.
- **TPRM vendor lifecycle** — onboarding → assessment → active → offboarding. Vendors link to connectors and inherit live posture.
- **Trust graph** — vendors → connectors → controls → risks with typed edges. 2D Sankey flow and 3D force-directed graph.

### Audit management

Full engagement lifecycle: auto-built control checklist from the framework mapping, evidence requests (PBC list), review decisions, evidence sign-off, and auditor-ready export.

### Integration layer

Three cross-feature flows that close silos between the standalone capabilities:

```
POST /v1/integrate/policy-to-findings   failing policy → finding → blast radius
POST /v1/integrate/ai-to-risk           high-residual AI system → risk register
POST /v1/integrate/threat-escalation    KEV pressure escalates vuln-control risks
POST /v1/integrate/run                  all three in one call
```

All flows are idempotent (safe to re-run) and use existing tables — no migration.

---

## Connectors

18 production connectors — all make live API calls when credentials are set, all route through `ResilientClient`. No connector returns fake evidence. With no credentials a connector reports "not configured."

| Category | Connectors |
|----------|-----------|
| Cloud | AWS Security Hub, AWS IAM, AWS Config, Azure Defender, GCP SCC, GCP IAM |
| Identity | Okta, Microsoft Entra ID |
| DevOps | GitHub, GitLab |
| Security | CrowdStrike Falcon, Qualys VMDR |
| ITSM | Jira, ServiceNow |
| Collaboration | Slack |
| Infrastructure | SSH / Linux |
| Catalog-ready | Tenable, Wiz (connector class + credentials-ready) |

**Connector allowlist** — live API calls require explicit opt-in. Set `LIVE_CONNECTORS_ALLOWLIST=OKTA,GITHUB` to activate specific connectors. All connectors are read-only; `POST` / `DELETE` methods are rejected at the HTTP client layer.

---

## API surface

```
# Evidence / Telemetry
POST  /v1/events               ingest findings from any scanner
GET   /summary                 compliance posture
GET   /findings                all findings (filterable)

# Policy as code
GET   /v1/policy/list
POST  /v1/policy/evaluate      evaluate evidence against one control
POST  /v1/policy/evaluate-all  two-pass eval (resolves composition requires:)
POST  /v1/policy/test          run inline policy tests

# Threat intelligence
GET   /v1/threat/summary       KEV count, ransomware, recent additions
GET   /v1/threat/kev           full catalog (filterable, ransomware-only flag)
POST  /v1/threat/enrich        enrich controls with KEV/EPSS context

# AI governance
GET   /v1/ai-gov/pet-catalog
POST  /v1/ai-gov/assess-pet    assess one PET's strength from its params
GET   /v1/ai-gov/systems/{id}/risk  dynamic privacy risk for a system
POST  /v1/ai-gov/score         ad-hoc privacy risk (no persistence)

# Integration
POST  /v1/integrate/policy-to-findings
POST  /v1/integrate/ai-to-risk
POST  /v1/integrate/threat-escalation
POST  /v1/integrate/run

# GRC / TPRM / Audits / Blast radius
GET/POST/PATCH/DELETE  /grc/risks
GET/POST/PATCH/DELETE  /tprm/vendors
GET/POST/PATCH/DELETE  /audits
POST                   /simulate        blast radius + threat enrichment
GET                    /remediation     ranked remediation plan
GET                    /trust/graph
GET                    /waivers
```

Full interactive docs at `/docs`.

---

## Quick start

**Prerequisites:** Python 3.11+, PostgreSQL (or [Neon free tier](https://neon.tech))

```bash
git clone https://github.com/shalak97/Comp-lens-2.0.git
cd Comp-lens-2.0
pip install -r requirements.txt

export DATABASE_URL="postgresql://user:pass@host/complens"
export EVIDENCE_SIGNING_KEY="$(openssl rand -hex 32)"
export APP_ENV=production

python -m alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Dashboard: `http://localhost:8000/dashboard`  
API docs: `http://localhost:8000/docs`

**Deploy to Render:** `render.yaml` is included. Fork → connect to Render → add a PostgreSQL database → set `DATABASE_URL` and `EVIDENCE_SIGNING_KEY` → deploy. Migrations run automatically.

### Connecting a tool

Connectors activate when their credentials are present and the connector key is in the allowlist:

```bash
OKTA_ORG_URL=https://your-org.okta.com
OKTA_API_TOKEN=your-ssws-token

GITHUB_TOKEN=ghp_...

AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1

LIVE_CONNECTORS_ALLOWLIST=OKTA,GITHUB,AWS
```

### Adding a policy

```yaml
# policies/my_policy.yaml
control: AC-2
severity: high
frameworks:
  NIST: [AC-2]
  SOC2: [CC6.1]
pass_when: "mfa_enforced == true and dormant_accounts == 0"
tests:
  - name: clean passes
    evidence: {mfa_enforced: true, dormant_accounts: 0}
    expect: pass
  - name: dormant accounts fail
    evidence: {mfa_enforced: true, dormant_accounts: 4}
    expect: fail
```

```bash
python cli/complens_policy.py --policies ./policies test
```

Reload without restart: `POST /v1/policy/reload`

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✓ | PostgreSQL connection string |
| `EVIDENCE_SIGNING_KEY` | ✓ | HMAC key for evidence signing (32+ hex chars) |
| `APP_ENV` | | `production` / `test` (default: `development`) |
| `COMP_LENS_API_KEYS` | | `key:tenant,key2:*` (omit to disable auth) |
| `LIVE_CONNECTORS_ALLOWLIST` | | Comma-separated connector keys e.g. `OKTA,GITHUB` |
| `ENABLE_SCHEDULER` | | `true` to run background sync |
| `POLICY_DIR` | | Path to YAML policies (default: `./policies`) |
| `EVIDENCE_BACKEND` | | `local` or `s3` |
| `NOTIFY_SLACK_WEBHOOK` | | Slack webhook for control-failure alerts |
| `ANTHROPIC_API_KEY` | | Enables AI agent features (optional) |

Per-connector credential variables (e.g. `OKTA_API_TOKEN`, `AWS_ACCESS_KEY_ID`) are documented in `app/config.py` and in `render.yaml` as commented examples.

---

## Running tests

```bash
export DATABASE_URL="sqlite+pysqlite:////tmp/test.db"
export APP_ENV=test
export EVIDENCE_SIGNING_KEY=testkey
export ENABLE_SCHEDULER=false

python -m pytest tests/ -q
# 203 passed
```

---

## What's honest

**What's real:**
- All 18 connectors make genuine API calls — none return synthetic data
- The policy engine runs against real evidence; expressions are AST-evaluated, never `eval()`'d
- Threat intelligence comes from public CISA/EPSS/NVD feeds — no API keys, no cost
- AI-governance privacy scores are computed from actual PET parameters
- 203 tests cover the core logic, all passing on the deployed codebase
- The blast radius BFS, policy AST cache, and 528-line duplicate block in `main.py` have all been fixed

**What has caveats:**
- Connector field mappings follow each vendor's documented REST API but depend on your product tier — validate against your own tenant on first connection
- AI-governance PET effectiveness scores are reasoned heuristics based on published privacy research, not formal proofs
- Policy `obligations` (open_jira_ticket, etc.) are declared and attached to decisions; automatic execution requires wiring to your middleware destinations — the plumbing is there, the mapping is yours to configure
- Render free tier sleeps after inactivity — first request after sleep takes 30–60 seconds

---

## Project structure

```
app/
├── main.py                    FastAPI app — 123 endpoints, zero duplicates
├── models.py                  SQLAlchemy models (10 migrations)
├── config.py                  Pydantic settings + connector credentials
├── connectors/
│   ├── base.py                BaseConnector contract (read-only, normalized output)
│   ├── http_client.py         ResilientClient (retries, circuit breaker, SSRF, redaction)
│   ├── okta.py / aws.py / github.py / ssh_linux.py / jira.py
│   └── secondary.py           Azure, GCP, GitLab, Slack, ServiceNow, Qualys, CrowdStrike
├── policy_as_code/
│   ├── evaluator.py           Safe AST evaluator with lru_cache (no eval())
│   └── engine.py              PolicyEngine — multi-rule, escalation, composition
└── services/
    ├── integration.py         Cross-feature wiring
    ├── threat_intel.py        CISA KEV + EPSS + NVD
    ├── ai_governance.py       PET assessment + dynamic privacy risk
    ├── simulator.py           Blast radius BFS (O(1) deque)
    ├── audit_service.py       Audit lifecycle + PBC
    └── ...
policies/                      YAML compliance policies (version-controlled)
cli/
└── complens_policy.py         Policy test / eval / list CLI
tests/                         203 tests
```

---

*FastAPI · PostgreSQL · Alembic · Pydantic v2 · MIT License*
