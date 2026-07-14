# Comp-Lens 

**Comp-Lens ** is a Compliance-as-Code and continuous control monitoring platform for GRC, security, audit, and AI governance teams.

It helps organizations map controls across multiple frameworks, collect technical evidence, detect control failures, track remediation, manage waivers, and generate audit-ready reports from a single platform.

---

## Problem Statement

Compliance programs are often manual, fragmented, and reactive.

Teams usually rely on spreadsheets, screenshots, email trails, and point-in-time evidence collection. This creates problems such as:

- Delayed control testing
- Manual evidence collection
- Weak audit traceability
- Poor visibility into control failures
- Duplicate work across frameworks
- Limited linkage between technical telemetry and compliance risk
- No continuous view of audit readiness

**Comp-Lens 2.0** solves this by converting compliance into a continuous, evidence-driven workflow.

---

## What Comp-Lens Does

Comp-Lens connects technical systems, compliance controls, evidence records, risk scoring, and reporting into one operating layer.

The platform is designed to answer questions such as:

- Are our controls passing or failing?
- Which frameworks are impacted by a failed control?
- Which systems produced the evidence?
- Is the evidence fresh and verifiable?
- Which findings should be remediated first?
- Which controls are waived?
- What is our current audit readiness?
- What AI systems require governance review?

---

## Key Features

### 1. Continuous Control Monitoring

Comp-Lens evaluates controls using telemetry from connected systems.

Example checks include:

- MFA enforcement
- Privileged access review
- Encryption at rest
- Security logging
- Repository branch protection
- Cloud configuration checks
- Vulnerability posture
- Configuration drift
- Evidence freshness

---

### 2. Multi-Framework Control Mapping

One technical control can map to multiple compliance frameworks.

Supported frameworks (in the built-in crosswalk):

- NIST 800-53
- ISO/IEC 27001
- SOC 2
- CIS Controls
- NIST AI RMF
- ISO/IEC 42001 (AI management systems)
- EU AI Act

This reduces duplicate work and allows one evidence item to support multiple audit requirements.

---

### 3. Evidence Management

Comp-Lens is built around audit-ready evidence.

Evidence records can include:

- Control ID
- Framework
- Source system
- Asset ID
- Timestamp
- Evidence hash
- Verification status
- Freshness status
- Audit trail metadata

This helps prove not only whether a control passed, but also when it passed, where the evidence came from, and whether the evidence remained unchanged.

---

### 4. Connector-Based Architecture

Comp-Lens is designed to collect evidence from enterprise systems through connectors.

Example connector categories:

| Category | Example Systems |
|---|---|
| Cloud | AWS, Azure, GCP |
| Identity | Okta, Azure AD |
| DevSecOps | GitHub, GitLab |
| ITSM | Jira, ServiceNow |
| Vulnerability | Qualys, CrowdStrike |
| Collaboration | Slack |
| Infrastructure | Linux / SSH |

---

### 5. Findings and Remediation

Comp-Lens converts failed control checks into findings.

Findings can include:

- Control ID
- Severity
- Source system
- Asset ID
- Description
- Status
- Risk impact
- Remediation recommendation

This helps security and compliance teams move from visibility to action.

---

### 6. Waiver and Exception Management

Comp-Lens supports waiver and exception workflows for cases where a control cannot be immediately remediated.

Waivers can help track:

- Business justification
- Risk acceptance
- Expiry date
- Control impact
- Owner
- Approval status

---

### 7. AI Governance Register

Comp-Lens includes an AI governance layer for tracking AI systems and their risk posture.

AI governance fields may include:

- AI system name
- Business owner
- Risk tier
- Data governance status
- Human oversight
- Transparency notice
- Evaluation report
- Logging status
- Impact assessment status

This supports governance requirements for high-risk AI systems.

---

### 8. Reporting and Exports

Comp-Lens can support audit and leadership reporting through:

- Executive risk summaries
- Control evidence reports
- Findings reports
- Waiver registers
- CSV exports
- PDF reports
- OSCAL-style machine-readable exports

---

## Example Use Cases

### Security Compliance

Track whether technical controls are operating effectively across cloud, IAM, endpoint, and DevSecOps systems.

### Audit Readiness

Generate evidence-backed reports showing control status, findings, waivers, and remediation progress.

### GRC Automation

Reduce manual spreadsheet-based compliance tracking by continuously collecting and evaluating control evidence.

### AI Governance

Maintain an inventory of AI systems and track governance requirements such as risk tier, evaluation reports, and human oversight.

### Control Mapping

Map one technical control to multiple frameworks to reduce duplicate evidence collection.

---

## High-Level Architecture

```text
Connectors
   ↓
Telemetry Normalization
   ↓
Policy and Control Evaluation
   ↓
Findings and Evidence Store
   ↓
Risk Scoring and Remediation
   ↓
Dashboard and Reports
```

---

## Core Modules

```text
app/
├── connectors/           # Integrations with source systems
├── services/             # Assessment, remediation, evidence, simulation logic
├── policy_as_code/       # Control and policy evaluation
├── static/               # Dashboard UI
├── models.py             # Data models
├── config.py             # Application configuration
├── database.py           # Database setup
└── main.py               # FastAPI application
```

---

## Dashboard

The dashboard is designed to provide a single view of:

- Overall compliance score
- Risk-weighted score
- Open findings
- Connector health
- Control coverage
- Evidence status
- Drift indicators
- Remediation queue
- AI governance status
- Report exports

---

## API Capabilities

Example API areas include:

| Area | Purpose |
|---|---|
| `/summary` | Compliance and risk summary |
| `/findings` | Control findings |
| `/waivers` | Waiver and exception tracking |
| `/remediation` | Remediation recommendations |
| `/connectors/status` | Connector health |
| `/v1/policy/list` | Control and policy catalog |
| `/evidence/verify` | Evidence verification |
| `/evidence/anchors` | Evidence integrity anchors |
| `/ai/systems` | AI governance register |
| `/reports/pdf` | PDF report export |
| `/reports.csv` | CSV report export |

---

## Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/shalak97/Comp-lens-2.0.git
cd Comp-lens-2.0
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

On macOS/Linux:

```bash
source .venv/bin/activate
```

On Windows:

```bash
.venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
uvicorn app.main:app --reload --port 8000
```

### 6. Open the dashboard

```text
http://localhost:8000/dashboard
```

---

## Production Considerations

Before using Comp-Lens in production, review and harden:

- Authentication and API key enforcement
- Tenant isolation
- Database configuration
- Evidence storage backend
- Evidence signing keys
- Secrets management
- Connector credential handling
- Rate limiting
- Logging and monitoring
- Dependency pinning
- CI/CD security
- Backup and recovery
- Audit logging

---

## Roadmap

Planned or recommended future improvements:

- Role-based access control
- Stronger tenant isolation
- Advanced connector configuration UI
- Evidence approval workflow
- Control owner assignment
- SLA-based remediation tracking
- Risk acceptance workflow
- Framework-specific audit packages
- Better graph visualization
- Integration with ticketing systems
- More AI governance workflows
- Policy-as-code versioning
- Compliance trend forecasting

---

## Positioning

Comp-Lens 2.0 is positioned as a practical, engineering-driven GRC platform that connects security telemetry with compliance outcomes.

It is suitable for:

- GRC analysts
- Security engineers
- IT auditors
- Compliance teams
- Cloud security teams
- AI governance teams
- Risk management teams

---

## License

MIT License
