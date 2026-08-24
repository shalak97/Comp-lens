# How to use Comp-Lens

A practical, task-oriented guide to operating Comp-Lens — installing it, connecting
the dashboard, and working through every screen. For what the platform is and why
it exists, see [`README.md`](README.md). For how it's built, see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

Every endpoint and button named below was cross-checked against the running code —
`app/main.py` (150+ routes) and `app/static/dashboard.html` (the console) — as of
this guide's writing. Where the dashboard itself is honest about a feature being
incomplete (the knowledge graph, waivers), this guide says so too.

---

## 1. Install and run it

### One-command install (recommended)

```bash
git clone <this repo> && cd Comp-lens
./install.sh
```

`install.sh` checks Docker is installed, generates a random `POSTGRES_PASSWORD`
and `EVIDENCE_SIGNING_KEY` (via `openssl rand -hex 32`), writes them to a
`.env` file at `chmod 600` (never committed — see `.gitignore`), then runs
`docker compose build && up -d` and waits for `/health/ready`. Re-running it is
safe: it won't overwrite an existing `.env` or touch your data.

When it finishes:

| | |
|---|---|
| Dashboard | `http://localhost:8000/dashboard` |
| API docs | `http://localhost:8000/docs` (Swagger UI) |
| Health | `http://localhost:8000/health/ready` |

### Manual Docker Compose

```bash
cp .env.example .env   # fill in POSTGRES_PASSWORD and EVIDENCE_SIGNING_KEY yourself
docker compose up -d
```

`docker-compose.local.yml` is a lighter local-dev variant (plaintext local DB
password, Postgres port exposed) — use it for development, not deployment.

### Render (one-click cloud deploy)

`render.yaml` defines a `web` service (Docker) plus a managed Postgres database.
Deploy it via Render's Blueprint flow; set `COMP_LENS_API_KEYS` and
`EVIDENCE_SIGNING_KEY` in the Render dashboard (marked `sync: false`, so they
never touch git) — **the app refuses to start in production without them.**

---

## 2. Connect the dashboard

The dashboard is a static console (`app/static/dashboard.html`) that talks to
whatever API base URL you point it at — it doesn't have to be the instance that
served it.

Click the **connection chip** (bottom of the left rail, shows *Connecting…* /
*Live* / *Offline* / *Demo*) to open **Connection settings**:

| Field | Meaning |
|---|---|
| API base URL | e.g. `https://your-instance.onrender.com`. Stored only in this browser tab. |
| API key | Sent as `X-API-Key`. Leave blank if auth is off. |
| Tenant ID | Scopes every request; defaults to `default`. |

Click **Save & reconnect**. The dashboard **never auto-switches to demo data**
if a live call fails — it just shows *Offline*, so you can't mistake a broken
connection for an empty environment.

**Demo mode** (the toggle next to the connection chip, or **Use demo data** in
the settings dialog) replaces every view with a fixed sample dataset for the
session — nothing is read from or written to your real instance while it's on.
Turning it on from a live connection asks for confirmation first.

---

## 3. Authentication & tenants

Auth is controlled by one environment variable, `COMP_LENS_API_KEYS`:

```
key1:tenantA,tenantB ; key2:*
```

- Semicolon-separated entries; `key:tenant1,tenant2` scopes a key to those
  tenants, `key:*` is an admin key (all tenants).
- **Unset entirely → auth is off** and every request is treated as an
  all-tenant admin. Fine behind a VPN or for local dev; the app **refuses to
  start this way in production** (`APP_ENV=production` with no keys → `503`).
- Generate a key: `python -c "import secrets; print(secrets.token_urlsafe(32))"`.

Every API call carries `?tenant_id=<id>` (the dashboard adds this
automatically once you've set a Tenant ID in Connection settings); a key can
only act on the tenants it's scoped to.

---

## 4. The dashboard, screen by screen

The rail groups 22 screens into 5 sections. Rows in tables across the app are
usually clickable — clicking one opens a **detail drawer** with the full record
and any actions available for it (this is a generic pattern, not
screen-specific, so it's called out once here rather than per screen).

### Posture

| Screen | What it shows | Reads from |
|---|---|---|
| **Overview** | Compliance score, trend, framework readiness, unified trust snapshot | `/summary`, `/trends`, `/catalog/frameworks`, `/v1/grc-trust/unified` |
| **Controls** | Every control's current status; click a row for detail, incl. **Run assessment** | `/controls`, `/v1/grc-trust/unified`, `POST /assessments` |
| **Findings** | Open issues with a lifecycle (open → resolved / risk-accepted). Filter by status/severity. Drawer actions: **Mark resolved**, **Accept risk**, **Create ticket** | `GET/PATCH /findings` |
| **Frameworks** | Framework-by-framework readiness and control coverage | `/catalog/frameworks` |
| **Audits** | Active/historical audit engagements — evidence requests, reviewer progress | `/audits*` (full CRUD + `/audits/{id}/export`) |
| **Reports** | One-click exports: PDF audit pack, CSV, and three OSCAL documents | `/reports/pdf`, `/reports/csv`, `/reports/oscal`, `/reports/oscal-poam`, `/reports/oscal-components` |
| **As-of / Timeline** | Reconstruct posture at any past date, or trace one control's full status-transition history | `/v1/posture/as-of`, `/v1/posture/timeline` |

### Compliance as Code

| Screen | What it shows | Reads from |
|---|---|---|
| **Policies** | The policy-as-code library (Rego). "Insert PDF" extracts a draft policy from an uploaded document | `/policies`, `/policies/import` |
| **Enforcement** | Shadow-first Zero-Trust: PEPs in front of legacy systems, asking the same OPA/Rego a `GET`/`POST` allow-or-deny per request. Promote a system from shadow → enforce once its would-block stream is clean | `/enforcement/status`, `/enforcement/systems`, `/enforcement/decisions` |
| **Agent Log** | The append-only, hash-chained log of every autonomous/assistive agent action, with a chain-integrity indicator that flags tampering | `/v1/agents/actions`, `/v1/agents/actions/verify` |

> **NL → policy authoring is API/CLI-only.** The dashboard's "New policy" button
> doesn't open an editor — it's a pointer to the CLI. To draft a policy from a
> plain-English description, call `POST /policy/draft` directly (or via
> `PolicyAuthoringService`); it stays `pending` until `POST /policy/{id}/approve`.

### Evidence

| Screen | What it shows | Reads from |
|---|---|---|
| **Connectors** | Native connectors (AWS, Okta, GitHub, Jira, SSH Linux, plus the synthetic `DEMO` source). **Add connection** to configure one — you can add several accounts of the same type (e.g. multiple AWS accounts). Each supports Test / Sync | `/connectors*`, `/connectors/instances*` |
| **GRC Platforms** | Inherited attestations from Vanta, Drata, OneTrust, Secureframe — read-only, credential-gated, fails closed without credentials. **Sync now** opens a connecting-window modal with plain-English failure diagnosis on error | `/v1/grc-sync/*` |
| **Knowledge Graph** | Evidence↔control↔framework relationships | *Illustrative only outside demo mode* — the dashboard itself says so; a real per-tenant graph exists at `GET /evidence/graph` for a future version of this view |
| **Evidence** | The hash-sealed evidence ledger, with an integrity re-verify action | `/evidence`, `/evidence/verify` |
| **Standards Ingest** | Paste an OCSF, SARIF, CycloneDX, SPDX, in-toto/SLSA, STIX, or Sigstore document and ingest it directly into findings/posture. **Load example** fills in a working fixture per format | `POST /v1/evidence/ingest?format=…` |

### Intelligence

| Screen | What it shows | Reads from |
|---|---|---|
| **Response** | Open findings ranked by posture-lift per fix effort, with one-click ticket creation | `/findings?limit=200` (derived) |
| **AI Inventory** | Registered AI systems and their governance state (PET catalog scoring) | `/ai-systems`, `/v1/ai-gov/*` |
| **Threat Intel** | CISA KEV (known-exploited vulnerabilities) cross-referenced with your asset inventory | `/v1/threat/kev`, `/v1/threat/summary` |

### Risk & Vendors

| Screen | What it shows | Reads from |
|---|---|---|
| **Risk Register** | Risk entries with full CRUD | `/grc/risks*` |
| **Vendors** | Third-party vendor inventory with full CRUD | `/tprm/vendors*` |
| **Trust Telemetry** | One score per control, fused from five independently-visible lanes (native / inherited / policy / enforcement / follow-through) — never silently merging inherited trust with directly-verified trust | `/v1/grc-trust/unified` |
| **Trust Graph** | Vendor → system → control dependency graph | *Illustrative only outside demo mode*, same caveat as Knowledge Graph |

---

## 5. Common workflows

**Connect a real system and run your first assessment**
1. **Connectors** → **Add connection** → pick AWS / Okta / GitHub / Jira / SSH Linux → label it.
2. Choose where credentials live: **This browser only** (AES-GCM encrypted client-side, sent to the server only for the duration of a sync — never persisted there) or **Server (encrypted)**, which calls `POST /connectors/instances`. You can add multiple connections of the same type (e.g. two AWS accounts). Env-var credentials work too — see `.env.example`.
3. Click **Test** to confirm connectivity, then **Sync**.
4. Results land in **Findings** and roll up into **Overview**. From **Controls**, you can also trigger **Run assessment** on a single control directly.

**Pull in inherited attestations from a GRC platform**
1. **GRC Platforms** → **Sync now** next to Vanta / Drata / OneTrust / Secureframe.
2. The connecting-window modal shows live progress; on failure it names the exact missing credential (e.g. `VANTA_CLIENT_ID`) rather than a bare error code.
3. Inherited results are kept in their own trust lane — check **Trust Telemetry** to see them fused (not merged) with native evidence.

**Ingest a standards-format evidence document**
1. **Standards Ingest** → pick a format → **Load example** (or paste your own document).
2. **Ingest** — the response shows how many records were persisted as findings vs. observed-only (e.g. build provenance and signatures persist as PASS attestations; threat-intel context is observed-only, never an invented verdict).

**Triage a finding**
1. **Findings** → click a row.
2. **Mark resolved**, **Accept risk**, or **Create ticket** from the drawer.

**Answer "were we compliant on March 1st?"**
1. **As-of / Timeline** → set the date/time → **Reconstruct**.
2. Or look up one control's full history with **Control timeline**.

**Verify the agent decision log hasn't been tampered with**
1. **Agent Log** — the *Chain integrity* readout shows **Verified** or **Broken**.
2. A broken chain names which record(s) failed hash verification (`GET /v1/agents/actions/verify`).

**Produce an audit package**
- **Reports** → PDF (board-ready), CSV (flat evidence export), or one of three OSCAL documents (Assessment Results, POA&M, Component Definition).
- For a full engagement with evidence requests and reviewer sign-off, use **Audits** instead — create an engagement, track requests, then **Export**.

**Register and score an AI system**
- **AI Inventory** → the system list reads `/ai-systems`; governance scoring runs through `/v1/ai-gov/*` (PET catalog, per-system risk).

---

## 6. API access

Interactive docs (`/docs`, `/redoc`, `/openapi.json`) are served automatically
outside production, or in production if `EXPOSE_API_DOCS=true` is set —
otherwise they're off by default in production (the full API surface is
sensitive to disclose).

```bash
curl -H "X-API-Key: <your key>" \
  "https://your-instance/summary?tenant_id=default"
```

The dashboard uses a small fraction of the ~150 routes `app/main.py` exposes —
everything in §4's tables plus the full CRUD surface behind Audits, Risk
Register, and Vendors. Two notable API-only capabilities with no dashboard UI
yet:

- **Waivers** (`POST/GET/DELETE /waivers`) — a formal, approver-tracked
  exception record, distinct from a finding's `risk_accepted` lifecycle state.
  No dashboard button creates one yet; use the API.
- **NL policy authoring** (`POST /policy/draft`) — see the callout in §4.

---

## See also

- [`README.md`](README.md) — what Comp-Lens is and why
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — how it's built, mapped against the
  autonomous-GRC standards stack (OSCAL, OCSF, SARIF, CycloneDX, SPDX,
  in-toto/SLSA, STIX, Sigstore) and what's still open
- [`DEPLOY.md`](DEPLOY.md) — deployment specifics
