# Is the UI showing what it needs to?

An audit of `app/static/dashboard.html` (3,437 lines, 24 views) against the
166 distinct operations the FastAPI app exposes.

**Answer in one line: 60 of 166 operations are wired into the dashboard.** Most
of the other 106 do not need a UI — but about 40 of them are product features a
user cannot reach at all, and five places in the UI *promise* a capability it
does not provide.

---

## How this was measured

Static path-matching was not trusted, because it is wrong in both directions
here: the dashboard builds paths by concatenation (`"/connectors/" + key +
"/test"`), and it also *mentions* endpoints in prose that it never calls
(`/evidence/graph` appears only inside an empty-state paragraph). A regex counts
the first as missing and the second as present.

So the reachable set is the union of two independently-built lists that are
checked against each other:

1. **Dynamic.** `dashboard.html` is loaded in headless Chromium with `fetch`
   replaced by a recorder that answers with a proxy behaving like both an empty
   array and an any-property object, so a view does not die on its first
   `.filter()` and stop before its second wave of requests. Every
   `RENDER.<view>()` is then invoked. **24 of 24 views ran to completion**; they
   made 28 distinct requests.
2. **Manual.** Every `api` / `apiGET` / `apiPOST` / `apiPATCH` call site and
   every `<a href>` download link, read out of the file with the line number
   each was found on (58 entries).

The script refuses to report if anything the browser actually requested is
missing from the manual list. It is not missing anything.

Reproduce: `python tools/ui_coverage.py` (add `--static` to skip the browser and
use the manual list alone — it says so in its output when you do).

**Limit of the method:** a path built entirely from runtime values with no
literal fragment would be invisible to both halves. None was found, but that is
the blind spot.

---

## 1. Defects — the UI says something that is not true

These are not coverage gaps. They are places where the interface makes a claim
the system does not honour.

### 1.1 "Insert PDF" in the Policies view reports success and does nothing

`dashboard.html:2407-2419`. The handler reads the chosen file, then sends:

```js
apiPOST(withTenant("/policies/import"), {name: f.name})
  .then(()=>{toast('Imported "'+f.name+'" as a draft policy','pass'); render();})
```

The file's **contents are never read**. The backend (`main.py:843`) takes the
body's optional `yaml` key; with only a `name` it returns

```json
{"imported": true, "name": "x.pdf",
 "note": "acknowledged; supply 'yaml' to validate and load a policy"}
```

The UI discards the `note`, shows **`Imported "x.pdf" as a draft policy`**, and
re-renders a list that is unchanged. Nothing is stored, nothing is extracted,
and no row appears.

It is worse than a no-op because of the asymmetry with demo mode: in demo the
same click *does* insert a visible draft row (`PDF_POLICIES.unshift(...)`), so
the feature demonstrates correctly and fails silently in production.

`POST /v1/documents/upload` exists and does exactly what the button promises —
takes `{filename, content_base64}`, extracts text from the PDF, and returns the
controls the document asserts. It is never called from anywhere.

The stale comment above the handler says *"Wiring a POST /policies/import
endpoint would persist them server-side and run extraction"* — the endpoint was
wired, but to a body that carries no document.

### 1.2 The Audits empty state tells you to do something you cannot do

`dashboard.html:2771`:

> "No audit engagements yet — Create one to start tracking evidence requests and
> auditor readiness."

There is no create action. The full action vocabulary of the dashboard is 62
names (`ACTION_NAMES`); none of them creates an audit. `POST /audits`
(`main.py:1751`) exists and is unreachable.

### 1.3 "Multi-source agreement" links to a placeholder

The GRC-platforms view closes with:

> "Inherited attestations are … cross-checked in **multi-source agreement**"

where the link is `act("navigate","trustgraph")`. In live mode the Trust Graph
view renders:

> "Illustrative view — demo only for now. This vendor/system/control graph is a
> fixed illustrative diagram; it isn't yet wired to a live per-tenant graph."

`GET /v1/grc-sync/multi-source` — *"Controls attested by multiple independent
sources — agreement vs conflict"* — is the real thing and is never called.

### 1.4 Risk and vendor readout tiles are computed from one page

`RENDER.risks` (`dashboard.html:1502`) loads `/grc/risks` with no `limit`, so it
gets the server default of **100** rows (`app/pagination.py:47`), then computes
*Open risks*, *High exposure*, *Accepted*, *Avg score* and the entire 5×5 heat
map from those rows. `RENDER.vendors` does the same. Above 100 records every one
of those numbers is wrong.

The dashboard does warn that the *list* was truncated (`notePage` /
`renderPageBanner`), which is good — but the tiles still read as totals.
`GET /grc/risks/summary` and `GET /tprm/vendors/summary` exist precisely to give
the true figures and are never called.

### 1.5 A second console exists that nothing links to

`app/static/evidence-map.html` (29 KB, *"Comp-Lens — Evidence Mindmap"*) is
served at `GET /evidence-map` and is covered by `tests/test_csp.py`. The string
`evidence-map` appears **zero** times in `dashboard.html`. It is reachable only
by typing the URL.

Likewise `/static/grc-sync-preview.html` and `/static/grc-sync-modal.js` are
served by the `/static` mount and referenced by nothing.

---

## 2. Two features the UI describes but never built

These are the sharpest gaps, because the dashboard ships **demo fixtures for
panels that do not exist** — someone wrote the data and stopped.

Of the 15 keys in the demo dataset `D`, three are never read by any view:
`D.inventory` (a stale duplicate of `D.aisystems`), and:

### 2.1 Waivers — `D.waivers` at `dashboard.html:703`

```js
waivers:[
  {control_id:"CP-9", reason:"Legacy mainframe — backup via offline tape…",
   approver:"CISO", expires_at:…, status:"active"}, …]
```

The word "waiver" appears exactly twice in the whole dashboard: that fixture,
and the Reports view's audit-pack contents list (`dashboard.html:1586`):

> **Waivers** — Active exceptions with approver and expiry, **excluded from the
> failing count**

So the UI tells the user that exceptions exist and that they change the failing
count, and gives no way to see, create, or revoke one. The backend has the whole
lifecycle: `POST /waivers` (gated on `Permission.APPROVE`), `GET /waivers`,
`DELETE /waivers/{id}`.

For a compliance product this is the second-most-used object after the finding —
"we accept this one, here is who approved it and when it expires" is the core
exception workflow.

### 2.2 Schedules — `D.schedules` at `dashboard.html:725`

```js
schedules:[{connector:"AWS", cadence:"every 6h", next_run:"in 2h 10m", enabled:true}, …]
```

And in the Add Connection dialog (`dashboard.html:2226`), choosing server-side
credential storage explains:

> "Credentials are encrypted at rest (Fernet) and stored on the server **for
> scheduled syncs**."

There is no way to create a schedule, see one, run one, or delete one. The
backend has `POST /schedules`, `GET /schedules`,
`POST /schedules/{id}/run`, `DELETE /schedules/{id}`.

Continuous monitoring is the difference between a compliance snapshot and a
compliance platform, and it is the reason the user was asked to hand over
credentials.

---

## 3. Everything else, by whether it needs a UI

### 3a. Correctly absent — machine surfaces (9)

No UI warranted; these are scraped, pulled, or pushed by other software.

| | |
|---|---|
| `GET /metrics` | Prometheus exposition |
| `GET /health/ready`, `GET /healthz` | probes (`/health/live` *is* used, by the connection chip) |
| `GET /enforcement/bundles/complens.tar.gz` | OPA bundle the enforcement agent pulls |
| `POST /enforcement/logs` | decision logs the agent pushes |
| `POST /ingest/report`, `POST /ingest/securityhub` | CI pushes Prowler / SecurityHub output |
| `POST /trends/snapshot` | cron |
| `POST /v1/policy/reload` | ops / CLI |

### 3b. Server-side equivalents of something the UI recomputes (8)

Works today, but see §1.4 — the client is re-implementing server logic on a
truncated page.

`GET /grc/risks/summary` · `GET /tprm/vendors/summary` ·
`GET /v1/grc-trust/{score,controls,platforms,policy}` (subsumed by
`/v1/grc-trust/unified`, which the UI does use) · `GET /frameworks` (duplicate of
`/catalog/frameworks`) · `GET /connectors/{name}`

### 3c. Genuine capability gaps (≈40)

Ordered by how much a GRC user would miss them.

| Capability | Operations with no UI | Why it matters |
|---|---|---|
| **Waivers** | `POST/GET /waivers`, `DELETE /waivers/{id}` | §2.1 — the exception workflow, promised in the Reports copy |
| **Schedules** | `POST/GET /schedules`, `POST /schedules/{id}/run`, `DELETE /schedules/{id}` | §2.2 — continuous monitoring, promised in the credentials copy |
| **Audit workspace** | 10 ops: `POST /audits`, `GET/PATCH/DELETE /audits/{id}`, `GET/POST /audits/{id}/requests`, `PATCH/DELETE /audits/requests/{id}`, `GET /audits/{id}/controls`, `PATCH /audits/controls/{id}` | The view shows *counts* of evidence requests; you cannot open, add, or answer one. Only list + refresh-posture + export are wired |
| **Manual attestations** | `POST/GET /attestations`, `GET /coverage`, `GET /catalog/families` | The resolver routes controls with no telemetry to an "attestation floor" — and nothing can record one |
| **Evidence integrity (audit-grade)** | `GET /evidence/verify` (bulk), `POST /evidence/anchor`, `GET /evidence/anchors`, `GET /evidence/proof` | The UI re-hashes one record at a time (`reverifyEvidence`). Merkle anchoring and inclusion proofs — the part an auditor actually wants — are unreachable |
| **Register writes** | `POST /grc/risks`, `DELETE /grc/risks/{id}`, `POST /tprm/vendors`, `DELETE /tprm/vendors/{id}`, `POST /ai-systems` | You cannot add a risk, a vendor, or an AI system. Only `PATCH` (treatment, review date) is wired — the registers are read-mostly |
| **Document → control extraction** | `POST /v1/documents/{upload,ingest,extract}` | §1.1 — the endpoints the PDF button should be calling |
| **Policy drafting & approval** | `POST /policy/draft`, `GET /policy/drafts`, `POST /policy/{id}/approve` | "New policy" is a toast saying to use the CLI, while a draft/approve API exists |
| **Control simulation** | `POST /simulate`, `GET /controls/{id}/{dependencies,fragility,remediation}`, `POST /remediation/plan` | "What else breaks if this control fails" — a differentiator with no surface |
| **Evidence graph** | 10 ops incl. `GET /evidence/graph`, `/documents`, `/lexicon`, `/crosswalk`, `/compliance`, `/export/oscal`, `POST /evidence/hits/{id}/confirm` | The Graph view says so itself, in live mode, and names the endpoint |
| **AI governance (PETs)** | 5 ops under `/v1/ai-gov/` | Inventory lists AI systems; privacy-risk scoring and PET assessment are unreachable |
| **Drift & forecast** | `GET /drift`, `GET /forecast` | "What changed" and "where is this heading" — both belong on Overview |
| **Asset inventory** | `GET /inventory`, `POST /inventory/discover` | No view. Note the nav item named "Inventory" is the *AI-systems* register, so the name is already taken |
| **Ontology / resolver** | `GET /ontology/{planes,bindings}`, `POST /resolve`, `GET /resolve/decisions` | The decision log answering "why was this control assessed this way", including what was skipped and why |
| **Trust & threat reads** | `GET /trust/graph`, `GET /trust/risk-telemetry`, `GET /v1/threat/summary`, `POST /v1/threat/enrich` | Threat view shows the raw KEV list but not the posture summary |
| **Multi-source agreement** | `GET /v1/grc-sync/multi-source`, `GET /v1/grc-sync/profiles` | §1.3 |
| **Batch & pipeline** | `POST /assessment-jobs`, `POST /assessments/bulk`, `POST /v1/integrate/{run,policy-to-findings,ai-to-risk,threat-escalation}`, `GET /remediation`, `GET /v1/policy/{list,test}`, `POST /v1/policy/evaluate-all`, `GET /connectors/safety`, `GET /connectors/{name}/{evidence,sync}`, `GET /evidence/by-connector/{name}`, `GET /legacy/sources`, `GET /crosswalk`, `GET /v1/scf/crosswalk` | Lower priority; most have a partial equivalent already on screen |

---

## 4. What the views do show, and where they stop

All 24 nav entries resolve to a real `RENDER` function — there are no dead nav
items. Three of them, however, are thinner than the nav implies:

| View | Requests it makes | Note |
|---|---|---|
| Knowledge graph | **none** | Fixed illustrative diagram; live mode shows an honest "not wired yet" panel |
| Trust graph | **none** | Same, and §1.3 links to it as if it were live |
| Reports | none (5 `<a href>` downloads) | Correct — these are file downloads, not fetches |
| Posture as-of | none until you press a button | Correct — `/v1/posture/as-of` and `/timeline` fire on submit |
| Standards Ingest | none until you press a button | Correct — `POST /v1/evidence/ingest` on submit |

---

## 5. Suggested order

Ranked by (user impact) ÷ (work), assuming the goal is an honest interface
rather than a complete one:

1. **§1.1** — either send the PDF to `/v1/documents/upload`, or stop claiming
   the import succeeded. A silent success is worse than a disabled button.
2. **§1.2** — add a create-audit form, or reword the empty state.
3. **§1.4** — two extra calls to the `…/summary` endpoints that already exist.
4. **§2.1 Waivers** — one list view + create/revoke. The demo fixture already
   describes the shape.
5. **§2.2 Schedules** — one panel inside the Connectors view. Same.
6. **§1.3** — point the link at a view backed by `/v1/grc-sync/multi-source`.
7. **§1.5** — link `evidence-map.html` from the nav, or note in the README that
   it is a standalone page.
8. Register writes (create risk / vendor / AI system), then the audit workspace.
