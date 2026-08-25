# Comp-Lens on the autonomous-GRC stack

*An architecture review: the Comp-Lens codebase mapped onto the six-layer model of
an autonomous-GRC system — obligation, canonical control, decision, evidence,
assertion, agency — plus the cross-cutting spine everything else hangs from.*

Every file reference below points to a real module in this repository. Ratings —
**Implemented / Partial / Absent** — describe implementation depth *against the
layered model*, not code quality: much of what is marked Partial is well-built and
simply narrow.

---

## Thesis

Comp-Lens is a genuine **L1–L4 implementation** with an unusually strong assertion
layer and cryptographic evidence integrity. It is thinnest exactly where the field
says the frontier is: the **obligation layer (L0)**, **evidence interoperability
(L3)**, and the **cross-cutting spine** that every other layer silently assumes.

The determinism boundary is drawn correctly: models propose, deterministic code
verifies, humans approve. The agent is never the decision point.

| | |
|---|---|
| **Strongest** | **L4 assertion** — lane-separated trust fusion that never merges inherited with directly-verified trust, plus valid OSCAL Assessment Results and an RFC 6962 evidence transparency log. |
| **Weakest** | **The spine** — no bitemporality, no resolvable identifiers, no framework-version pinning, no agent identity: the four properties the model calls load-bearing. |
| **Canonical framework** | NIST 800-53 (`_CANONICAL_FRAMEWORK = "NIST_800_53"`) |

---

## The stack at a glance

```
 L5  Orchestration & agency   ◐ Partial   models propose; deterministic code disposes
        ▲ proposes into
 L4  Assertion                ● Strong     per-control trust as queryable state
        ▲ asserts over
 L3  Evidence                 ◐ Partial    strong internal model, no standard vocabularies
        ▲ feeds
 L2  Decision                 ● Strong     the determinism boundary — two engines
        ▲ evaluates against
 L1  Canonical control        ◐ Partial    one namespace, honest but ungraded crosswalks
        ▲ interprets
 L0  Obligation               ○ Absent     Comp-Lens starts one layer up
 ─────────────────────────────────────────────────────────────────────
 SPINE  bitemporal · identified · versioned control graph   ○ mostly Absent
```

---

## L0 — Obligation: turning law into data · **Absent**

**The layer.** Represent the obligation itself as data — structural markup (Akoma
Ntoso), then deontic rules (LegalRuleML) with *defeasibility*, so a base rule can be
derogated by a later paragraph. The least mature layer in the field.

**In Comp-Lens.** Two real on-ramps sit near this line, but neither represents
obligations:

- `app/services/doc_ingest.py` turns a policy PDF or SOC 2 report into markdown and
  extracts which controls it *evidences* — an evidence on-ramp, not an obligation one.
- The crawler drift signal (`app/services/trust_telemetry.py::_drift_signal`,
  `CrawlResult.status == "changed"`) flags when a regulatory page *changes* — change
  detection, not structured ingestion.

**The gap.** Obligations live as hand-written Python control evaluators.
`app/policy_as_code/obligations.py` is a *dispatcher* — it routes an obligation string
to an operational procedure by substring guess (`"jira" → open_ticket`) — not a deontic
representation. There is no defeasible/derogation model, so an exception that alters a
rule's premises cannot be expressed as data.

---

## L1 — Canonical control: the pivot · **Partial**

**The layer.** Everything hangs off a single canonical control set with typed, scored
crosswalks (NIST IR 8477 set-theory relationship mapping). Get this wrong and no amount
of automation helps.

**In Comp-Lens.** The architecture correctly pivots on one canonical namespace:
`_CANONICAL_FRAMEWORK = "NIST_800_53"` is pinned in the trust fusion so every signal
lane joins in the same namespace. Crosswalks are centralised and — unusually — honest
about confidence: `app/grc_platforms/crosswalk.py` grades each mapping
`exact / partial / heuristic` (→ 0.95 / 0.70 / 0.50) and downgrades a notch when the
source framework had to be inferred.

- `app/grc_platforms/crosswalk.py` — framework-keyed, quality-graded crosswalk registry
- `app/services/crosswalk.py` — concept-lexicon equivalence join
- `app/frameworks.py`, `app/data/frameworks/*.json` — framework catalogs

**The gap — partially closed.** `app/grc_platforms/crosswalk.py` now carries a typed,
scored STRM edge: a NIST IR 8477 `RelationshipType` (equivalent / subset / superset /
intersects / not-related) with a direction, plus a single first-class `confidence` that
propagates downstream and a per-crosswalk source/revision (`CROSSWALK_META`,
`SCHEMA_VERSION`). Confidence is a strict generalisation of the old quality table — every
existing edge keeps its exact legacy value (regression-guarded in
`tests/test_crosswalk_strm.py`). What remains: `app/services/crosswalk.py` still treats
two controls as equivalent whenever they share ≥1 concept in the lexicon — an
overlap-count join with no ground truth, the field's canonical failure mode — and the
framework catalog JSON still carries no version field.

---

## L2 — Decision: executable intent · **Implemented**

**The layer.** The determinism boundary. Everything below enforcement must be
deterministic and replayable; an agent may author a rule but must never be the policy
decision point.

**In Comp-Lens.** Two evaluators, both deterministic and replayable:

- OPA/Rego for declared policies — `main.rego`, `compliance.rego`, `policies/*.yaml`
- `app/policy_as_code/evaluator.py` — a purpose-built AST-allowlist expression DSL with
  quantifiers and a fixed function registry, hardened against ReDoS and sequence-multiply
  DoS, rejecting `__` names, fail-closed (a missing field is `None`, never an error).
  Parses are cached; the same expression parses once ever.

**The gap.** The field names four viable policy languages that are not substitutes;
Comp-Lens effectively runs a fifth (the DSL) alongside Rego — defensible, but surface to
maintain. One seam leaks the determinism: obligation → procedure routing in
`obligations.py::_infer_procedure` is substring inference, a soft heuristic inside an
otherwise crisp layer.

---

## L3 — Evidence: normalised telemetry · **Partial**

**The layer.** The layer the field has genuinely unified — OCSF for events, SARIF for
static analysis, SPDX/CycloneDX for composition, in-toto/SLSA + Sigstore for provenance,
STIX/TAXII for threat intel.

**In Comp-Lens.** A strong internal model with real integrity:

- `app/data/concept_lexicon.json` — a closed-set concept lexicon (100 concepts) is the
  evidence pivot
- `app/services/merkle.py` — an RFC 6962 transparency log with leaf/node domain
  separation (closing second-preimage forgery)
- `app/services/evidence_sign.py` — signs records and fails closed in production
- `app/services/integrity.py` — recomputes `record_hash` to detect metadata or store
  tampering

Every evidence hit already carries a `confidence` — the right primitive.

**The gap — OCSF boundary now in place.** `app/services/ocsf.py` adds the evidence-layer
seam: `from_ocsf()` maps an OCSF event (AWS Security Lake, Datadog, Security Hub, …) to
the internal normalized evidence — a flat telemetry dict, evidenced lexicon concepts, and
control results lifted from OCSF Compliance Findings — and `to_ocsf_compliance_finding()`
renders a Comp-Lens decision back as a standard OCSF Compliance Finding (class 2003). It
is pure and covered by `tests/test_ocsf_adapter.py` (14 cases, incl. a round-trip and a
live guard that every emittable concept exists in the lexicon). `app/services/sarif.py`
adds the static-analysis half: `from_sarif()` maps CodeQL/Semgrep/GitHub-code-scanning
findings to normalized evidence, `sarif_rollup()` produces the `critical_vulnerabilities`
policy field (RA-5), and `to_sarif()` renders Comp-Lens control failures as a SARIF 2.1.0
log uploadable to GitHub code scanning (`tests/test_sarif_adapter.py`, 11 cases).
`app/services/cyclonedx.py` adds SBOM + VEX: `from_cyclonedx()` maps vulnerabilities to
normalized evidence while honouring VEX (`not_affected` / `false_positive` are not counted
as open findings), `sbom_summary()` produces the `critical_vulnerabilities` policy field,
and — the headline — `to_cdx_evidence()` / `component_evidence()` implement the CycloneDX
evidence object (**field + confidence + named identification technique**), so the bare
`confidence` numbers (a crosswalk edge's included) can finally be expressed with a named
technique. That closes the identification-technique gap this section used to flag.

The rest of the vocabulary family now has boundary adapters too, all pure and tested:
`app/services/spdx.py` (the other SBOM standard — inventory + security externalRefs),
`app/services/intoto.py` (in-toto/SLSA build provenance, with a DSSE codec),
`app/services/stix.py` (STIX 2.1 threat intel → `threat_intelligence` /
`malware_protection` concepts), and `app/services/sigstore.py` (signed-attestation +
Rekor transparency metadata — explicitly structural, never a crypto verdict). So L3 now
speaks OCSF, SARIF, CycloneDX, SPDX, in-toto/SLSA, STIX and Sigstore at the seam.

**These boundaries are now wired into the live ingestion path.**
`app/services/standards_ingest.py` normalises a standard document to evidence, *plans*
what to persist (a pure, unit-tested step), and lands it through the same idempotent
`record_external_finding` sink the Security Hub / Prowler ingestion uses — so
standard-format evidence folds into findings, posture, drift and the OSCAL export with no
new write path. OCSF control verdicts are crosswalked into the canonical NIST namespace on
the way in (reusing the L1 STRM crosswalk — e.g. SOC2 `CC6.7` → `SC-28`); vulnerability
findings map to their NIST control (`RA-5`); build provenance (in-toto/SLSA) and
signatures (Sigstore) now persist as PASS attestations against `SR-3` / `SI-7`; only
threat-intel context stays observed-only. `POST /v1/evidence/ingest?format=…` exposes it.
The internal lexicon stays the pivot everything normalises into.

---

## L3.5 — Capability surface: coverage as content · **Implemented**

**The problem.** Every connector used to decide which controls it supported by branching
on `control_id` inside `collect_telemetry`, and every control needed a hand-written
evaluator in `app/policy/engine.py` plus a `CROSSWALK` entry in `app/frameworks.py`.
Adding one control meant three code edits across three files, so coverage scaled with
engineering headcount. It stalled at **10 machine-verifiable controls against a
1,196-control catalog** — 0.8%.

**The inversion.** Connectors no longer know that controls exist.

- `app/connectors/capabilities.py` — a connector declares **probes**: reusable telemetry
  collectors bound to a vendor-neutral *asset type* (`object_storage`, `managed_database`,
  `compute_instance`, `network_ruleset`, `cloud_account`, …), each advertising the
  normalized **signals** it emits. Declarations are class-level data, so a capability
  surface is readable with no credentials present.
- `app/data/control_checks.json` — a control is data: the asset type it applies to, the
  signals it needs, a boolean expression over them, its severity, and its own framework
  crosswalk. It never names a vendor.
- The resolver joins the two, picking the narrowest probe that covers a check's
  requirement so a one-signal control doesn't trigger a wide, expensive probe.

Expressions run through the existing sandboxed evaluator in
`app/policy_as_code/evaluator.py` — no `eval()`, no dunder access — so check content stays
data rather than executable code.

**Why it compounds.** Checks merge into the two registries the platform already reads
(`CONTROL_CATALOG` and `CROSSWALK`), so one JSON entry reaches assessment, coverage, the
audit control list and OSCAL export with no further wiring. Twelve AWS probes emitting 55
signals now satisfy **38 controls**; taking machine-verifiable coverage from 10 to 48.
The same 38 checks required no edit at all when Azure and GCP declared probes — Azure's
three probes immediately satisfied 6 of them and GCP's single probe satisfied 4, two of
which are now verified identically across all three clouds from a single definition.

**Tri-state honesty.** A missing signal returns `NOT_APPLICABLE`, never `FAIL`. "We could
not observe this" and "we observed it and it is wrong" are different claims, and every
cloud call is individually guarded so a missing IAM permission degrades to unobserved
rather than fabricating a finding.

**The guardrail.** `tests/test_capability_surface.py::test_no_orphan_checks` fails the
build if the pack ever declares a control no connector can satisfy — precisely the drift
that let the old `control_bindings.json` reference six connectors that did not exist.
`GET /coverage/automation` and `GET /connectors/capabilities` expose the same metric at
runtime.

## L4 — Assertion: compliance as queryable state · **Implemented (the standout)**

**The layer.** Compliance becomes a queryable, continuously-validated state with
machine-readable evidence and per-control indicators carrying an explicit freshness
guarantee.

**In Comp-Lens.** `app/services/trust_telemetry.py` is a genuine KSI-equivalent: one
score per control fused from five lanes — *native, inherited, policy, enforcement,
follow-through* — each 0–1 and **independently visible**, with weights renormalised over
only the lanes a control actually has. Its stated design goal is the model's exact
principle: *"inherited trust is never silently merged with directly-verified trust."* The
enforcement lane scores from live PEP/PDP counters (shadow vs enforce) — the strongest
evidence a control truly works.

- `app/services/oscal_export.py` — emits valid OSCAL Assessment Results 1.1.2, with
  confidence and signatures on each observation
- `app/audit_models.py` — models the 3PAO engagement (planning → fieldwork → review →
  complete) with an `auto_status` bridge from live posture

**The gap — narrowing.** OSCAL now emits three of seven models: Assessment Results, plus
**POA&M** (`/reports/oscal-poam`) and **Component Definition** (`/reports/oscal-components`)
via the pure builders in `app/services/oscal_poam.py`. Still missing: SSP, catalog, profile,
and a real assessment-plan (the `import-ap` href still dangles), so the package isn't yet
the full *system of record*. On freshness, `app/services/freshness.py` adds the explicit
`next_validation` primitive (cadence → expiry, `is_stale`); wiring it onto stored trust/
posture rows is the remaining step. As it stands the trust score still decays with age but
carries no per-row expiry — decay-by-age is not a freshness *guarantee*, the property that
turns a control status
into a control claim with an expiry.

---

## L5 — Orchestration & agency · **Partial**

**The layer.** Where "autonomous" actually lives — and where most teams get the
boundary wrong.

**In Comp-Lens.** Comp-Lens gets the boundary right:

- `app/services/llm_client.py` — the LLM only proposes concept hits; the caller
  re-verifies every quote and validates every id against the closed-set lexicon, so
  *"a weak model can only reduce recall,"* never inject an ungrounded link. Temperature is
  capped 0–0.1 for reproducibility.
- `app/services/policy_authoring.py` — NL → policy drafting stays `status="pending"` and
  enforces nothing until a human approves.

**The gap — largely closed.** `AgentIdentity` gives every autonomous/assistive actor a
verifiable identity, and `services/agent_audit.py` records each action in an append-only,
**hash-chained** log (`AgentAction`), so "which agent acted under whose authorisation"
(Singapore IMDA, NIST CAISI) is answerable and the trail is tamper-evident —
`verify_chain()` detects any altered or removed entry, exposed at
`GET /v1/agents/actions{,/verify}`. The NL→policy authoring agent now logs every
proposal against that identity. What remains: richer approvals (reasoning trace,
estimated impact, rollback, expiry — today `decide(approve)` is still a bare boolean) and
an MCP layer.

---

## The five failure modes, scored against the code

| Failure mode | Verdict | What the code actually does |
|---|---|---|
| **1. Mapping without ground truth** *(the deepest)* | **Exposed** | Concept-overlap equivalence and quality-graded crosswalks, neither validated against an authoritative source. Partly mitigated by the honest `heuristic` downgrade — but no inter-run agreement or confidence routed to review. |
| **2. Evidence ≠ effectiveness** | **Partial** | The enforcement lane scoring live PEP/PDP traffic is the correct instinct — proof a control blocks real requests. Other lanes are point-in-time and sampled, not full-population. |
| **3. Bitemporality** | **Addressed** | `Posture` keeps the materialized current view, and the new append-only `posture_history` table records every status transition as a valid-time interval; `_upsert_posture` writes them. `app/services/posture_history.py` reconstructs `as_of(date)` and per-control `timeline()`, exposed at `GET /v1/posture/as-of` and `/v1/posture/timeline`. The pure algorithm lives in `bitemporal.py`. |
| **4. Schema & framework drift** | **Partly addressed** | Every stored finding now pins `framework_version` (from `services/framework_versions.py`, e.g. NIST 800-53 → `rev5`), so a later revision can't silently reinterpret past assertions. The crosswalk registry also carries `SCHEMA_VERSION`/`CROSSWALK_META`. What's left: versioning the framework catalog JSON itself. |
| **5. Goodhart on indicators** | **Partial** | Keeping all five lanes individually visible is the right defence against gaming a single number, and failures route to obligations. But the composite is still a proxy, and control failures do not yet feed risk scenarios. |

---

## Highest-leverage next build: the spine

The model's own conclusion — a **typed, versioned, bitemporal control graph with
confidence propagation** — is precisely the layer Comp-Lens is missing, and each piece
slots into an existing seam rather than a rewrite.

1. **Add a valid-time / system-time axis to stored posture.** Give `Posture`,
   `ControlAttestation` and `EvidenceMeta` bitemporal columns and stop the in-place
   `updated_at` overwrite. This alone unlocks "as-of" reconstruction and closes failure
   mode #3.
2. **Promote crosswalk `quality` to a typed, scored STRM edge.** *(Done —
   `app/grc_platforms/crosswalk.py`.)* Each edge carries a NIST IR 8477 relationship type
   and direction plus a numeric strength; the same edge schema generalises beyond
   crosswalks to the whole graph.
3. **Make one `confidence` field propagate end-to-end.** *(Started — the crosswalk now
   emits a single first-class `confidence`, consumed by the connector base.)* Confidence
   also exists at the hit, the draft and the trust lane as local notions; thread the one
   number the rest of the way, evidence → control → framework → compliance claim.
4. **Pin the framework version on every assertion, and give controls resolvable URIs.**
   Closes failure mode #4 and replaces bare tenant-scoped control strings with stable
   identifiers — the identifier discipline the model calls "the whole ballgame."
5. **Give agents identity, an append-only decision log, and richer approvals.** Distinct
   from evidence integrity: a verifiable agent identity, a tamper-evident record of agent
   actions, and an approval object carrying reasoning, impact, rollback and an *expiry* —
   plus a `next_validation` on trust so a claim ships with a freshness guarantee.

---

*Grounded by reading the source on branch `claude/git-access-gjnzah`. Verdicts reflect
the code as it stands, not roadmap intent.*
