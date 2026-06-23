"""Declarative platform profiles. Adding a new GRC platform = adding one of these.

Field paths follow each vendor's documented API. Validate against your own tenant
on first connection — exact paths and statuses vary by API version and product tier.
The control_crosswalk maps each platform's control taxonomy to Comp-Lens control ids;
unmapped controls are still ingested (as "evidenced but unmapped"), never dropped.
"""
from app.grc_platforms.base import PlatformProfile

# A small starter crosswalk. In production this is generated from the framework
# crosswalk (app/frameworks.py) where the platform exposes framework refs.
_SOC2_TO_CL = {
    "CC6.1": "AC-2", "CC6.2": "AC-2", "CC6.3": "AC-3", "CC6.6": "SC-7",
    "CC6.7": "SC-28", "CC7.1": "RA-5", "CC7.2": "SI-4", "CC8.1": "CM-3",
}

VANTA = PlatformProfile(
    platform="VANTA", name="Vanta", base_url="https://api.vanta.com",
    auth_method="oauth2", env_vars=["VANTA_CLIENT_ID", "VANTA_CLIENT_SECRET"],
    results_path="/v1/tests", items_key="results", pagination_key="pageInfo.endCursor",
    field_test_id="testId", field_status="outcome", field_control_ref="controlId",
    field_updated="latestFlipTime", field_title="name", field_frameworks="frameworks",
    status_map={"ok": "pass", "passing": "pass", "failing": "fail",
                "deactivated": "not_applicable", "in_progress": "error"},
    speaks_frameworks=["SOC2", "ISO27001"],
    notes="Vanta /v1/tests returns test outcomes pre-mapped to controls + frameworks.")

DRATA = PlatformProfile(
    platform="DRATA", name="Drata", base_url="https://public-api.drata.com",
    auth_method="api_key", env_vars=["DRATA_API_KEY"],
    results_path="/public/controls", items_key="data", pagination_key="meta.nextCursor",
    field_test_id="id", field_status="checkStatus", field_control_ref="code",
    field_updated="updatedAt", field_title="name", field_frameworks="frameworkTags",
    status_map={"ready": "pass", "passing": "pass", "unhealthy": "fail",
                "failing": "fail", "not_monitored": "not_applicable"},
    speaks_frameworks=["SOC2", "ISO27001"],
    notes="Drata /public/controls returns control readiness + monitor health.")

# OneTrust is privacy/vendor-risk focused — treated as a vendor-risk source, but
# its control-style assessments still ingest here when present.
ONETRUST = PlatformProfile(
    platform="ONETRUST", name="OneTrust", base_url="https://api.onetrust.com",
    auth_method="api_key", env_vars=["ONETRUST_API_KEY", "ONETRUST_BASE_URL"],
    results_path="/api/compliance/v2/assessments", items_key="content",
    pagination_key="page.nextCursor",
    field_test_id="assessmentId", field_status="status", field_control_ref="controlId",
    field_updated="lastUpdated", field_title="name", field_frameworks="frameworks",
    status_map={"completed": "pass", "approved": "pass", "rejected": "fail",
                "in_progress": "error", "not_started": "not_applicable"},
    speaks_frameworks=["SOC2", "ISO27001"],
    notes="OneTrust is privacy/vendor-risk centric; assessments map to controls where present.")

ALL_PROFILES = {"VANTA": VANTA, "DRATA": DRATA, "ONETRUST": ONETRUST}
