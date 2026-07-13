"""Unified trust portal: standards crosswalk + YAML-loadable profiles + transparency."""
import os

from app.grc_platforms.base import GRCPlatformConnector, PlatformProfile
from app.grc_platforms.crosswalk import resolve, resolve_best
from app.grc_platforms.loader import load_all_profiles, load_yaml_profiles

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_uni.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


# ── standards crosswalk ──
def test_soc2_exact_mapping():
    m = resolve("SOC2", "CC6.1")
    assert m.control_id == "AC-2" and m.quality == "exact"

def test_iso_mapping():
    assert resolve("ISO27001", "A.8.24").control_id == "SC-28"

def test_resolve_best_declared_framework():
    m, fw = resolve_best("CC6.7", ["SOC2"])
    assert m.control_id == "SC-28" and fw == "SOC2"

def test_resolve_best_inference_downgrades():
    m, fw = resolve_best("A.8.5", [])   # not declared
    assert m.quality == "heuristic"

def test_unknown_ref_returns_none():
    assert resolve("SOC2", "ZZ9.9") is None


# ── YAML-loadable profiles ──
def test_yaml_profile_loaded():
    profs = load_yaml_profiles()
    assert "SECUREFRAME" in profs
    assert profs["SECUREFRAME"].source.startswith("yaml:")

def test_registry_merges_builtin_and_yaml():
    allp = load_all_profiles()
    assert {"VANTA", "DRATA", "ONETRUST", "SECUREFRAME"} <= set(allp.keys())

def test_from_dict_builds_profile():
    p = PlatformProfile.from_dict({
        "platform": "TESTP", "name": "Test", "base_url": "https://x", "auth_method": "api_key",
        "env_vars": ["X_KEY"], "results_path": "/t", "field_test_id": "id",
        "field_status": "s", "field_control_ref": "c", "field_updated": "u",
        "speaks_frameworks": ["SOC2"]})
    assert p.platform == "TESTP" and "SOC2" in p.speaks_frameworks


# ── ingestion via shared crosswalk + transparency ──
def _resp():
    return {"data": [
        {"id": "1", "status": "passed", "control_key": "CC6.1", "name": "MFA",
         "updated_at": "2026-06-20T00:00:00Z", "frameworks": {"SOC2": ["CC6.1"]}},
        {"id": "2", "status": "passed", "control_key": "ZZ9", "name": "custom",
         "updated_at": "2026-06-20T00:00:00Z", "frameworks": {}}]}

def test_ingest_via_shared_crosswalk():
    sf = load_yaml_profiles()["SECUREFRAME"]
    resp = _resp()

    class Fake(GRCPlatformConnector):
        def _authed_get(self, path, cursor=None): return resp

    atts = Fake(sf).bulk_ingest()
    mapped = [a for a in atts if a.external_test_id == "1"][0]
    assert mapped.comp_lens_control_id == "AC-2"
    assert "exact match" in mapped.mapping_reason

def test_unmapped_kept_with_reason():
    sf = load_yaml_profiles()["SECUREFRAME"]
    resp = _resp()

    class Fake(GRCPlatformConnector):
        def _authed_get(self, path, cursor=None): return resp

    atts = Fake(sf).bulk_ingest()
    un = [a for a in atts if a.external_test_id == "2"][0]
    assert un.comp_lens_control_id is None and "unmapped" in un.mapping_reason

def test_telemetry_carries_reason():
    sf = load_yaml_profiles()["SECUREFRAME"]
    resp = _resp()

    class Fake(GRCPlatformConnector):
        def _authed_get(self, path, cursor=None): return resp

    tel = Fake(sf).bulk_ingest()[0].to_telemetry()
    assert tel.get("mapping_reason")

def test_vanta_still_maps_after_migration():
    """Built-in profiles migrated from hardcoded dict to shared crosswalk still work."""
    v = load_all_profiles()["VANTA"]
    resp = {"results": [{"testId": "v1", "outcome": "OK", "controlId": "CC6.1",
            "name": "x", "latestFlipTime": "2026-06-20T00:00:00Z", "frameworks": {}}],
            "pageInfo": {"endCursor": None}}

    class Fake(GRCPlatformConnector):
        def _authed_get(self, path, cursor=None): return resp

    assert Fake(v).bulk_ingest()[0].comp_lens_control_id == "AC-2"
