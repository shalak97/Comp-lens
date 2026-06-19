"""External threat intelligence: CISA KEV + EPSS + NVD, mapped to controls.

The honest bridge problem: feeds speak CVEs, compliance speaks controls. There is
no legitimate direct map from an arbitrary CVE to an arbitrary control. So we use
only DEFENSIBLE bridges:

  1. Vulnerability-management controls (RA-5, SI-2, SC-7, CA-7, SI-3) have a genuine
     relationship to "how many vulnerabilities are actively exploited right now."
     A failing RA-5 with 300 actively-exploited KEV CVEs (40 ransomware) is far more
     urgent than a failing RA-5 in a quiet week. That enrichment is real.
  2. Connector findings that carry a CVE id are looked up directly in KEV/EPSS — the
     strongest, most specific signal.

We never claim CVE-X maps to an unrelated control. Threat context is attached only
where the relationship is genuine, and always labelled with its basis.

Feeds (all free):
  - CISA KEV:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - EPSS:      https://api.first.org/data/v1/epss
  - NVD CVE:   https://services.nvd.nist.gov/rest/json/cves/2.0

Network: feeds are fetched live in production (open egress). Results are cached with a
TTL because the catalogs update a few times per week, not in real time — re-fetching
per request would be slow and disrespectful to the source. On a cold/offline start we
fall back to a small seed of real, famous KEV entries so the feature still shows real data.
"""
from __future__ import annotations

import json
import time
import urllib.request
from typing import Any, Dict, List, Optional

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CACHE_TTL = 6 * 3600  # 6 hours — feeds update a few times/week

# Control families with a GENUINE relationship to active exploitation pressure.
VULN_CONTROLS = {
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SI-2": "Flaw Remediation",
    "SI-3": "Malicious Code Protection",
    "SC-7": "Boundary Protection",
    "CA-7": "Continuous Monitoring",
    "RA-3": "Risk Assessment",
}

# A small seed of real, well-known KEV entries — used only as cold-start fallback
# so the feature is never empty even before the first successful live fetch.
_SEED_KEV = [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
     "vulnerabilityName": "Apache Log4j2 Remote Code Execution (Log4Shell)",
     "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2023-34362", "vendorProject": "Progress", "product": "MOVEit Transfer",
     "vulnerabilityName": "Progress MOVEit Transfer SQL Injection",
     "dateAdded": "2023-06-02", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks", "product": "PAN-OS",
     "vulnerabilityName": "PAN-OS Command Injection",
     "dateAdded": "2024-04-12", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2024-6387", "vendorProject": "OpenBSD", "product": "OpenSSH",
     "vulnerabilityName": "OpenSSH Remote Code Execution (regreSSHion)",
     "dateAdded": "2024-07-01", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2022-22965", "vendorProject": "VMware", "product": "Spring Framework",
     "vulnerabilityName": "Spring Framework RCE (Spring4Shell)",
     "dateAdded": "2022-04-04", "knownRansomwareCampaignUse": "Known"},
]

_cache: Dict[str, Any] = {"kev": None, "kev_ts": 0.0, "epss": {}, "source": "none"}


def _fetch_json(url: str, timeout: float = 12.0) -> Optional[Any]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Comp-Lens/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read())
    except Exception:
        return None


# ── CISA KEV ──
def get_kev(force: bool = False) -> Dict[str, Any]:
    """Return the KEV catalog, cached. Falls back to last cache, then seed."""
    now = time.time()
    if not force and _cache["kev"] and (now - _cache["kev_ts"]) < CACHE_TTL:
        return {"vulnerabilities": _cache["kev"], "source": _cache["source"],
                "count": len(_cache["kev"]), "cached": True}
    data = _fetch_json(KEV_URL)
    if data and isinstance(data, dict) and "vulnerabilities" in data:
        vulns = data["vulnerabilities"]
        _cache.update(kev=vulns, kev_ts=now, source="cisa-live")
        return {"vulnerabilities": vulns, "source": "cisa-live",
                "count": len(vulns), "cached": False}
    # fall back to last good cache, then seed
    if _cache["kev"]:
        return {"vulnerabilities": _cache["kev"], "source": _cache["source"],
                "count": len(_cache["kev"]), "cached": True, "stale": True}
    _cache.update(kev=_SEED_KEV, kev_ts=now, source="seed-fallback")
    return {"vulnerabilities": _SEED_KEV, "source": "seed-fallback",
            "count": len(_SEED_KEV), "cached": False,
            "note": "live feed unreachable; showing seed of well-known KEV entries"}


def kev_summary() -> Dict[str, Any]:
    kev = get_kev()
    vulns = kev["vulnerabilities"]
    ransomware = sum(1 for v in vulns
                     if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known")
    # recent additions (by dateAdded, lexical sort works on ISO dates)
    recent = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)[:10]
    return {
        "total_known_exploited": len(vulns),
        "ransomware_linked": ransomware,
        "source": kev["source"],
        "recent": [{"cve": v.get("cveID"), "name": v.get("vulnerabilityName"),
                    "vendor": v.get("vendorProject"), "product": v.get("product"),
                    "date_added": v.get("dateAdded"),
                    "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"}
                   for v in recent],
    }


# ── EPSS (exploit probability) ──
def get_epss(cve_ids: List[str]) -> Dict[str, float]:
    """EPSS scores (0..1) for given CVEs. Cached per-CVE."""
    out: Dict[str, float] = {}
    missing = []
    for c in cve_ids:
        if c in _cache["epss"]:
            out[c] = _cache["epss"][c]
        else:
            missing.append(c)
    if missing:
        q = ",".join(missing[:100])
        data = _fetch_json(f"{EPSS_URL}?cve={q}")
        if data and isinstance(data, dict):
            for row in data.get("data", []):
                cve = row.get("cve")
                try:
                    score = float(row.get("epss", 0))
                except (TypeError, ValueError):
                    score = 0.0
                if cve:
                    _cache["epss"][cve] = score
                    out[cve] = score
    return out


# ── NVD severity (optional, single CVE) ──
def get_nvd_severity(cve_id: str) -> Optional[Dict[str, Any]]:
    data = _fetch_json(f"{NVD_URL}?cveId={cve_id}")
    if not data:
        return None
    try:
        metrics = data["vulnerabilities"][0]["cve"]["metrics"]
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                m = metrics[key][0]["cvssData"]
                return {"cve": cve_id, "base_score": m.get("baseScore"),
                        "severity": m.get("baseSeverity", "")}
    except (KeyError, IndexError):
        pass
    return None


# ── the bridge: enrich controls with real-world exploitation pressure ──
def threat_pressure() -> Dict[str, Any]:
    """Aggregate exploitation pressure from KEV, applied to vuln-mgmt controls."""
    s = kev_summary()
    total = s["total_known_exploited"]
    ransomware = s["ransomware_linked"]
    # a simple, explainable pressure score 0..100
    pressure = min(100, round((total / 20) + ransomware * 0.5))
    return {"exploitation_pressure": pressure,
            "actively_exploited": total, "ransomware_linked": ransomware,
            "basis": "CISA KEV catalog", "source": s["source"]}


def enrich_controls(control_ids: List[str], cve_map: Optional[Dict[str, List[str]]] = None
                    ) -> Dict[str, Dict[str, Any]]:
    """Attach threat context to controls — only where the relationship is genuine.

    cve_map: optional {control_id: [cve_ids]} from connector findings. When present,
    those specific CVEs are looked up in KEV/EPSS (the strongest signal).
    """
    cve_map = cve_map or {}
    kev = get_kev()
    kev_cves = {v.get("cveID"): v for v in kev["vulnerabilities"]}
    pressure = threat_pressure()
    out: Dict[str, Dict[str, Any]] = {}
    # gather all finding CVEs to score EPSS in one call
    all_cves = sorted({c for cves in cve_map.values() for c in cves})
    epss = get_epss(all_cves) if all_cves else {}
    for cid in control_ids:
        ctx: Dict[str, Any] = {}
        base = cid.split("(")[0].strip()
        # bridge 1: vuln-management control → aggregate pressure
        if base in VULN_CONTROLS:
            ctx["exploitation_pressure"] = pressure["exploitation_pressure"]
            ctx["actively_exploited"] = pressure["actively_exploited"]
            ctx["ransomware_linked"] = pressure["ransomware_linked"]
            ctx["basis"] = f"{VULN_CONTROLS[base]} — KEV catalog pressure"
        # bridge 2: specific CVEs from connector findings
        finding_cves = cve_map.get(cid, [])
        if finding_cves:
            exploited = [c for c in finding_cves if c in kev_cves]
            ctx["finding_cves"] = finding_cves
            ctx["kev_exploited_cves"] = exploited
            ctx["max_epss"] = round(max((epss.get(c, 0) for c in finding_cves), default=0), 3)
            if exploited:
                ctx["basis"] = f"{len(exploited)} actively-exploited CVE(s) in findings (CISA KEV)"
        if ctx:
            out[cid] = ctx
    return out
