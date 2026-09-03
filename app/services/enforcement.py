"""Enforcement control-plane ingestion core.

The enforcement control plane (see app/app.py) serves the signed policy bundle
to OPA and receives OPA *decision logs*, turning each into a decision record.
This module owns that ingestion core — the in-memory evidence store plus the
per-entry parser — so it is the single source of truth shared by both the
standalone control-plane app and the platform's trust telemetry (which reads
the live PEP/PDP counters to score the `enforcement` lane).

Storage is in-memory (a ring buffer + dicts): decisions and PEP liveness reset
on restart. Swap for the Comp-Lens evidence ledger for durability.
"""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

POLICY_DIR = Path(os.environ.get("COMPLENS_POLICY_DIR", Path(__file__).resolve().parent.parent / "policy"))
MAX_DECISIONS = 5000

# ----------------------------------------------------------------------------
# In-memory evidence store (not durable, not per-tenant — see module docstring)
# ----------------------------------------------------------------------------
DECISIONS: deque = deque(maxlen=MAX_DECISIONS)        # newest appended right
PEPS: dict[str, dict] = {}                            # data-plane node -> liveness
SYS_COUNTERS: dict[str, dict] = defaultdict(lambda: {"requests": 0, "allow": 0,
                                                     "denied": 0, "would_block": 0,
                                                     "last_seen": None})
BOOT = time.time()


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _coerce_bool(v) -> bool:
    return str(v).lower() == "true"


def _ingest_entry(e: dict) -> dict | None:
    """Parse one OPA decision-log entry into a decision record (or None to skip).

    Fully defensive: malformed entries (missing keys, wrong types) are skipped,
    never raised — the decision-log sink must not fail on a single bad entry.
    """
    if e.get("path") not in ("envoy/authz/allow", "envoy/authz"):
        return None
    result = e.get("result") or {}
    if not isinstance(result, dict):
        return None
    h = result.get("headers") or {}
    inp = (((e.get("input") or {}).get("attributes") or {}).get("request") or {}).get("http") or {}
    bundles = e.get("bundles") or {}
    rev = (bundles.get("complens") or {}).get("revision") or ""
    labels = e.get("labels") or {}
    node = labels.get("system") or labels.get("id") or "pdp"

    rec = {
        "ts": e.get("timestamp") or now_iso(),
        "decision_id": e.get("decision_id", ""),
        "system": h.get("x-complens-system") or inp.get("host") or "unknown",
        "method": inp.get("method", ""),
        "path": inp.get("path", ""),
        "subject": h.get("x-complens-subject", "anonymous"),
        "mode": h.get("x-complens-mode", "shadow"),
        "policy": h.get("x-complens-policy", "unconfigured"),
        "enforced_allow": bool(result.get("allowed", True)),
        "would_allow": _coerce_bool(h.get("x-complens-would-allow", "true")),
        "would_block": _coerce_bool(h.get("x-complens-would-block", "false")),
        "reason": h.get("x-complens-reason", ""),
        "revision": rev,
        "node": node,
    }

    # liveness + counters
    p = PEPS.setdefault(node, {"node": node, "first_seen": now_iso(), "decisions": 0})
    p["last_seen"] = now_iso()
    p["revision"] = rev
    p["decisions"] += 1

    c = SYS_COUNTERS[rec["system"]]
    c["requests"] += 1
    c["last_seen"] = rec["ts"]
    if rec["enforced_allow"]:
        c["allow"] += 1
    else:
        c["denied"] += 1
    if rec["would_block"]:
        c["would_block"] += 1

    DECISIONS.append(rec)
    return rec


@lru_cache(maxsize=4)
def _systems_config_at(_stamp: tuple[int, int]) -> dict:
    """The parsed bundle config for one version of data.json.

    Keyed on the file's identity rather than cached outright, because set_mode()
    rewrites this file: an unconditional cache would keep serving shadow after
    an operator switched a system to enforce. A changed mtime or size is a
    different key, so the next read reparses. maxsize bounds the few versions a
    process sees.
    """
    try:
        return json.loads((POLICY_DIR / "data.json").read_text()).get("systems", {})
    except (OSError, ValueError):
        return {}


def _systems_config() -> dict:
    """Per-system config from the policy bundle's data.json (empty if absent).

    Read on every enforcement status call and on every unified-trust request,
    so it is parsed once per version of the file rather than once per call.
    """
    try:
        st = (POLICY_DIR / "data.json").stat()
    except OSError:
        return {}
    return _systems_config_at((st.st_mtime_ns, st.st_size))


def bundle_revision() -> str:
    """Short content hash of the deployed policy bundle ('unversioned' if absent)."""
    try:
        import hashlib
        rego = (POLICY_DIR / "main.rego").read_bytes()
        data = (POLICY_DIR / "data.json").read_bytes()
        return hashlib.sha256(rego + b"\x00" + data).hexdigest()[:12]
    except OSError:
        return "unversioned"


def status_snapshot() -> dict:
    """Fleet + counter summary the dashboard's Enforcement view renders."""
    cfg = _systems_config()
    fail_open = [h for h, c in cfg.items() if c.get("fail") == "open"]
    enforcing = [h for h, c in cfg.items() if c.get("mode") == "enforce"]
    totals = {"allow": 0, "denied": 0, "would_block": 0, "requests": 0}
    for c in SYS_COUNTERS.values():
        for k in totals:
            totals[k] += c.get(k, 0)
    live_cut = time.time() - 120
    peps = []
    for p in PEPS.values():
        last = p.get("last_seen")
        online = False
        if last:
            try:
                online = datetime.fromisoformat(last).timestamp() > live_cut
            except ValueError:
                online = False
        peps.append({**p, "online": online})
    return {
        "control_plane": "ok",
        "uptime_s": int(time.time() - BOOT),
        "bundle_revision": bundle_revision(),
        "pdp_nodes": len(PEPS),
        "peps_online": sum(1 for p in peps if p["online"]),
        "systems_protected": len(cfg),
        "systems_enforcing": len(enforcing),
        "systems_shadow": len(cfg) - len(enforcing),
        "systems_fail_open": fail_open,
        "totals": totals,
        "peps": peps,
    }


def systems_list() -> list[dict]:
    """Per-system config + live counters, enforce-first then noisiest-shadow."""
    cfg = _systems_config()
    out = []
    for host, c in cfg.items():
        ctr = SYS_COUNTERS.get(host, {})
        out.append({
            "system": host,
            "mode": c.get("mode", "shadow"),
            "fail": c.get("fail", "open"),
            "policy_id": c.get("policy_id", "unconfigured"),
            "allowed_roles": c.get("allowed_roles", []),
            "revision": bundle_revision(),
            "requests": ctr.get("requests", 0),
            "allow": ctr.get("allow", 0),
            "denied": ctr.get("denied", 0),
            "would_block": ctr.get("would_block", 0),
            "last_seen": ctr.get("last_seen"),
        })
    out.sort(key=lambda s: (s["mode"] != "enforce", -s["would_block"]))
    return out


def recent_decisions(limit: int = 100) -> list[dict]:
    return list(DECISIONS)[-limit:][::-1]


def set_mode(host: str, mode: str) -> dict:
    """Flip a system between shadow/enforce by rewriting the bundle's data.json.

    Raises ValueError on a bad mode and KeyError on an unknown system.
    """
    if mode not in ("shadow", "enforce"):
        raise ValueError("mode must be 'shadow' or 'enforce'")
    path = POLICY_DIR / "data.json"
    doc = json.loads(path.read_text())
    if host not in doc.get("systems", {}):
        raise KeyError(host)
    doc["systems"][host]["mode"] = mode
    path.write_text(json.dumps(doc, indent=2) + "\n")
    return {"system": host, "mode": mode, "bundle_revision": bundle_revision()}
