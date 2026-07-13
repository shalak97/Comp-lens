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


def _systems_config() -> dict:
    """Per-system config from the policy bundle's data.json (empty if absent)."""
    try:
        return json.loads((POLICY_DIR / "data.json").read_text()).get("systems", {})
    except (OSError, ValueError):
        return {}
