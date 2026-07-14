"""Connector safety guardrails — three layered controls over live API calls.

Live third-party API calls can cost money and touch real data, so every
outbound path is gated here. By default the system is LOCKED: no connector
reaches a live API regardless of credentials. Operators opt in explicitly.

Layer 1 — global kill-switch
    LIVE_CONNECTORS_ENABLED must be exactly "true" (case-insensitive) to allow
    ANY live call. Unset / anything else => every connector forced to demo.

Layer 2 — per-connector allowlist
    LIVE_CONNECTORS_ALLOWLIST is a comma-separated list of connector keys
    (e.g. "OKTA,GITHUB"). Only listed connectors may go live. Empty list with
    the kill-switch on means "none" (fail-closed), not "all".

Layer 3 — read-only enforcement
    Connector telemetry methods are read calls by design, but this asserts it:
    only methods on an allowlist of safe read verbs may be invoked live. Any
    method whose name implies mutation (create/update/delete/post/...) raises.

Each layer fails closed: when in doubt, demo. Decisions are explained via
`reason` so the UI and logs can show exactly why a connector is or isn't live.
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

KILL_SWITCH_ENV = "LIVE_CONNECTORS_ENABLED"
ALLOWLIST_ENV = "LIVE_CONNECTORS_ALLOWLIST"
SSH_ALLOWED_HOSTS_ENV = "SSH_ALLOWED_HOSTS"
SSH_TRUST_UNKNOWN_ENV = "SSH_TRUST_UNKNOWN_HOSTS"


def ssh_host_allowed(host: str) -> bool:
    """When SSH_ALLOWED_HOSTS is set (comma-separated), only those hosts may be
    connected to — stops a client-supplied target turning the connector into an
    SSH pivot. Unset = allow any (relies on host-key verification below)."""
    raw = os.getenv(SSH_ALLOWED_HOSTS_ENV, "").strip()
    if not raw:
        return True
    allowed = {h.strip().lower() for h in raw.split(",") if h.strip()}
    return (host or "").strip().lower() in allowed


def apply_ssh_host_key_policy(client) -> None:
    """Verify host keys on a paramiko SSHClient. Loads known host keys and
    REJECTS unknown hosts (MITM protection) unless SSH_TRUST_UNKNOWN_HOSTS=true
    is set to explicitly opt back into the old auto-accept behaviour."""
    import paramiko
    for load in (client.load_system_host_keys, client.load_host_keys):
        try:
            if load is client.load_host_keys:
                path = os.path.expanduser("~/.ssh/known_hosts")
                if os.path.exists(path):
                    load(path)
            else:
                load()
        except Exception:  # noqa: BLE001 — missing known_hosts is fine
            pass
    if os.getenv(SSH_TRUST_UNKNOWN_ENV, "false").strip().lower() == "true":
        logger.warning("SSH host-key verification disabled (%s=true) — MITM risk.",
                       SSH_TRUST_UNKNOWN_ENV)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

# method-name prefixes that are NEVER allowed on a live connector instance
_MUTATION_PREFIXES = (
    "create", "update", "delete", "remove", "put", "post", "patch", "write",
    "set", "add", "modify", "disable", "enable", "revoke", "grant", "send",
    "trigger", "execute", "run", "deploy", "provision", "terminate", "reset",
    "rotate", "issue", "approve", "reject", "assign", "upload", "push",
)
# safe read-verb prefixes telemetry collection is allowed to use
_SAFE_READ_PREFIXES = (
    "collect_telemetry", "healthcheck", "get", "list", "fetch", "read",
    "describe", "query", "scan", "search", "check", "status", "retrieve",
)


def kill_switch_on() -> bool:
    """True when live calls are globally permitted."""
    return os.getenv(KILL_SWITCH_ENV, "false").strip().lower() == "true"


def _allowlist() -> set:
    raw = os.getenv(ALLOWLIST_ENV, "")
    return {k.strip().upper() for k in raw.split(",") if k.strip()}


def live_allowed(connector_key: str, auth_method: str | None = None) -> dict[str, Any]:
    """Decide whether `connector_key` may make live calls. Fails closed.

    Synthetic connectors (auth_method == "none") have no external API and are
    always allowed — they call nothing that costs money or touches real data.

    Returns {"allowed": bool, "reason": str} so callers can surface why.
    """
    if auth_method == "none":
        return {"allowed": True, "reason": "synthetic connector (no external API)"}
    if not kill_switch_on():
        return {"allowed": False,
                "reason": f"live calls globally disabled ({KILL_SWITCH_ENV} != true)"}
    allow = _allowlist()
    if not allow:
        return {"allowed": False,
                "reason": f"kill-switch on but {ALLOWLIST_ENV} is empty (fail-closed)"}
    if connector_key.upper() not in allow:
        return {"allowed": False,
                "reason": f"{connector_key} not in {ALLOWLIST_ENV}"}
    return {"allowed": True, "reason": "allowed: kill-switch on + connector allowlisted"}


def assert_read_only(method_name: str) -> None:
    """Raise if a method name implies mutation. Layer 3 enforcement."""
    low = method_name.lower()
    # explicit mutation prefixes are always blocked (checked first)
    for p in _MUTATION_PREFIXES:
        if low.startswith(p):
            raise PermissionError(
                f"blocked non-read connector method '{method_name}' "
                f"(read-only enforcement)")
    # must match a known safe-read prefix; otherwise fail closed
    for p in _SAFE_READ_PREFIXES:
        if low.startswith(p):
            return
    raise PermissionError(
        f"connector method '{method_name}' is not on the safe-read allowlist")


def safety_state() -> dict[str, Any]:
    """Snapshot for the API/UI — never includes secrets."""
    on = kill_switch_on()
    allow = sorted(_allowlist())
    return {
        "live_enabled": on,
        "allowlist": allow,
        "mode": "LIVE" if (on and allow) else "SAFE",
        "summary": ("All connectors locked to demo — no live API calls possible."
                    if not on else
                    (f"Live enabled for: {', '.join(allow)}." if allow else
                     "Kill-switch on but allowlist empty — still no live calls (fail-closed).")),
        "read_only_enforced": True,
    }
