"""What this deployment has actually been given, and what it still needs.

Someone who has just cloned the repo and run it has a working dashboard full of
demo data and no idea what is real. The information that would tell them is
spread across a .env file they may not have opened, a connector catalog, a
kill-switch, and two startup preflights whose output scrolled past in a
container log.

This gathers it into one answer: for each thing the platform can be connected
to, is it configured, what would configure it, and what is the consequence of
leaving it alone.

**No secret ever leaves this module.** Every credential is reported as a
boolean — set or not set — keyed by the environment variable's NAME. That is
deliberate and load-bearing: the report is useful precisely because it can be
read by whoever is doing the setup, and it stops being safe to show the moment
it carries a value. Tests assert it.

The honesty rule the rest of the codebase follows applies here too: where this
cannot determine something, it says so rather than guessing. An unreachable
database is reported as unreachable, not as "not configured".
"""
from __future__ import annotations

import os
from typing import Any

from app import db_url, storecheck
from app.config import settings

#: Item states, in the order the UI should sort them.
BLOCKED = "blocked"    # nothing works until this is dealt with
ATTENTION = "attention"  # works, but not the way the operator probably assumes
READY = "ready"
OPTIONAL = "optional"   # not configured, and that is a legitimate choice

_ORDER = {BLOCKED: 0, ATTENTION: 1, OPTIONAL: 2, READY: 3}


def _item(key: str, title: str, state: str, detail: str,
          fix: str = "", env: dict[str, bool] | None = None,
          **extra: Any) -> dict[str, Any]:
    return {"key": key, "title": title, "state": state, "detail": detail,
            "fix": fix, "env": env or {}, **extra}


def _is_set(name: str) -> bool:
    """True if an environment variable carries a non-empty value.

    Reads os.environ rather than settings so that connector variables the
    Settings model does not model (there are many) are still reportable.
    """
    return bool((os.environ.get(name) or "").strip())


# ── the platform's own plumbing ──
def _database() -> dict[str, Any]:
    ins = db_url.inspect(settings.database_url, production=settings.is_production)
    if not ins.ok:
        return _item("database", "Database", BLOCKED,
                     "; ".join(ins.errors),
                     "Set DATABASE_URL to a PostgreSQL you control — see DEPLOY.md.",
                     {"DATABASE_URL": bool(settings.database_url)})
    if ins.is_sqlite:
        return _item("database", "Database", ATTENTION,
                     "Running on SQLite — fine for a local try, but it is a single "
                     "file with one writer and no concurrent access.",
                     "Set DATABASE_URL to PostgreSQL before this holds anything "
                     "you would miss.",
                     {"DATABASE_URL": True}, engine="sqlite")
    return _item("database", "Database", READY,
                 f"PostgreSQL at {ins.host}." + (" " + ins.warnings[0] if ins.warnings else ""),
                 "", {"DATABASE_URL": True}, engine="postgresql")


def _evidence() -> dict[str, Any]:
    backend = (settings.evidence_backend or "local").lower()
    if backend == "s3":
        if not settings.evidence_s3_bucket:
            return _item("evidence", "Evidence storage", BLOCKED,
                         "EVIDENCE_BACKEND is s3 but no bucket is set — the app "
                         "refuses to start in this state.",
                         "Set EVIDENCE_S3_BUCKET, or set EVIDENCE_BACKEND back to 'local'.",
                         {"EVIDENCE_S3_BUCKET": False})
        where = settings.evidence_s3_endpoint or "AWS S3"
        return _item("evidence", "Evidence storage", READY,
                     f"Object storage: {settings.evidence_s3_bucket} via {where}. "
                     "Artifacts survive restarts and deploys.",
                     "", {"EVIDENCE_S3_BUCKET": True,
                          "EVIDENCE_S3_ENDPOINT": bool(settings.evidence_s3_endpoint),
                          "AWS_ACCESS_KEY_ID": _is_set("AWS_ACCESS_KEY_ID"),
                          "AWS_SECRET_ACCESS_KEY": _is_set("AWS_SECRET_ACCESS_KEY")},
                     durable=True)

    path = settings.evidence_local_path
    ok, message = storecheck.check_local_store(path)
    if not ok:
        return _item("evidence", "Evidence storage", BLOCKED, message,
                     "Fix the permissions on that path, or point "
                     "EVIDENCE_LOCAL_PATH somewhere writable.",
                     {"EVIDENCE_LOCAL_PATH": True}, durable=False)

    ephemeral = path.startswith("/tmp")
    if ephemeral:
        return _item("evidence", "Evidence storage", ATTENTION,
                     f"Local files under {path}, which most hosts wipe on "
                     "restart. Findings and posture live in the database and are "
                     "unaffected; what is lost on each deploy is the stored "
                     "artifact behind each one.",
                     "For durability at no cost, point EVIDENCE_BACKEND=s3 at any "
                     "S3-compatible store with a free tier (Cloudflare R2, "
                     "Backblaze B2) using EVIDENCE_S3_ENDPOINT.",
                     {"EVIDENCE_LOCAL_PATH": True}, durable=False)
    return _item("evidence", "Evidence storage", READY,
                 f"Local files under {path}.", "",
                 {"EVIDENCE_LOCAL_PATH": True}, durable=True)


def _auth() -> dict[str, Any]:
    configured = _is_set("COMP_LENS_API_KEYS")
    if configured:
        return _item("auth", "API authentication", READY,
                     "API keys are configured; requests are authenticated and "
                     "scoped to a tenant.", "", {"COMP_LENS_API_KEYS": True})
    state = BLOCKED if settings.is_production else ATTENTION
    return _item("auth", "API authentication", state,
                 "No API keys set — every endpoint is open to anyone who can "
                 "reach this service. Fine behind a VPN or on a laptop; not "
                 "fine on a public address.",
                 'Set COMP_LENS_API_KEYS, e.g. "somekey:*" for full access or '
                 '"somekey:tenant-a" to scope it.',
                 {"COMP_LENS_API_KEYS": False})


def _evidence_signing() -> dict[str, Any]:
    if _is_set("EVIDENCE_SIGNING_KEY"):
        return _item("signing", "Evidence signing", READY,
                     "Stored evidence is signed, so tampering is detectable.",
                     "", {"EVIDENCE_SIGNING_KEY": True})
    return _item("signing", "Evidence signing", ATTENTION,
                 "No signing key — evidence is stored without the HMAC that "
                 "makes later modification detectable.",
                 "Set EVIDENCE_SIGNING_KEY to a random 32+ character secret. "
                 "Changing it later invalidates existing signatures.",
                 {"EVIDENCE_SIGNING_KEY": False})


# ── the things you connect ──
def connectors() -> list[dict[str, Any]]:
    """Every connector with a real implementation, and what it still needs."""
    from app.connectors import catalog as ccat
    from app.connectors import safety as _safety

    state = _safety.safety_state()
    allowlist = {a.upper() for a in state.get("allowlist", [])}
    live_enabled = bool(state.get("live_enabled"))

    # One implementation backs several catalog entries — AWS_IAM, AWS_CONFIG
    # and AWS_SECURITY_HUB all resolve to the AWS connector — and they do NOT
    # declare the same variables: AWS_IAM needs two, AWS_CONFIG also needs
    # AWS_REGION. Reporting the first entry found would understate what the
    # connector actually needs and call it configured one variable early. So
    # the requirement is the UNION across every entry that shares the
    # implementation.
    grouped: dict[str, dict[str, Any]] = {}
    for entry in ccat.CONNECTOR_CATALOG:
        registry_key = entry.get("registry_key")
        if not registry_key:
            continue
        g = grouped.setdefault(registry_key, {"entry": entry, "env_vars": set()})
        g["env_vars"].update(entry.get("env_vars", []))

    out: list[dict[str, Any]] = []
    for registry_key, group in grouped.items():
        entry = group["entry"]
        env = {name: _is_set(name) for name in sorted(group["env_vars"])}
        have_all = bool(env) and all(env.values())
        allowed = registry_key.upper() in allowlist and live_enabled

        if not have_all:
            missing = [n for n, v in env.items() if not v]
            item_state, detail = OPTIONAL, (
                f"Not configured — running on demo data. Missing: "
                f"{', '.join(missing)}.")
            fix = (f"Set {', '.join(missing)} in .env, then add "
                   f"{registry_key} to LIVE_CONNECTORS_ALLOWLIST.")
        elif not allowed:
            item_state, detail = ATTENTION, (
                "Credentials are set, but this connector is not in the live "
                "allowlist, so it still returns demo data. That is the "
                "fail-closed default, not a fault.")
            fix = f"Add {registry_key} to LIVE_CONNECTORS_ALLOWLIST."
        else:
            item_state, detail, fix = READY, "Configured and making live calls.", ""

        out.append(_item(registry_key, entry.get("vendor") or registry_key,
                         item_state, detail, fix, env,
                         category=entry.get("category"),
                         auth_method=entry.get("auth_method"),
                         connector_key=entry["key"]))
    out.sort(key=lambda i: (_ORDER[i["state"]], i["title"].lower()))
    return out


def report() -> dict[str, Any]:
    """The whole picture, ordered so the blocking things are first."""
    core = [_database(), _evidence(), _auth(), _evidence_signing()]
    core.sort(key=lambda i: _ORDER[i["state"]])
    conns = connectors()
    live = [c for c in conns if c["state"] == READY]
    counts: dict[str, int] = {}
    for i in [*core, *conns]:
        counts[i["state"]] = counts.get(i["state"], 0) + 1
    return {
        "environment": settings.app_env,
        "platform": core,
        "connectors": conns,
        "counts": counts,
        "live_connectors": len(live),
        "total_connectors": len(conns),
        # The single sentence someone reads first.
        "summary": _summary(core, conns),
    }


def _summary(core: list[dict], conns: list[dict]) -> str:
    blocked = [i for i in core if i["state"] == BLOCKED]
    if blocked:
        return (f"{len(blocked)} thing(s) must be fixed before this deployment "
                f"works: {', '.join(i['title'] for i in blocked)}.")
    live = [c for c in conns if c["state"] == READY]
    if not live:
        return ("Running entirely on demo data. Nothing here reflects a real "
                "estate until a connector is configured and allowlisted.")
    attention = [i for i in core if i["state"] == ATTENTION]
    tail = (f" {len(attention)} setting(s) worth reviewing."
            if attention else "")
    return (f"{len(live)} of {len(conns)} connectors are live; the rest return "
            f"demo data.{tail}")
