"""API authentication, tenant authorization, and role-based access control.

API keys are scoped to the tenants they may access AND to a role that decides
what they may do there. Tenant scoping alone left every valid key able to
mutate anything in its tenants, which made segregation of duties — a control
this product assesses for its customers — unenforceable on the product itself:
there was no way to give an auditor read access to evidence without also
granting them the ability to alter findings and approve their own waivers.

Config (env var COMP_LENS_API_KEYS), entries separated by ';':
    key1:tenantA,tenantB ; key2:* ; key3:tenantC:auditor ; key4:*:admin
  - `*` in the tenant field grants access to all tenants
  - an optional third field names the role; it defaults to `operator`
  - a key with no `:` is treated as an all-tenant admin for backward
    compatibility, with a warning logged.

Roles, narrowest first:
  viewer    read-only; cannot see raw evidence payloads
  auditor   read everything including evidence, attest controls; mutates nothing
  operator  the previous default — run assessments, manage findings/connectors
  admin     everything, including waiver approval and key/tenant administration

If COMP_LENS_API_KEYS is empty, auth is OFF (local dev) and every request is
treated as an all-tenant admin.

Generate a key:  python -c "import secrets; print(secrets.token_urlsafe(32))"
"""

from __future__ import annotations

import enum
import hmac
import logging
import os
from dataclasses import dataclass, field

from fastapi import Header, HTTPException, status

logger = logging.getLogger(__name__)

ALL = "*"


class Permission(enum.StrEnum):
    """What a caller may do, independent of which tenant they may do it in."""

    READ = "read"                 # list/read non-sensitive resources
    READ_EVIDENCE = "read:evidence"   # raw evidence payloads and proofs
    ASSESS = "assess"             # run assessments, sync connectors, ingest
    WRITE = "write"               # mutate findings, risks, audits, schedules
    ATTEST = "attest"             # record a human attestation on a control
    APPROVE = "approve"           # approve/revoke waivers — the SoD boundary
    ADMIN = "admin"               # tenant/key administration, enforcement mode


#: Role -> the permissions it carries. Ordered narrowest to widest.
ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "viewer": frozenset({Permission.READ}),
    "auditor": frozenset({Permission.READ, Permission.READ_EVIDENCE, Permission.ATTEST}),
    "operator": frozenset({
        Permission.READ, Permission.READ_EVIDENCE, Permission.ASSESS,
        Permission.WRITE, Permission.ATTEST,
    }),
    "admin": frozenset(Permission),
}

DEFAULT_ROLE = "operator"


@dataclass
class Principal:
    key_id: str          # masked key id for logging
    tenants: set[str]    # set of allowed tenant ids, or {"*"}
    role: str = DEFAULT_ROLE
    permissions: frozenset[Permission] = field(
        default_factory=lambda: ROLE_PERMISSIONS[DEFAULT_ROLE])

    @property
    def is_admin(self) -> bool:
        """All-tenant reach. Distinct from the admin ROLE, which is about what
        the caller may do rather than where."""
        return ALL in self.tenants

    def can_access(self, tenant_id: str) -> bool:
        return self.is_admin or tenant_id in self.tenants

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions


def _parse_keys() -> dict[str, tuple[set[str], str]]:
    """key -> (allowed tenants, role). Format: `key:tenants[:role]`."""
    raw = os.getenv("COMP_LENS_API_KEYS", "")
    mapping: dict[str, tuple[set[str], str]] = {}
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            logger.warning("API key configured without tenant scope; treating as admin.")
            mapping[entry] = ({ALL}, "admin")
            continue
        parts = entry.split(":")
        key = parts[0].strip()
        tset = {t.strip() for t in parts[1].split(",") if t.strip()}

        # A key with no explicit role keeps exactly the reach it had before
        # roles existed: an all-tenant (`*`) key was the admin key, and a
        # tenant-scoped key could do everything within its tenants but nothing
        # administrative. Defaulting `*` to operator would silently strip admin
        # from every existing deployment's admin key.
        default_role = "admin" if tset == {ALL} or not tset else DEFAULT_ROLE
        role = (parts[2].strip().lower() if len(parts) > 2 and parts[2].strip()
                else default_role)
        if role not in ROLE_PERMISSIONS:
            # Fail closed on a typo: a misspelled role must not silently widen
            # access, and must not silently grant the default either.
            logger.error("API key %s names unknown role %r; granting viewer only.",
                         _mask(key), role)
            role = "viewer"
        mapping[key] = (tset or {ALL}, role)
    return mapping


def auth_enabled() -> bool:
    return len(_parse_keys()) > 0


def _mask(key: str) -> str:
    return key[:4] + "\u2026" + key[-2:] if len(key) > 6 else "key"


def require_principal(x_api_key: str | None = Header(default=None)) -> Principal:
    """FastAPI dependency. Returns the caller's Principal.

    When auth is disabled (no keys configured), returns an admin principal so
    local dev and the DEMO flow keep working.
    """
    keys = _parse_keys()
    if not keys:
        # Fail closed in production: never hand out an admin principal when auth
        # is unconfigured. In non-production this is the local-dev admin path.
        from app.config import settings
        if settings.is_production:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Server authentication is not configured.")
        return Principal(key_id="anonymous", tenants={ALL}, role="admin",
                         permissions=ROLE_PERMISSIONS["admin"])

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    for key, (tenants, role) in keys.items():
        if hmac.compare_digest(x_api_key, key):
            return Principal(key_id=_mask(key), tenants=tenants, role=role,
                             permissions=ROLE_PERMISSIONS[role])

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API key.")


def authorize_tenant(principal: Principal, tenant_id: str) -> None:
    """Raise 403 if the principal may not act on this tenant."""
    if not principal.can_access(tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key is not authorized for this tenant.",
        )


def require(permission: Permission):
    """FastAPI dependency factory enforcing one permission.

    Used as `p: Principal = Depends(require(Permission.WRITE))` so the route
    keeps its Principal while the permission check happens before the handler
    body runs.
    """

    def _dep(x_api_key: str | None = Header(default=None)) -> Principal:
        principal = require_principal(x_api_key)
        authorize_permission(principal, permission)
        return principal

    return _dep


def authorize_permission(principal: Principal, permission: Permission) -> None:
    """Raise 403 if the principal's role does not carry this permission."""
    if not principal.has(permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(f"Role '{principal.role}' is not permitted to "
                    f"{permission.value}."),
        )
