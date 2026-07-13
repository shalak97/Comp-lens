"""API authentication AND tenant authorization.

API keys are scoped to the tenants they may access. This closes the gap where
any valid key could read/write any tenant.

Config (env var COMP_LENS_API_KEYS), entries separated by ';':
    key1:tenantA,tenantB ; key2:* ; key3:tenantC
  - `*` grants access to all tenants (admin key)
  - a key with no `:` is treated as admin (`*`) for backward compatibility,
    with a warning logged.

If COMP_LENS_API_KEYS is empty, auth is OFF (local dev) and every request is
treated as an all-tenant admin.

Generate a key:  python -c "import secrets; print(secrets.token_urlsafe(32))"
"""

from __future__ import annotations

import hmac
import logging
import os
from dataclasses import dataclass

from fastapi import Header, HTTPException, status

logger = logging.getLogger(__name__)

ALL = "*"


@dataclass
class Principal:
    key_id: str          # masked key id for logging
    tenants: set[str]    # set of allowed tenant ids, or {"*"}

    @property
    def is_admin(self) -> bool:
        return ALL in self.tenants

    def can_access(self, tenant_id: str) -> bool:
        return self.is_admin or tenant_id in self.tenants


def _parse_keys() -> dict[str, set[str]]:
    raw = os.getenv("COMP_LENS_API_KEYS", "")
    mapping: dict[str, set[str]] = {}
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            key, tenants = entry.split(":", 1)
            tset = {t.strip() for t in tenants.split(",") if t.strip()}
            mapping[key.strip()] = tset or {ALL}
        else:
            logger.warning("API key configured without tenant scope; treating as admin.")
            mapping[entry] = {ALL}
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
        return Principal(key_id="anonymous", tenants={ALL})

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    for key, tenants in keys.items():
        if hmac.compare_digest(x_api_key, key):
            return Principal(key_id=_mask(key), tenants=tenants)

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API key.")


def authorize_tenant(principal: Principal, tenant_id: str) -> None:
    """Raise 403 if the principal may not act on this tenant."""
    if not principal.can_access(tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key is not authorized for this tenant.",
        )
