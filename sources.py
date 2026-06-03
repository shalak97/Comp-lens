"""Legacy data source registry.

Legacy systems are described once, server-side, as named sources. A request
references a source by NAME plus an asset id — it never supplies a connection
string, query, or file path. This keeps the door closed on SSRF and injection
while still letting one platform talk to many heterogeneous legacy systems.

Config (env LEGACY_SOURCES_JSON inline, or LEGACY_SOURCES_FILE path):

[
  {
    "name": "mainframe-hr",
    "type": "sql",
    "url": "oracle+oracledb://user:pass@host:1521/?service_name=HR",
    "query": "SELECT mfa_flag, last_login FROM users WHERE user_id = :asset_id",
    "discovery_query": "SELECT user_id FROM users",
    "key_column": "user_id",
    "field_map": {
      "mfa_enforced": {"from": "mfa_flag", "coerce": "bool", "truthy": ["Y","1","TRUE"]},
      "days_since_last_login": {"from": "last_login", "coerce": "days_since"},
      "owner": {"from": "dept"}
    }
  },
  { "name": "asset-export", "type": "file", "url": "file:///data/assets.csv",
    "format": "csv", "key_column": "host", "field_map": {"disk_encrypted": {"from":"luks","coerce":"bool"}} },
  { "name": "legacy-soap", "type": "soap", "url": "https://host/ws", "soap_action": "GetUser",
    "template": "<...>{asset_id}</...>", "field_paths": {"mfa_flag": ".//{ns}MfaEnabled"},
    "namespaces": {"ns": "urn:hr"}, "field_map": {"mfa_enforced": {"from":"mfa_flag","coerce":"bool"}} },
  { "name": "corp-ldap", "type": "ldap", "url": "ldap://dc01:389", "bind_dn": "...", "bind_pw": "...",
    "base_dn": "OU=Users,DC=corp,DC=com", "filter": "(sAMAccountName={asset_id})",
    "field_map": {"days_since_last_login": {"from":"lastLogonTimestamp","coerce":"days_since"}} }
]
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Dict, List, Optional

from app.config import settings

logger = logging.getLogger(__name__)

VALID_TYPES = {"sql", "file", "soap", "ldap"}


@dataclass
class LegacySource:
    name: str
    type: str
    url: str
    field_map: Dict[str, Any] = field(default_factory=dict)
    # sql
    query: Optional[str] = None
    discovery_query: Optional[str] = None
    key_column: Optional[str] = None
    # file
    format: str = "csv"            # csv | json | fixed
    fields: Optional[list] = None  # for fixed-width: [{"name","start","length"}]
    # soap
    soap_action: Optional[str] = None
    template: Optional[str] = None
    field_paths: Optional[Dict[str, str]] = None
    namespaces: Optional[Dict[str, str]] = None
    # ldap
    bind_dn: Optional[str] = None
    bind_pw: Optional[str] = None
    base_dn: Optional[str] = None
    filter: Optional[str] = None


def _raw_config() -> list:
    import os
    # Read env directly (not the cached settings singleton) so configuration
    # changes and per-test setup are honored regardless of import order.
    inline = os.getenv("LEGACY_SOURCES_JSON") or settings.legacy_sources_json
    path = os.getenv("LEGACY_SOURCES_FILE") or settings.legacy_sources_file
    if inline:
        return json.loads(inline)
    if path:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return []


@lru_cache
def _load() -> Dict[str, LegacySource]:
    out: Dict[str, LegacySource] = {}
    for raw in _raw_config():
        t = str(raw.get("type", "")).lower()
        if t not in VALID_TYPES:
            logger.warning("skipping legacy source %s: bad type %r", raw.get("name"), t)
            continue
        out[raw["name"]] = LegacySource(
            name=raw["name"], type=t, url=raw["url"], field_map=raw.get("field_map", {}),
            query=raw.get("query"), discovery_query=raw.get("discovery_query"),
            key_column=raw.get("key_column"), format=raw.get("format", "csv"),
            fields=raw.get("fields"), soap_action=raw.get("soap_action"),
            template=raw.get("template"), field_paths=raw.get("field_paths"),
            namespaces=raw.get("namespaces"), bind_dn=raw.get("bind_dn"),
            bind_pw=raw.get("bind_pw"), base_dn=raw.get("base_dn"), filter=raw.get("filter"),
        )
    return out


def reload_sources() -> None:
    _load.cache_clear()


def get_source(name: str) -> Optional[LegacySource]:
    return _load().get(name)


def list_sources() -> List[Dict[str, str]]:
    # names + types only — never expose connection strings or credentials
    return [{"name": s.name, "type": s.type} for s in _load().values()]
