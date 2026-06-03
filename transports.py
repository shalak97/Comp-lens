"""Transports that fetch one raw record from a legacy system.

Each returns a flat dict of raw columns/attributes for the given asset; the
caller then applies the source's field_map to normalize it.

  sql   : SQLAlchemy, parameterized query (asset_id bound as :asset_id) — safe
  file  : local path or sftp:// URL; csv | json | fixed-width
  soap  : POST a templated envelope, extract values by element path
  ldap  : bind + search, return entry attributes

Connection details all come from the server-side LegacySource config, never
from the client request.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from app.config import settings
from app.connectors.base import ConnectorError
from app.legacy.sources import LegacySource

logger = logging.getLogger(__name__)

# cache SQLAlchemy engines per url so we reuse connection pools
_engines: Dict[str, Any] = {}


def _engine(url: str):
    from sqlalchemy import create_engine
    if url not in _engines:
        _engines[url] = create_engine(url, pool_pre_ping=True)
    return _engines[url]


def fetch_raw(source: LegacySource, asset_id: Optional[str]) -> Dict[str, Any]:
    try:
        if source.type == "sql":
            return _fetch_sql(source, asset_id)
        if source.type == "file":
            return _fetch_file(source, asset_id)
        if source.type == "soap":
            return _fetch_soap(source, asset_id)
        if source.type == "ldap":
            return _fetch_ldap(source, asset_id)
    except ConnectorError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ConnectorError(f"legacy {source.type} fetch failed: {exc}") from exc
    raise ConnectorError(f"unsupported legacy type {source.type}")


def discover(source: LegacySource) -> List[str]:
    """Enumerate asset ids from a source (sql only, via discovery_query)."""
    if source.type == "sql" and source.discovery_query and source.key_column:
        from sqlalchemy import text
        with _engine(source.url).connect() as c:
            rows = c.execute(text(source.discovery_query)).mappings().all()
            return [str(r[source.key_column]) for r in rows if r.get(source.key_column) is not None]
    return []


# ── SQL ──
def _fetch_sql(source: LegacySource, asset_id: Optional[str]) -> Dict[str, Any]:
    if not source.query:
        raise ConnectorError("sql source missing 'query'")
    from sqlalchemy import text
    with _engine(source.url).connect() as c:
        # asset_id bound as a parameter -> no SQL injection possible
        row = c.execute(text(source.query), {"asset_id": asset_id}).mappings().first()
        return dict(row) if row else {}


# ── FILE (local or SFTP) ──
def _read_bytes(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme in ("", "file"):
        path = parsed.path if parsed.scheme == "file" else url
        with open(path, "rb") as fh:
            return fh.read()
    if parsed.scheme == "sftp":
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(parsed.hostname, port=parsed.port or 22,
                       username=parsed.username or settings.ssh_default_user,
                       password=parsed.password, key_filename=settings.ssh_key_path,
                       timeout=settings.request_timeout_seconds)
        try:
            sftp = client.open_sftp()
            with sftp.open(parsed.path, "rb") as fh:
                return fh.read()
        finally:
            client.close()
    raise ConnectorError(f"unsupported file scheme {parsed.scheme!r}")


def _fetch_file(source: LegacySource, asset_id: Optional[str]) -> Dict[str, Any]:
    data = _read_bytes(source.url)
    fmt = (source.format or "csv").lower()

    if fmt == "json":
        obj = json.loads(data.decode("utf-8"))
        if isinstance(obj, dict):
            return obj
        rows = obj
        if source.key_column and asset_id is not None:
            for r in rows:
                if str(r.get(source.key_column)) == str(asset_id):
                    return r
            return {}
        return rows[0] if rows else {}

    if fmt == "fixed":
        if not source.fields:
            raise ConnectorError("fixed-width source needs 'fields'")
        text_data = data.decode("utf-8", "ignore")
        for line in text_data.splitlines():
            rec = {f["name"]: line[f["start"]: f["start"] + f["length"]].strip() for f in source.fields}
            if not source.key_column or asset_id is None or str(rec.get(source.key_column)) == str(asset_id):
                return rec
        return {}

    # default: csv
    reader = csv.DictReader(io.StringIO(data.decode("utf-8")))
    rows = list(reader)
    if source.key_column and asset_id is not None:
        for r in rows:
            if str(r.get(source.key_column)) == str(asset_id):
                return dict(r)
        return {}
    return dict(rows[0]) if rows else {}


# ── SOAP ──
def _fetch_soap(source: LegacySource, asset_id: Optional[str]) -> Dict[str, Any]:
    if not source.template or not source.field_paths:
        raise ConnectorError("soap source needs 'template' and 'field_paths'")
    envelope = source.template.replace("{asset_id}", str(asset_id or ""))
    headers = {"Content-Type": "text/xml; charset=utf-8"}
    if source.soap_action:
        headers["SOAPAction"] = source.soap_action
    r = requests.post(source.url, data=envelope.encode("utf-8"), headers=headers,
                      timeout=settings.request_timeout_seconds)
    if r.status_code >= 400:
        raise ConnectorError(f"soap {r.status_code}")
    root = ET.fromstring(r.content)
    ns = source.namespaces or {}
    out: Dict[str, Any] = {}
    for key, path in source.field_paths.items():
        el = root.find(path, ns) if ns else root.find(path)
        out[key] = el.text if el is not None else None
    return out


# ── LDAP ──
def _fetch_ldap(source: LegacySource, asset_id: Optional[str]) -> Dict[str, Any]:
    try:
        from ldap3 import ALL, Connection, Server
    except ImportError as exc:  # pragma: no cover
        raise ConnectorError("ldap3 not installed") from exc
    if not (source.base_dn and source.filter):
        raise ConnectorError("ldap source needs 'base_dn' and 'filter'")
    server = Server(source.url, get_info=ALL)
    conn = Connection(server, user=source.bind_dn, password=source.bind_pw, auto_bind=True)
    try:
        flt = source.filter.replace("{asset_id}", str(asset_id or ""))
        conn.search(source.base_dn, flt, attributes=["*"])
        if not conn.entries:
            return {}
        entry = conn.entries[0]
        return {k: entry[k].value for k in entry.entry_attributes}
    finally:
        conn.unbind()
