"""Configured connector instances — labeled connections on top of the connector
catalog. An instance is a (connector_key, label, non-secret config) tuple; sync
and test delegate to the connector framework (which reads credentials from the
environment and fails closed to demo mode). Config never stores secret values.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors import catalog as ccat
from app.connectors import framework as cfw
from app.models import ConnectorInstance


def _to_dict(inst: ConnectorInstance) -> dict[str, Any]:
    # Expose which config keys are set (names only), never the values.
    return {
        "id": inst.id,
        "connector_key": inst.connector_key,
        "label": inst.label,
        "config_keys_set": sorted((inst.config or {}).keys()),
        "enabled": inst.enabled,
        "on": inst.enabled,
        "last_sync_at": inst.last_sync_at.isoformat() if inst.last_sync_at else None,
        "last_status": inst.last_status,
        "last_mode": inst.last_mode,
        "last_error": inst.last_error,
        "evidence_count": inst.evidence_count,
        "created_at": inst.created_at.isoformat() if inst.created_at else None,
    }


def _connector(connector_key: str) -> dict[str, Any]:
    c = ccat.get(connector_key)
    if not c:
        raise ValueError(f"unknown connector '{connector_key}'")
    return c


def list_instances(db: Session, tenant_id: str) -> list[dict[str, Any]]:
    rows = db.execute(select(ConnectorInstance).where(
        ConnectorInstance.tenant_id == tenant_id
    ).order_by(ConnectorInstance.created_at.desc())).scalars().all()
    return [_to_dict(r) for r in rows]


def create_instance(db: Session, tenant_id: str, connector_key: str, label: str,
                    config: dict | None = None) -> dict[str, Any]:
    _connector(connector_key)  # validate the key exists
    inst = ConnectorInstance(
        tenant_id=tenant_id, connector_key=connector_key,
        label=label or connector_key, config=config or {}, enabled=True)
    db.add(inst)
    db.commit()
    return _to_dict(inst)


def delete_instance(db: Session, tenant_id: str, instance_id: str) -> bool:
    inst = db.get(ConnectorInstance, instance_id)
    if not inst or inst.tenant_id != tenant_id:
        return False
    db.delete(inst)
    db.commit()
    return True


def _get_owned(db: Session, tenant_id: str, instance_id: str) -> ConnectorInstance:
    inst = db.get(ConnectorInstance, instance_id)
    if not inst or inst.tenant_id != tenant_id:
        raise KeyError(instance_id)
    return inst


def sync_instance(db: Session, tenant_id: str, instance_id: str) -> dict[str, Any]:
    inst = _get_owned(db, tenant_id, instance_id)
    res = cfw.sync(db, _connector(inst.connector_key), tenant_id)
    inst.last_sync_at = datetime.now(UTC)
    inst.last_status = res.get("status")
    inst.last_mode = res.get("mode")
    inst.last_error = res.get("error")
    inst.evidence_count = res.get("evidence_count", 0)
    db.commit()
    return res


def test_instance(db: Session, tenant_id: str, instance_id: str) -> dict[str, Any]:
    inst = _get_owned(db, tenant_id, instance_id)
    return cfw.test_connection(_connector(inst.connector_key))


def ephemeral_sync(db: Session, tenant_id: str, connector_key: str,
                   config: dict | None = None) -> dict[str, Any]:
    """Sync a connector by type without persisting an instance."""
    return cfw.sync(db, _connector(connector_key), tenant_id)


def ephemeral_test(connector_key: str, config: dict | None = None) -> dict[str, Any]:
    """Test a connector by type without persisting an instance."""
    return cfw.test_connection(_connector(connector_key))
