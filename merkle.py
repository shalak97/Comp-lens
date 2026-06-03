"""Merkle transparency log for evidence.

Periodically build a Merkle tree over a tenant's evidence record_hashes and
store the signed root (an "anchor"). Auditors can later get an inclusion proof
for any evidence record and verify it against the anchored root — proving the
record existed and hasn't been altered, WITHOUT per-write hash-chaining (so no
write-path serialization bottleneck). Solves the concurrency issue of linear
chains: records are batched into a tree at anchor time.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import EvidenceMeta, MerkleAnchor


def _h(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _node(a: str, b: str) -> str:
    # order-independent pairing so proofs are simple to verify
    lo, hi = sorted((a, b))
    return _h(lo + hi)


def build_tree(leaves: List[str]) -> Tuple[str, List[List[str]]]:
    """Return (root, levels) where levels[0] = leaves."""
    if not leaves:
        return _h(""), [[]]
    levels = [list(leaves)]
    cur = list(leaves)
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            if i + 1 < len(cur):
                nxt.append(_node(cur[i], cur[i + 1]))
            else:
                nxt.append(cur[i])  # odd one promoted
        levels.append(nxt)
        cur = nxt
    return cur[0], levels


def inclusion_proof(levels: List[List[str]], index: int) -> List[str]:
    proof = []
    for level in levels[:-1]:
        sib = index ^ 1
        if sib < len(level):
            proof.append(level[sib])
        index //= 2
    return proof


def verify_proof(leaf: str, proof: List[str], root: str) -> bool:
    h = leaf
    for sib in proof:
        h = _node(h, sib)
    return h == root


class MerkleService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def _ordered_leaves(self, tenant_id: str) -> List[Tuple[str, str]]:
        rows = self.db.execute(
            select(EvidenceMeta.evidence_id, EvidenceMeta.record_hash)
            .where(EvidenceMeta.tenant_id == tenant_id)
            .order_by(EvidenceMeta.created_at.asc(), EvidenceMeta.evidence_id.asc())
        ).all()
        return [(eid, rh or "") for eid, rh in rows]

    def anchor(self, tenant_id: str) -> Dict[str, Any]:
        leaves = [rh for _eid, rh in self._ordered_leaves(tenant_id)]
        root, _ = build_tree(leaves)
        a = MerkleAnchor(tenant_id=tenant_id, root=root, leaf_count=len(leaves))
        self.db.add(a)
        self.db.flush()
        return {"anchor_id": a.id, "root": root, "leaf_count": len(leaves),
                "created_at": a.created_at.isoformat()}

    def anchors(self, tenant_id: str) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            select(MerkleAnchor).where(MerkleAnchor.tenant_id == tenant_id)
            .order_by(MerkleAnchor.created_at.desc())
        ).scalars().all()
        return [{"anchor_id": a.id, "root": a.root, "leaf_count": a.leaf_count,
                 "created_at": a.created_at.isoformat()} for a in rows]

    def proof(self, tenant_id: str, evidence_id: str) -> Dict[str, Any]:
        ordered = self._ordered_leaves(tenant_id)
        ids = [e for e, _ in ordered]
        leaves = [rh for _, rh in ordered]
        if evidence_id not in ids:
            return {"found": False}
        idx = ids.index(evidence_id)
        root, levels = build_tree(leaves)
        proof = inclusion_proof(levels, idx)
        return {"found": True, "evidence_id": evidence_id, "leaf": leaves[idx],
                "proof": proof, "root": root,
                "verified": verify_proof(leaves[idx], proof, root)}
