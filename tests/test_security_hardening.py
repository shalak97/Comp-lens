"""Regression tests for the security-hardening fixes.

Covers: tenant-scoped evidence deletion (no cross-tenant IDOR), signed Merkle
anchors + leaf/node domain separation, evidence-root signature binding, and the
OPA-is-opt-in config default.
"""
from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/complens_sec.db")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "test-signing-key")


# ── #1 cross-tenant evidence deletion ──
def test_delete_document_is_tenant_scoped(db_session):
    from app.models import EvidenceDocument
    from app.services.evidence_graph import EvidenceService
    svc = EvidenceService(db_session)
    doc_id = svc.add_document("tenantA", "d", "MFA is enforced for all administrators.")["doc_id"]

    # a different tenant must NOT be able to delete it
    assert svc.delete_document(doc_id, "tenantB") is False
    assert db_session.get(EvidenceDocument, doc_id) is not None

    # the owning tenant can
    assert svc.delete_document(doc_id, "tenantA") is True
    assert db_session.get(EvidenceDocument, doc_id) is None


# ── #6 Merkle anchor signing + domain separation ──
def test_merkle_anchor_is_signed(db_session):
    from app.services.evidence_sign import verify_root
    from app.services.merkle import MerkleService
    out = MerkleService(db_session).anchor("empty-tenant")
    assert out["signature"]
    assert verify_root(out["root"], "empty-tenant", out["leaf_count"], out["signature"]) is True
    # a forged signature does not verify
    assert verify_root(out["root"], "empty-tenant", out["leaf_count"], "deadbeef") is False


def test_sign_root_binds_root_tenant_and_count():
    from app.services.evidence_sign import sign_root, verify_root
    sig = sign_root("abc", "t", 5)
    assert verify_root("abc", "t", 5, sig) is True
    assert verify_root("abcd", "t", 5, sig) is False       # root bound
    assert verify_root("abc", "other", 5, sig) is False    # tenant bound
    assert verify_root("abc", "t", 6, sig) is False        # leaf_count bound


def test_merkle_domain_separation_blocks_internal_node_forgery():
    from app.services.merkle import build_tree, inclusion_proof, verify_proof
    leaves = [f"rec{i}" * 8 for i in range(4)]
    root, levels = build_tree(leaves)
    # an internal node hash must not be accepted as a leaf (second-preimage)
    internal_node = levels[1][0]
    assert verify_proof(internal_node, [], root) is False
    # legitimate inclusion proofs still verify
    assert all(verify_proof(leaves[i], inclusion_proof(levels, i), root) for i in range(4))


# ── #4 OPA is opt-in by default ──
def test_opa_is_opt_in_by_default():
    from app.config import settings
    assert settings.opa_url is None
    assert settings.policy_engine.lower() != "opa"
