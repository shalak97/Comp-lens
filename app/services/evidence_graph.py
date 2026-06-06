"""Evidence graph: turn documents into a document -> concept -> control graph.

Pipeline: detect concepts (LLM, grounded by verbatim quote) -> verify every quote
exists in the source -> drop unverifiable or unknown-concept hits -> map concepts to
controls via the curated lexicon (no hallucinated control ids possible). If the LLM is
unavailable, fall back to deterministic alias matching. Every edge carries provenance
(quote, confidence, method) so the graph is auditable and reproducible.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import EvidenceDocument, EvidenceConceptHit
from app.services import framework_catalog as catalog
from app.services import llm_client

_LEX_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "concept_lexicon.json")


@lru_cache(maxsize=1)
def lexicon() -> List[Dict[str, Any]]:
    with open(_LEX_PATH, encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def _lex_index() -> Dict[str, Dict[str, Any]]:
    return {c["id"]: c for c in lexicon()}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip().lower()


def verify_quote(quote: str, doc_text: str) -> bool:
    """A hit survives only if its quote appears (whitespace-insensitively) in the source."""
    q = _norm(quote)
    return len(q) >= 8 and q in _norm(doc_text)


def _sentences(text: str) -> List[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]


def lexicon_detect(doc_text: str) -> List[Dict[str, Any]]:
    """Deterministic fallback: find concepts by whole-word alias match, quote the containing sentence."""
    hits: List[Dict[str, Any]] = []
    sents = _sentences(doc_text)
    low_sents = [s.lower() for s in sents]
    for c in lexicon():
        matched_sent = None
        for alias in c["aliases"]:
            pat = re.compile(r"(?<!\w)" + re.escape(alias.lower()) + r"(?!\w)")
            for i, ls in enumerate(low_sents):
                if pat.search(ls):
                    matched_sent = sents[i]
                    break
            if matched_sent:
                break
        if matched_sent:
            hits.append({"concept_id": c["id"], "quote": matched_sent[:400], "confidence": 0.5})
    return hits


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract(doc_text: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Return (method, verified_hits). method in {'llm','lexicon'}."""
    valid_ids = set(_lex_index())
    method = "lexicon"
    raw = llm_client.detect_concepts(doc_text, lexicon())
    if raw is not None:
        method = "llm"
    else:
        raw = lexicon_detect(doc_text)
    # validate: known concept id + verbatim quote
    seen = set()
    out: List[Dict[str, Any]] = []
    for h in raw:
        cid = h.get("concept_id")
        if cid not in valid_ids or cid in seen:
            continue
        if not verify_quote(h.get("quote", ""), doc_text):
            continue
        seen.add(cid)
        out.append({"concept_id": cid, "quote": h["quote"][:600],
                    "confidence": max(0.0, min(1.0, float(h.get("confidence", 0.6)))),
                    "method": method})
    return method, out


def build_graph(docs: List[EvidenceDocument], hits: List[EvidenceConceptHit],
                framework: Optional[str] = None) -> Dict[str, Any]:
    lex = _lex_index()
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    def add_node(nid, ntype, label, meta=None):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, "meta": meta or {}}

    doc_by_id = {d.doc_id: d for d in docs}
    active_concepts = set()
    confirmed_edges = 0

    for h in hits:
        c = lex.get(h.concept_id)
        if not c:
            continue
        d = doc_by_id.get(h.doc_id)
        if not d:
            continue
        add_node(f"doc:{d.doc_id}", "document", d.name,
                 {"source_type": d.source_type, "method": d.method, "hits": 0})
        add_node(f"concept:{c['id']}", "concept", c["label"], {"controls": 0})
        edges.append({"source": f"doc:{d.doc_id}", "target": f"concept:{c['id']}",
                      "type": "evidences", "confidence": round(h.confidence, 2),
                      "quote": h.quote, "method": h.method, "confirmed": bool(h.confirmed),
                      "hit_id": h.id})
        if h.confirmed:
            confirmed_edges += 1
        active_concepts.add(c["id"])

    # concept -> control edges (only for concepts that have evidence)
    for cid in active_concepts:
        c = lex[cid]
        for m in c["controls"]:
            if framework and m["framework"] != framework:
                continue
            meta = catalog.get(m["framework"], m["control_id"]) or {}
            nid = f"ctrl:{m['framework']}:{m['control_id']}"
            add_node(nid, "control", m["control_id"],
                     {"framework": m["framework"], "title": meta.get("title", ""),
                      "family": meta.get("family", ""), "automated": meta.get("automated", False)})
            edges.append({"source": f"concept:{cid}", "target": nid, "type": "maps_to"})
            nodes[f"concept:{cid}"]["meta"]["controls"] += 1

    # tally doc hit counts
    for e in edges:
        if e["type"] == "evidences":
            nodes[e["source"]]["meta"]["hits"] += 1

    ntypes = {}
    for n in nodes.values():
        ntypes[n["type"]] = ntypes.get(n["type"], 0) + 1
    return {"nodes": list(nodes.values()), "edges": edges,
            "stats": {"documents": ntypes.get("document", 0), "concepts": ntypes.get("concept", 0),
                      "controls": ntypes.get("control", 0), "edges": len(edges),
                      "confirmed_edges": confirmed_edges}}


class EvidenceService:
    def __init__(self, db: Session):
        self.db = db

    def add_document(self, tenant_id: str, name: str, content: str,
                     source_type: str = "text") -> Dict[str, Any]:
        chash = content_hash(content)
        existing = self.db.execute(
            select(EvidenceDocument).where(EvidenceDocument.tenant_id == tenant_id,
                                           EvidenceDocument.content_hash == chash)).scalar_one_or_none()
        if existing:
            doc = existing
            self.db.execute(EvidenceConceptHit.__table__.delete().where(
                EvidenceConceptHit.doc_id == doc.doc_id))
        else:
            doc = EvidenceDocument(tenant_id=tenant_id, name=name, content=content,
                                   content_hash=chash, char_count=len(content),
                                   source_type=source_type, status="pending")
            self.db.add(doc)
            self.db.flush()
        method, hits = extract(content)
        doc.method = method
        doc.model = (llm_client.active_model() if method == "llm" else None)
        doc.prompt_version = llm_client.PROMPT_VERSION if method == "llm" else None
        doc.status = "extracted"
        for h in hits:
            self.db.add(EvidenceConceptHit(tenant_id=tenant_id, doc_id=doc.doc_id,
                        concept_id=h["concept_id"], quote=h["quote"],
                        confidence=h["confidence"], method=h["method"]))
        try:
            from app.services.evidence_sign import sign as _sign
            doc.signature, doc.signed_at = _sign(doc.content_hash, tenant_id, doc.doc_id)
        except Exception:
            pass
        self.db.commit(); self.db.refresh(doc)
        return {"doc_id": doc.doc_id, "name": doc.name, "method": method,
                "concepts_found": len(hits), "char_count": doc.char_count,
                "hits": [{"concept_id": h["concept_id"], "confidence": h["confidence"],
                          "quote": h["quote"]} for h in hits]}

    def list_documents(self, tenant_id: str) -> List[Dict[str, Any]]:
        docs = self.db.execute(select(EvidenceDocument).where(
            EvidenceDocument.tenant_id == tenant_id)).scalars().all()
        out = []
        for d in docs:
            n = self.db.execute(select(EvidenceConceptHit).where(
                EvidenceConceptHit.doc_id == d.doc_id)).scalars().all()
            out.append({"doc_id": d.doc_id, "name": d.name, "source_type": d.source_type,
                        "method": d.method, "status": d.status, "char_count": d.char_count,
                        "concepts_found": len(n), "model": d.model,
                        "created_at": d.created_at.isoformat() if d.created_at else None})
        return out

    def graph(self, tenant_id: str, framework: Optional[str] = None) -> Dict[str, Any]:
        docs = self.db.execute(select(EvidenceDocument).where(
            EvidenceDocument.tenant_id == tenant_id)).scalars().all()
        hits = self.db.execute(select(EvidenceConceptHit).where(
            EvidenceConceptHit.tenant_id == tenant_id)).scalars().all()
        return build_graph(list(docs), list(hits), framework)

    def confirm_hit(self, hit_id: str, confirmed: bool = True,
                    auto_attest: bool = False, approver: Optional[str] = None) -> Dict[str, Any]:
        hit = self.db.get(EvidenceConceptHit, hit_id)
        if not hit:
            raise ValueError("hit not found")
        hit.confirmed = confirmed
        attested = []
        if confirmed and auto_attest:
            from app.services.attestation import AttestationService
            doc = self.db.get(EvidenceDocument, hit.doc_id)
            c = _lex_index().get(hit.concept_id, {})
            svc = AttestationService(self.db)
            for m in c.get("controls", []):
                svc.upsert(hit.tenant_id, m["framework"], m["control_id"], "compliant",
                           approver=approver, note=f"Evidenced by document: {doc.name if doc else hit.doc_id}",
                           evidence_ref=f"doc:{hit.doc_id}")
                attested.append(f"{m['framework']}:{m['control_id']}")
        self.db.commit()
        return {"hit_id": hit_id, "confirmed": confirmed, "attested_controls": attested}

    def delete_document(self, doc_id: str) -> None:
        self.db.execute(EvidenceConceptHit.__table__.delete().where(
            EvidenceConceptHit.doc_id == doc_id))
        d = self.db.get(EvidenceDocument, doc_id)
        if d:
            self.db.delete(d)
        self.db.commit()
