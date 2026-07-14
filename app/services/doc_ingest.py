"""Document → markdown → controls → telemetry events.

The 'compliance as code' on-ramp: drop in a real policy PDF, SOC 2 report, or
vendor security doc, and Comp-Lens converts it to clean markdown (a throwaway
intermediate), extracts which controls it provides evidence for, and emits
canonical evidence events that flow into the telemetry / policy layer.

Two-tier extraction (as chosen):
  - deterministic lexicon scan — always on, no AI, fully reliable baseline
  - optional LLM layer — richer extraction when a model is reachable

The markdown is NOT persisted; only the extracted control evidence is kept.
"""
from __future__ import annotations

import re
from typing import Any

from app.services import evidence_graph as evg


# ── doc → markdown (clean intermediate) ──
def to_markdown(text: str, source_type: str = "text") -> str:
    """Normalize extracted document text into lightweight, clean markdown.

    Not a full HTML/PDF→MD converter — a pragmatic normalizer: collapse
    whitespace, promote ALL-CAPS / numbered headers, bulletize obvious lists.
    Good enough to make extraction reliable; thrown away after.
    """
    lines = [ln.rstrip() for ln in (text or "").splitlines()]
    out: list[str] = []
    for ln in lines:
        s = ln.strip()
        if not s:
            if out and out[-1] != "":
                out.append("")
            continue
        # numbered section header: "4.2 Access Control"
        if re.match(r"^\d+(\.\d+)*\s+[A-Z]", s) and len(s) < 90:
            out.append(f"## {s}")
        # ALL-CAPS short line => header
        elif s.isupper() and 3 <= len(s) <= 80:
            out.append(f"### {s.title()}")
        # bullet-ish
        elif re.match(r"^[\-\*•·]\s+", s):
            out.append(re.sub(r"^[\-\*•·]\s+", "- ", s))
        elif re.match(r"^\(?[a-z]\)?[\.\)]\s+", s):  # (a) lettered list
            out.append("- " + re.sub(r"^\(?[a-z]\)?[\.\)]\s+", "", s))
        else:
            out.append(s)
    md = "\n".join(out)
    md = re.sub(r"\n{3,}", "\n\n", md).strip()
    return md


# ── markdown → controls (lexicon baseline + optional LLM) ──
def extract_controls(markdown: str) -> dict[str, Any]:
    """Find which controls this document provides evidence for.

    Uses evidence_graph.extract() which prefers an LLM if one is wired and falls
    back to the deterministic lexicon scan otherwise. Returns control-level
    evidence with the verbatim quote that justifies each.
    """
    method, hits = evg.extract(markdown)          # [{concept_id, quote, confidence}], method in {llm,lexicon}
    lex = {c["id"]: c for c in evg.lexicon()}
    by_control: dict[str, dict[str, Any]] = {}
    for h in hits:
        concept = lex.get(h.get("concept_id"))
        if not concept:
            continue
        for ctrl in concept.get("controls", []):
            cid = ctrl.get("control_id")
            if not cid:
                continue
            entry = by_control.setdefault(cid, {
                "control_id": cid, "concepts": [], "quote": h.get("quote", ""),
                "confidence": 0.0, "frameworks": set()})
            entry["concepts"].append(concept["id"])
            entry["confidence"] = max(entry["confidence"], h.get("confidence", 0.5))
            entry["frameworks"].add(ctrl.get("framework", "NIST_800_53"))
    controls = []
    for cid, e in by_control.items():
        controls.append({"control_id": cid, "concepts": sorted(set(e["concepts"])),
                         "quote": e["quote"][:300], "confidence": round(e["confidence"], 2),
                         "frameworks": sorted(e["frameworks"])})
    controls.sort(key=lambda x: x["confidence"], reverse=True)
    return {"method": method, "controls": controls, "concept_hits": len(hits)}


# ── controls → canonical telemetry events ──
def to_events(extracted: dict[str, Any], tenant_id: str, source: str = "document") -> list[dict[str, Any]]:
    """Turn extracted controls into canonical evidence events.

    A document is *evidence that a control is addressed*, so each becomes a
    'pass' event with the justifying quote retained as evidence. (A reviewer can
    later downgrade; the document asserting a control ≠ the control being
    effective, but it IS evidence the control exists.)
    """
    events = []
    for c in extracted.get("controls", []):
        events.append({
            "source": source, "tenant_id": tenant_id,
            "control_id": c["control_id"], "status": "pass",
            "severity": "info",
            "evidence": {"from_document": True, "quote": c["quote"],
                         "concepts": c["concepts"], "extraction": extracted.get("method"),
                         "confidence": c["confidence"]},
        })
    return events


# ── the full pipeline ──
def ingest_document(text: str, tenant_id: str = "default",
                    source: str = "document", source_type: str = "text") -> dict[str, Any]:
    """doc text → markdown → controls → events. Returns everything for transparency."""
    md = to_markdown(text, source_type)
    extracted = extract_controls(md)
    events = to_events(extracted, tenant_id, source)
    return {
        "markdown_chars": len(md),
        "extraction_method": extracted["method"],
        "controls_found": len(extracted["controls"]),
        "controls": extracted["controls"],
        "events": events,
    }
