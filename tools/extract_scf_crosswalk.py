#!/usr/bin/env python3
"""Regenerate app/data/scf_crosswalk.json from the official SCF workbook.

app/data/scf_crosswalk.json is a *generated* file. Without this script it would
be 170KB of unexplained mappings that nobody could re-derive, audit, or update
when SCF ships a new release — which is a poor look for the one feature whose
entire purpose is giving the crosswalk verifiable provenance.

Usage:
    # the workbook lives in the SCF council's public repo
    git clone --depth 1 https://github.com/securecontrolsframework/securecontrolsframework
    python tools/extract_scf_crosswalk.py \\
        --xlsx securecontrolsframework/secure-controls-framework-scf-2026-2.xlsx

Parsed with the stdlib only (zipfile + ElementTree) — an .xlsx is a zip of XML,
and neither openpyxl nor pandas is a dependency of this project.

TWO NORMALIZATION DECISIONS, both verified against the workbook and both easy
to get silently wrong on a naive regeneration:

1. NIST ids. SCF zero-pads ("AC-01", "AC-11(01)"); our catalog does not
   ("AC-1", "AC-11(1)"). Both the family number and any enhancement number
   need the padding stripped. Missing the enhancement case silently drops ~440
   references, since they simply fail to match the catalog.

2. ISO ids — the subtle one. SCF has BOTH an "ISO 27001 2022" and an
   "ISO 27002 2022" column, and the intuitive choice is wrong. ISO 27001:2022
   has two numbering systems that collide: the ISMS management clauses
   (4.1-10.2) and Annex A (A.5.1-A.8.34). SCF's 27001 column holds the
   *management clauses* — verified empirically: all 31 of its distinct tokens
   are clause-shaped ("4.4", "9.3.2"), none fall in Annex-A-only ranges.
   Annex A reuses ISO 27002:2022's control numbering, so the 27002 column is
   the one comparable to our Annex-A-only catalog (93 of its 96 distinct
   tokens match directly once prefixed "A."). Using the 27001 column would
   produce silently WRONG links, not empty ones — clause 5.1 "Leadership"
   would collide with Annex A.5.1 "Policies for information security", same
   number, unrelated content.

Columns are resolved BY HEADER TEXT, never by position. SCF adds framework
columns between releases, so a hardcoded index would eventually read a
different framework's data and produce confidently wrong mappings — the same
class of failure as picking the wrong ISO column.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
RELS_NS = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}
R_ID = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "app" / "data" / "scf_crosswalk.json"
NIST_CATALOG = REPO / "app" / "data" / "frameworks" / "nist_800_53.json"
ISO_CATALOG = REPO / "app" / "data" / "frameworks" / "iso_27001_2022.json"

# Header labels as they appear in the workbook, with whitespace collapsed.
H_DOMAIN, H_NAME, H_ID = "SCF Domain", "SCF Control", "SCF #"
H_ISO27002, H_NIST = "ISO 27002 2022", "NIST 800-53 R5"
H_ISO27001 = "ISO 27001 2022"  # deliberately NOT used — see module docstring

_ENH = re.compile(r"\(0*(\d+)\)")
_NIST_ID = re.compile(r"^([A-Z]{2})-0*(\d+)(\(0*\d+\))?$")


def col_index(ref: str) -> int:
    """'BC12' -> zero-based column index."""
    idx = 0
    for ch in ref:
        if ch.isalpha():
            idx = idx * 26 + (ord(ch.upper()) - 64)
        else:
            break
    return idx - 1


def load_sheet(z: zipfile.ZipFile, sheet_name: str) -> ET.Element:
    """Resolve a sheet by NAME via the workbook relationships.

    The crosswalk is not always sheet3.xml — the physical filename is an
    implementation detail of whichever tool last saved the workbook.
    """
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
    targets = {r.get("Id"): r.get("Target") for r in rels.findall("r:Relationship", RELS_NS)}
    for sheet in wb.findall("a:sheets/a:sheet", NS):
        if sheet.get("name") == sheet_name:
            target = targets[sheet.get(R_ID)].lstrip("/")
            if not target.startswith("xl/"):
                target = "xl/" + target
            return ET.fromstring(z.read(target))
    available = [s.get("name") for s in wb.findall("a:sheets/a:sheet", NS)]
    sys.exit(f"sheet {sheet_name!r} not found. Available: {available}")


def shared_strings(z: zipfile.ZipFile) -> list[str]:
    root = ET.fromstring(z.read("xl/sharedStrings.xml"))
    text_tag = f"{{{NS['a']}}}t"
    return ["".join(t.text or "" for t in si.iter(text_tag))
            for si in root.findall("a:si", NS)]


def row_cells(row: ET.Element, shared: list[str]) -> dict[int, str]:
    """Cell values by column index.

    Only <v> is read. The workbook has no inline strings (t="inlineStr") and no
    formula cells lacking a cached value — both were checked; either would mean
    silently missing data here.
    """
    out: dict[int, str] = {}
    for c in row.findall("a:c", NS):
        v = c.find("a:v", NS)
        if v is None or v.text is None:
            continue
        out[col_index(c.get("r"))] = shared[int(v.text)] if c.get("t") == "s" else v.text
    return out


def resolve_columns(header: dict[int, str]) -> dict[str, int]:
    """Map required header labels to column indices, failing loudly."""
    normalized = {re.sub(r"\s+", " ", label).strip(): idx for idx, label in header.items()}
    wanted = {"domain": H_DOMAIN, "name": H_NAME, "id": H_ID,
              "iso": H_ISO27002, "nist": H_NIST}
    resolved, missing = {}, []
    for key, label in wanted.items():
        if label in normalized:
            resolved[key] = normalized[label]
        else:
            missing.append(label)
    if missing:
        sys.exit(f"required column(s) not found in the header row: {missing}\n"
                 f"SCF may have renamed them; update the H_* constants.")
    if H_ISO27001 in normalized and resolved["iso"] == normalized[H_ISO27001]:
        sys.exit("refusing to run: resolved the ISO 27001 column, which holds "
                 "management clauses, not Annex A controls (see docstring)")
    return resolved


def normalize_nist(token: str) -> str | None:
    """'AC-01' -> 'AC-1'; 'AC-11(01)' -> 'AC-11(1)'."""
    token = token.strip()
    if not token:
        return None
    m = _NIST_ID.match(token)
    if not m:
        return token  # unexpected shape: keep it so the catalog filter reports it
    family, number, enhancement = m.groups()
    if enhancement:
        return f"{family}-{number}({_ENH.match(enhancement).group(1)})"
    return f"{family}-{number}"


def normalize_iso(token: str) -> str | None:
    token = token.strip()
    return f"A.{token}" if token else None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xlsx", required=True, type=Path, help="path to the SCF workbook")
    ap.add_argument("--sheet", default=None,
                    help="crosswalk sheet name (default: auto-detect 'SCF <version>')")
    ap.add_argument("--version", default=None,
                    help="version label for the output (default: derived from the sheet name)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    if not args.xlsx.exists():
        sys.exit(f"no such workbook: {args.xlsx}")

    z = zipfile.ZipFile(args.xlsx)
    sheet_name = args.sheet
    if sheet_name is None:
        wb = ET.fromstring(z.read("xl/workbook.xml"))
        names = [s.get("name") for s in wb.findall("a:sheets/a:sheet", NS)]
        # the crosswalk sheet is "SCF <version>"; the others carry a descriptive
        # suffix ("Compensating Controls 2026.2") or no version at all
        candidates = [n for n in names if re.fullmatch(r"SCF \d{4}\.\d+", n or "")]
        if len(candidates) != 1:
            sys.exit(f"could not auto-detect the crosswalk sheet from {names}; pass --sheet")
        sheet_name = candidates[0]

    version = args.version or f"scf-{sheet_name.split()[-1]}"
    sheet = load_sheet(z, sheet_name)
    shared = shared_strings(z)
    rows = sheet.find("a:sheetData", NS).findall("a:row", NS)
    if not rows:
        sys.exit(f"sheet {sheet_name!r} has no rows")

    cols = resolve_columns(row_cells(rows[0], shared))
    nist_ids = {r["id"] for r in json.loads(NIST_CATALOG.read_text())}
    iso_ids = {r["id"] for r in json.loads(ISO_CATALOG.read_text())}

    controls = []
    nist_kept = iso_kept = 0
    unmatched_nist: set[str] = set()
    unmatched_iso: set[str] = set()

    for row in rows[1:]:
        d = row_cells(row, shared)
        scf_id = (d.get(cols["id"]) or "").strip()
        if not scf_id:
            continue

        nist_refs = sorted({n for tok in (d.get(cols["nist"]) or "").split("\n")
                            if (n := normalize_nist(tok)) is not None})
        iso_refs = sorted({i for tok in (d.get(cols["iso"]) or "").split("\n")
                           if (i := normalize_iso(tok)) is not None})
        unmatched_nist |= {n for n in nist_refs if n not in nist_ids}
        unmatched_iso |= {i for i in iso_refs if i not in iso_ids}

        # Keep only references that resolve against our real catalogs, so the
        # crosswalk can never point a caller at a control that doesn't exist.
        nist_refs = [n for n in nist_refs if n in nist_ids]
        iso_refs = [i for i in iso_refs if i in iso_ids]
        nist_kept += len(nist_refs)
        iso_kept += len(iso_refs)
        if not nist_refs and not iso_refs:
            continue  # nothing this control can pivot through

        controls.append({
            "scf_id": scf_id,
            "domain": (d.get(cols["domain"]) or "").strip(),
            "name": (d.get(cols["name"]) or "").strip(),
            "nist_800_53_r5": nist_refs,
            "iso_27001_annex_a": iso_refs,
        })

    # Sanity gates: a regeneration that silently collapses is worse than one
    # that fails, because the result still looks like a valid crosswalk.
    if len(controls) < 500:
        sys.exit(f"only {len(controls)} controls extracted — expected 800+. "
                 f"Columns or sheet layout probably changed; not writing.")
    if unmatched_nist:
        sys.exit(f"{len(unmatched_nist)} NIST refs did not match the catalog, "
                 f"e.g. {sorted(unmatched_nist)[:10]}. Normalization is likely "
                 f"stale; not writing.")

    doc = {
        "version": version,
        "source": "https://github.com/securecontrolsframework/securecontrolsframework",
        "generated_by": "tools/extract_scf_crosswalk.py",
        "license_note": (
            "Per the source repository's README: \"The SCF is free via "
            "Creative Commons licensing.\" Confirm the exact CC variant at "
            "securecontrolsframework.com before any redistribution beyond "
            "this internal crosswalk use."
        ),
        "note": (
            "NIST refs pivot through SCF's NIST SP 800-53 R5 column "
            "(zero-padding normalized to match our catalog). ISO refs pivot "
            "through SCF's ISO 27002:2022 column, NOT its ISO 27001:2022 "
            "column - the latter maps to the ISO management-system clauses "
            "(4-10), not Annex A, and is not comparable to our Annex-A-only "
            "iso_27001_2022.json catalog. Every ref here is pre-filtered to "
            "exist in the corresponding catalog file."
        ),
        "controls": controls,
    }
    args.out.write_text(json.dumps(doc, indent=1, sort_keys=False))

    print(f"sheet: {sheet_name}  ->  version {version}")
    print(f"SCF controls with >=1 usable ref: {len(controls)}")
    print(f"NIST refs kept: {nist_kept}  unmatched: {len(unmatched_nist)}")
    print(f"ISO  refs kept: {iso_kept}  unmatched (dropped): "
          f"{len(unmatched_iso)} -> {sorted(unmatched_iso)[:5]}")
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
