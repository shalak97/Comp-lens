"""One control, one spelling.

NIST writes an enhancement `AC-2(1)`. Four of this repository's knowledge bases
write the same control `AC-2.1`, and nothing translated between them:

    control_baselines.json   182 of 370 keys unreachable
    control_guidance.json    182 of 371
    cis_mappings.json          4 of  70
    nist_related.json        362 of 651

They are different dictionary keys and different graph nodes, so the join
silently produced nothing rather than failing. /remediation/plan reported
`baseline: ["—"]` and empty guidance for every enhancement — including ones
SP 800-53B does place in the LOW or MODERATE baseline — and because
`baseline_bonus` feeds `priority_score`, enhancements were ranked below base
controls whatever their tier. The dependency graph built `AC-6(7)` from the
concept lexicon and `AC-6.7` from nist_related as two unconnected nodes, so a
failure cascade stopped at the namespace boundary.

`canonical_control_id` is the one translation, applied where the data is loaded
and where it is looked up.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

from app.services.control_identity import canonical_control_id

DATA = pathlib.Path(__file__).resolve().parent.parent / "app" / "data"
KNOWLEDGE_BASES = ("control_baselines.json", "control_guidance.json",
                   "cis_mappings.json", "nist_related.json")


@pytest.mark.parametrize(("given", "want"), [
    ("AC-2.1", "AC-2(1)"),
    ("SC-7.13", "SC-7(13)"),
    ("SR-5.2", "SR-5(2)"),
    ("ac-2.1", "AC-2(1)"),          # case-insensitive
    ("  AC-2.1  ", "AC-2(1)"),      # tolerant of whitespace
    ("AC-2(1)", "AC-2(1)"),         # already canonical
    ("AC-2", "AC-2"),               # base control untouched
])
def test_a_dotted_enhancement_becomes_the_catalogue_spelling(given, want):
    assert canonical_control_id(given) == want


@pytest.mark.parametrize("given", [
    "A.8.24",               # ISO 27001 — dots, but not a NIST enhancement
    "CC6.1",                # SOC 2
    "SC-28-OBJSTORE-KMS",   # this platform's internal id
    "AC-2-7",               # internal spelling of an enhancement
    "PM-1",
    "",
])
def test_everything_else_is_left_alone(given):
    """A canonicaliser that reaches too far would break three other
    namespaces that legitimately contain dots or hyphens."""
    assert canonical_control_id(given) == given


def _nist_catalog_ids() -> set[str]:
    rows = json.loads((DATA / "frameworks" / "nist_800_53.json").read_text())
    return {r["id"] for r in rows}


@pytest.mark.parametrize("filename", KNOWLEDGE_BASES)
def test_every_knowledge_base_key_resolves_to_a_real_control(filename):
    """The regression itself: a key that resolves to nothing is a lookup that
    silently returns the default forever."""
    catalog = _nist_catalog_ids()
    keys = [k for k in json.loads((DATA / filename).read_text())
            if re.match(r"^[A-Z]{2,3}-\d", k)]
    assert keys, f"{filename} has no control-shaped keys — has its format changed?"
    unresolved = sorted(k for k in keys if canonical_control_id(k) not in catalog)
    assert not unresolved, (
        f"{filename}: {len(unresolved)} of {len(keys)} keys name no control in the "
        f"NIST catalogue, e.g. {unresolved[:5]}")


def test_the_knowledge_bases_are_keyed_the_way_the_lookups_expect():
    """End to end through the loader, not just the helper."""
    from app.services.remediation_optimizer import _kb

    kb = _kb()
    catalog = _nist_catalog_ids()
    for name in ("baselines", "guidance", "cis"):
        index = kb[name]
        assert index, f"{name} knowledge base is empty"
        control_keys = [k for k in index if re.match(r"^[A-Z]{2,3}-\d", k)]
        stray = [k for k in control_keys if k not in catalog]
        assert not stray, f"{name} still holds unjoinable keys: {stray[:5]}"


def test_an_enhancement_now_carries_its_baseline_tier():
    """The user-visible symptom: NIST places AC-2(1) in the MODERATE and HIGH
    baselines, and the plan reported it as having none."""
    from app.services.remediation_optimizer import _kb

    tiers = _kb()["baselines"].get("AC-2(1)")
    assert tiers, "AC-2(1) has no baseline tiers — the join is still missing"
    assert {"MODERATE", "HIGH"} & set(tiers), tiers

    # Reachable by either spelling, because callers pass both.
    assert _kb()["baselines"].get(canonical_control_id("AC-2.1")) == tiers


def test_the_dependency_graph_holds_one_node_per_control():
    """`AC-6(7)` from the concept lexicon and `AC-6.7` from nist_related were
    two nodes. A cascade that reached one could not continue through the
    other."""
    from app.services import dependency_graph as dg

    graph = dg._graph()
    dotted = sorted(n for n in graph if re.match(r"^[A-Z]{2,3}-\d+\.\d+$", n))
    assert not dotted, f"graph still has dotted nodes alongside canonical ones: {dotted[:5]}"

    # And a lookup by either spelling reaches the same node.
    for node in list(graph)[:200]:
        m = re.match(r"^([A-Z]{2,3}-\d+)\((\d+)\)$", node)
        if not m:
            continue
        assert dg.out_edges(f"{m.group(1)}.{m.group(2)}") == dg.out_edges(node)
        break
    else:
        pytest.skip("no enhancement nodes in the graph to check")
