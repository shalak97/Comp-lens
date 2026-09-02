"""The connector catalog must not present a roadmap as shipped capability.

app/connectors/catalog.py is partly aspirational: over half its entries name a
vendor and the evidence it could supply, but have no connector class behind
them. Every entry took maturity="production" from the default argument of _c(),
so /connectors/catalog reported 44 production integrations where 21 exist.

That is the same failure the rest of the platform is built to avoid — claiming
something evidence does not support. A connector nobody implemented is exactly
the "control nobody can observe" the product warns about, one layer down.

maturity is now derived from the registry at read time rather than asserted in
the table, so it cannot drift from what is actually registered.
"""
from __future__ import annotations

from app.connectors import catalog as cat
from app.connectors.registry import registry


def test_every_entry_reports_whether_it_is_implemented():
    rows = cat.all_connectors()
    assert rows
    for row in rows:
        assert "implemented" in row, f"{row['key']} does not say whether it is implemented"
        assert row["implemented"] in (True, False, None)


def test_implemented_matches_the_registry_exactly():
    """The claim is derived, not declared — so it must agree with reality."""
    live = set(registry.supported())
    for row in cat.all_connectors():
        expected = bool(row.get("registry_key")) and row["registry_key"] in live
        assert row["implemented"] is expected, (
            f"{row['key']}: implemented={row['implemented']} but registry_key="
            f"{row.get('registry_key')!r} and the registry has {sorted(live)}")


def test_unimplemented_entries_are_not_advertised_as_production():
    """The regression. These entries inherited maturity="production" from a
    default argument despite having no code behind them."""
    liars = [r["key"] for r in cat.all_connectors()
             if r["implemented"] is False and r["maturity"] == "production"]
    assert not liars, (
        "catalogued as production-grade with no connector behind them: "
        f"{liars}")


def test_implemented_entries_keep_their_declared_maturity():
    """The fix must not understate either — a shipped connector stays
    production-grade."""
    shipped = [r for r in cat.all_connectors() if r["implemented"]]
    assert shipped, "no connector resolved against the registry at all"
    assert all(r["maturity"] == "production" for r in shipped)


def test_get_annotates_a_single_entry_the_same_way():
    row = cat.get("AWS_IAM")
    assert row is not None
    assert row["implemented"] is True
    assert row["maturity"] == "production"


def test_get_is_case_insensitive_and_returns_none_for_unknown():
    assert cat.get("aws_iam") is not None
    assert cat.get("NOT_A_CONNECTOR") is None


def test_by_category_entries_are_annotated_too():
    cloud = cat.by_category("cloud")
    assert cloud
    assert all("implemented" in r for r in cloud)


def test_annotation_does_not_mutate_the_source_table():
    """all_connectors() returns annotated copies; the module-level table stays
    the declared source of truth."""
    cat.all_connectors()
    assert all("implemented" not in row for row in cat.CONNECTOR_CATALOG)
    assert {row["maturity"] for row in cat.CONNECTOR_CATALOG} == {"production"}


def test_catalog_endpoint_exposes_the_distinction():
    """It has to reach the API, not just the module — the dashboard's
    'Shipped' readout counts on it."""
    import os
    os.environ.setdefault("APP_ENV", "local")
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        rows = c.get("/connectors/catalog").json()
    assert isinstance(rows, list) and rows
    assert any(r.get("implemented") is True for r in rows)
    assert any(r.get("implemented") is False for r in rows), (
        "the catalog ships roadmap entries; the API should say which they are")
