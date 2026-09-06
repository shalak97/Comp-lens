"""The same defect as aws.py, in the connector next door.

After fixing three signals in aws.py I asked where the next ones would be, and
answered it with a count: `secondary.py` coerced 25 pack signals to a definite
value, more than aws.py had. This is what was actually there.

`ConnectorError` is ResilientClient's single failure type — a 403 from an
under-provisioned role, a 429, an open circuit, a timeout and a genuine 404 all
arrive identically. Two helpers caught it and answered False:

    _has_management_policy  -> lifecycle_configured   SI-12-OBJSTORE-LIFECYCLE
    _entra_only_auth        -> (not yet read by the pack, but latent)

and one loop left its False default when it could not read anything:

    _virtual_machine_telemetry -> public_ip_assigned  SC-7-COMPUTE-PUBLIC-IP

That last one is the one worth pausing on. **Every other instance of this bug
found in this codebase over-reported — invented a violation. This one
under-reported.** A VM whose NICs could not be read was announced as having no
public IP, so a host that may well be internet-facing passed the control that
exists to catch exactly that. A fabricated finding wastes an afternoon; a
suppressed one is the failure this product is sold to prevent.

The file already knew the distinction in three places — `_has_delete_lock`
returns None and logs, `_sql_server_telemetry` sets its signal to None,
`_vnet_telemetry` omits signals entirely. `_has_delete_lock` and
`_entra_only_auth` sit ten lines apart, one right and one wrong, and
`_entra_only_auth`'s own annotation said `bool | None` while its body could
never return None.

`not_found_ok=True` was already on ResilientClient for precisely this, and
github.py already used it. It just had not reached here.
"""
from __future__ import annotations

import ast
import logging
import pathlib
import textwrap

import pytest

SRC = pathlib.Path(__file__).resolve().parent.parent / "app" / "connectors" / "secondary.py"
CONNECTORS = SRC.parent


class _ConnectorError(Exception):
    pass


def _load():
    """Lift the helpers out of the class so they run without azure/google SDKs."""
    src = SRC.read_text()
    tree = ast.parse(src)
    ns: dict = {"ConnectorError": _ConnectorError,
                "logger": logging.getLogger("test.azure"),
                "settings": type("S", (), {"azure_subscription_id": "sub"})()}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in ("_tri", "_sub_relative"):
            exec(ast.get_source_segment(src, node), ns)  # noqa: S102
    cls = next(n for n in tree.body
               if isinstance(n, ast.ClassDef) and n.name == "AzureConnector")
    for node in cls.body:
        if isinstance(node, ast.FunctionDef) and node.name in (
                "_has_management_policy", "_entra_only_auth"):
            code = textwrap.dedent(ast.get_source_segment(src, node))
            exec(code.replace("@staticmethod\n", ""), ns)  # noqa: S102
    return ns


NS = _load()


class _Azure:
    """`mode` picks which answer ARM gives."""

    def __init__(self, mode):
        self.mode = mode

    def _arm(self, path, api_version=None, *, not_found_ok=False):
        if self.mode == "denied":
            raise _ConnectorError("AZURE: 403 Forbidden — role lacks Storage read")
        if self.mode == "throttled":
            raise _ConnectorError("AZURE: 429 Too Many Requests")
        if self.mode == "circuit":
            raise _ConnectorError("AZURE: circuit open — service failing, backing off")
        if self.mode == "404":
            if not_found_ok:
                return None
            raise _ConnectorError("AZURE: HTTP 404")
        if "managementPolicies" in path:
            return {"properties": {"policy": {"rules": [{"name": "expire"}]}}}
        return {"properties": {"azureADOnlyAuthentication": True}}

    _has_management_policy = NS["_has_management_policy"]
    _entra_only_auth = NS["_entra_only_auth"]


HELPERS = ["_has_management_policy", "_entra_only_auth"]
FAILURES = ["denied", "throttled", "circuit"]


@pytest.mark.parametrize("helper", HELPERS)
@pytest.mark.parametrize("mode", FAILURES)
def test_a_failed_read_reports_nothing(helper, mode):
    """The regression: every one of these used to answer False."""
    conn = _Azure(mode)
    args = ("rg", "acct") if helper == "_has_management_policy" else ("/servers/s",)
    assert getattr(conn, helper)(*args) is None, (
        f"{helper} answered a control question after a {mode} failure")


@pytest.mark.parametrize("helper", HELPERS)
def test_a_genuine_404_is_still_a_real_answer(helper):
    """The half a careless fix would break. ARM 404s when the setting does not
    exist, and that IS an observed negative — the original reasoning was right
    as far as it went."""
    conn = _Azure("404")
    args = ("rg", "acct") if helper == "_has_management_policy" else ("/servers/s",)
    assert getattr(conn, helper)(*args) is False


@pytest.mark.parametrize("helper", HELPERS)
def test_a_configured_resource_still_passes(helper):
    conn = _Azure("ok")
    args = ("rg", "acct") if helper == "_has_management_policy" else ("/servers/s",)
    assert getattr(conn, helper)(*args) is True


# ── the three-state property read ──
@pytest.mark.parametrize(("value", "want"), [(True, True), (False, False), (None, None)])
def test_tri_keeps_an_absent_property_absent(value, want):
    assert NS["_tri"](value) is want


@pytest.mark.parametrize(("value", "want"), [(True, False), (False, True), (None, None)])
def test_tri_inverts_without_inventing(value, want):
    """`allowBlobPublicAccess` inverts into `public_access_blocked`, which drives
    a CRITICAL control. An absent property must not become "public"."""
    assert NS["_tri"](value, invert=True) is want


# ── the class, across every connector ──
def test_no_connector_helper_promises_a_bool_it_cannot_know():
    """A helper that swallows ConnectorError and returns a bare True/False is
    turning "the call failed" into a control verdict. Catching the shape here
    is worth more than the three fixes above, because it covers the connector
    written next."""
    offenders = []
    for path in CONNECTORS.glob("*.py"):
        tree = ast.parse(path.read_text())
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for handler in [n for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler)]:
                name = ast.unparse(handler.type) if handler.type else "bare"
                if "ConnectorError" not in name and name != "Exception":
                    continue
                for stmt in handler.body:
                    if (isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant)
                            and stmt.value.value in (True, False)
                            and not fn.name.startswith("healthcheck")):
                        offenders.append(
                            f"{path.name}:{stmt.lineno} {fn.name} returns "
                            f"{stmt.value.value!r} on {name}")
    assert not offenders, (
        "a connector answers a control question after a failed call. Return None "
        "so the check reports NOT_APPLICABLE, or use not_found_ok=True to "
        f"separate a real 404 from everything else: {offenders}")


def test_the_client_still_offers_the_mechanism_this_relies_on():
    """`not_found_ok` is what separates "ARM says no" from "we could not ask".
    If it were removed, the fixes above would silently lose their distinction."""
    import inspect

    from app.connectors.http_client import ResilientClient
    assert "not_found_ok" in inspect.signature(ResilientClient.get).parameters
