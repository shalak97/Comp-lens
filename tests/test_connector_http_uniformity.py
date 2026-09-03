"""Every connector goes through the hardened client — and that stays true.

`http_client`'s docstring claims that connectors talking to an external API get
timeouts, retries, backoff, 429 handling, a circuit breaker, SSRF blocking,
read-only enforcement and credential redaction, uniformly. For a while that
claim was false: github.py, jira.py, security_tools.py and most of
secondary.py called `requests` directly, so eleven connectors had a timeout and
none of the rest.

The cause was a rule that was too absolute to keep. Read-only enforcement
blocked POST outright, which is right for anything that changes a customer's
estate — but an OAuth2 token exchange and a GraphQL query are POSTs by
protocol and cannot be anything else. A connector needing one could not use
`ResilientClient` at all, so it used raw `requests` for *everything* and lost
the guarantees on its ordinary GETs too. The rule was strong enough to be
routed around, which is the weakest kind of rule.

So `post_read()` takes a declared `ReadIntent` — TOKEN or QUERY, nothing else —
and the general `request()`/`get()` path still refuses POST. The intent is not
verifiable (no client can know what a server does with a body); what it buys is
that every read-shaped POST is greppable, and that reaching for the general
path cannot make a mutating call by accident.

The last test here is the one that matters over time: it walks the connector
package and fails if a new connector reaches for `requests` directly, so the
docstring cannot quietly become false again.
"""
from __future__ import annotations

import ast
import pathlib
from unittest.mock import MagicMock, patch

import pytest

from app.connectors.base import ConnectorError
from app.connectors.http_client import ReadIntent, ResilientClient, _breaker_for, _breakers

CONNECTOR_DIR = pathlib.Path(__file__).resolve().parent.parent / "app" / "connectors"


def setup_function():
    _breakers.clear()


def _response(status=200, body=None, text="", headers=None):
    m = MagicMock()
    m.status_code = status
    m.headers = headers or {}
    m.text = text
    if body is None:
        m.json.side_effect = ValueError("not json")
    else:
        m.json.return_value = body
    return m


# ── the read-only boundary, and the one hole in it ──
def test_a_bare_post_is_still_refused():
    """The rule that keeps a connector from changing a customer's estate."""
    with pytest.raises(ConnectorError) as e:
        ResilientClient(service="T").request("POST", "https://api.example.com/x")
    assert "read-only" in str(e.value)


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_no_other_write_verb_has_a_way_through(method):
    with pytest.raises(ConnectorError):
        ResilientClient(service="T").request(method, "https://api.example.com/x")


def test_post_read_requires_a_declared_intent():
    """The exception must be opted into by name, not by passing a truthy flag."""
    c = ResilientClient(service="T")
    for bogus in ("token", True, 1, None):
        with pytest.raises(ConnectorError) as e:
            c.post_read("https://api.example.com/x", intent=bogus)
        assert "ReadIntent" in str(e.value)


@pytest.mark.parametrize("intent", list(ReadIntent))
def test_a_declared_read_post_is_allowed(intent):
    c = ResilientClient(service="PR", max_retries=0)
    with patch.object(c.session, "request",
                      return_value=_response(body={"access_token": "t"})) as sent:
        assert c.post_read("https://api.example.com/oauth", intent=intent,
                           data={"grant_type": "client_credentials"}) == {"access_token": "t"}
    assert sent.call_args.args[0] == "POST"
    assert sent.call_args.kwargs["data"] == {"grant_type": "client_credentials"}


def test_the_intent_vocabulary_stays_small():
    """A member for anything other than "get a credential" or "ask a question"
    would be a write with permission to call itself a read."""
    assert {i.name for i in ReadIntent} == {"TOKEN", "QUERY"}


def test_a_read_post_still_gets_the_guarantees():
    """The whole point of routing tokens through here rather than around it."""
    c = ResilientClient(service="PRG", max_retries=0)
    with patch.object(c.session, "request",
                      return_value=_response(401, text='{"error":"bad SSWS leaked123"}')):
        with pytest.raises(ConnectorError) as e:
            c.post_read("https://api.example.com/oauth", intent=ReadIntent.TOKEN)
    assert "leaked123" not in str(e.value), "a token exchange leaked a credential"

    with pytest.raises(ConnectorError) as e:
        c.post_read("http://169.254.169.254/latest/api/token", intent=ReadIntent.TOKEN)
    assert "internal/metadata" in str(e.value), "a token POST bypassed the SSRF guard"


# ── absence versus failure ──
def test_not_found_ok_reports_absence_rather_than_raising():
    """GitHub answers "branch protection is not configured" with a 404. That is
    an observation about the asset, not a failed call, and a control that
    cannot tell them apart reports the wrong thing."""
    c = ResilientClient(service="NF", max_retries=0)
    with patch.object(c.session, "request", return_value=_response(404, text="nope")):
        assert c.get("https://api.example.com/x", not_found_ok=True) is None


def test_a_404_is_still_an_error_when_it_was_not_expected():
    c = ResilientClient(service="NF2", max_retries=0)
    with patch.object(c.session, "request", return_value=_response(404, text="nope")):
        with pytest.raises(ConnectorError):
            c.get("https://api.example.com/x")


def test_an_expected_404_does_not_trip_the_circuit_breaker():
    """Otherwise a repo with no branch protection would look like an outage and
    take the whole GitHub connector offline."""
    c = ResilientClient(service="NF3", max_retries=0)
    with patch.object(c.session, "request", return_value=_response(404)):
        for _ in range(10):
            assert c.get("https://api.example.com/x", not_found_ok=True) is None
    assert not _breaker_for("NF3").is_open


# ── shapes real APIs actually use ──
def test_a_non_json_body_comes_back_as_text():
    """Qualys answers with XML. Calling that a failure would lose the reading."""
    c = ResilientClient(service="XML", max_retries=0)
    xml = "<HOST><DETECTION/><DETECTION/></HOST>"
    with patch.object(c.session, "request", return_value=_response(text=xml)):
        assert c.get("https://api.example.com/x") == xml


def test_basic_auth_is_forwarded():
    c = ResilientClient(service="AUTH", max_retries=0)
    with patch.object(c.session, "request", return_value=_response(body={})) as sent:
        c.get("https://api.example.com/x", auth=("user", "pass"))
    assert sent.call_args.kwargs["auth"] == ("user", "pass")


def test_credentials_are_not_echoed_when_a_request_fails():
    c = ResilientClient(service="AUTH2", max_retries=0)
    with patch.object(c.session, "request",
                      return_value=_response(403, text='{"api_key": "supersecret"}')):
        with pytest.raises(ConnectorError) as e:
            c.get("https://api.example.com/x", auth=("user", "hunter2"))
    assert "supersecret" not in str(e.value)


# ── the invariant, enforced against the source ──
def _module_calls_requests_directly(path: pathlib.Path) -> list[str]:
    """Network calls made on the `requests` module rather than through the client.

    `requests.utils.quote` and `google.auth.transport.requests` are not network
    calls, so only the verb functions count.
    """
    verbs = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
    found = []
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if (isinstance(fn, ast.Attribute) and fn.attr in verbs
                and isinstance(fn.value, ast.Name) and fn.value.id == "requests"):
            found.append(f"requests.{fn.attr} at line {node.lineno}")
    return found


def test_no_connector_calls_requests_directly():
    """The claim in http_client's docstring, enforced.

    A new connector written the obvious way — `requests.get(url, timeout=...)` —
    silently opts out of every guarantee the package advertises. This is the
    test that stops that being discovered a year later during an incident.
    """
    offenders = {}
    for path in sorted(CONNECTOR_DIR.glob("*.py")):
        if path.name == "http_client.py":      # the one module that may
            continue
        calls = _module_calls_requests_directly(path)
        if calls:
            offenders[path.name] = calls
    assert not offenders, (
        "connectors bypassing ResilientClient — they get a timeout and none of "
        f"the retry, breaker, SSRF or redaction behaviour: {offenders}")


def test_every_http_connector_builds_a_resilient_client():
    """The other half: not importing `requests` is not the same as using the
    client. A connector that talks HTTP must hold one."""
    # AWS goes through boto3 (its own retry/timeout config), and these three
    # make no HTTP calls at all.
    NON_HTTP = {"AWSConnector", "MockConnector", "LegacyConnector",
                "AIGovernanceConnector", "SSHLinuxConnector"}

    missing = []
    for path in sorted(CONNECTOR_DIR.glob("*.py")):
        source = path.read_text()
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(getattr(b, "id", "") == "BaseConnector" for b in node.bases):
                continue
            if node.name in NON_HTTP:
                continue
            body = ast.get_source_segment(source, node) or ""
            if "ResilientClient(" not in body:
                missing.append(f"{path.name}:{node.name}")
    assert not missing, f"HTTP connectors with no ResilientClient: {missing}"


def test_the_read_shaped_posts_are_few_and_named():
    """Every POST any connector makes, in one list.

    If this number grows, someone is expressing writes as reads, and the review
    that catches it starts here.
    """
    posts = []
    for path in sorted(CONNECTOR_DIR.glob("*.py")):
        source = path.read_text()
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "post_read"):
                intent = next((k.value for k in node.keywords if k.arg == "intent"), None)
                posts.append(f"{path.name}:{node.lineno}:"
                             f"{getattr(intent, 'attr', '?')}")
    # Azure, Wiz and CrowdStrike exchange OAuth2 credentials; Wiz queries
    # GraphQL and Qualys requests an XML report.
    assert len(posts) == 5, f"unexpected set of read-shaped POSTs: {posts}"
    assert sum(1 for p in posts if p.endswith("TOKEN")) == 3
    assert sum(1 for p in posts if p.endswith("QUERY")) == 2
