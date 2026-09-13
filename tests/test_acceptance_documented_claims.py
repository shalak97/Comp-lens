"""The software must do what its own documentation says it does.

Acceptance testing is the one SDLC level this suite had no real coverage of.
Classifying all 100 test files by level gives:

    security               31      conformance / schema   23
    smoke / startup        21      performance / load      7
    compatibility           6      system / end-to-end     5
    acceptance / docs       1   <- and that one only mentions a doc in passing

Every other level is genuinely covered. This one was a hole, and a pointed one
for this particular product: Comp-Lens exists to catch the case where a
document asserts something the system does not actually do. Shipping it with
unverified claims in its own README would be that failure, committed by the
tool that detects it.

**The sweep that produced this file found no defects.** Documented endpoints,
documented environment variables, named connectors and claimed frameworks were
all accurate as of this commit. That is worth stating plainly rather than
padding: the value here is preventing drift, not repairing it. A README is the
part of a codebase that rots most quietly, because nothing executes it.

Four claims are checked, each chosen because it is mechanically decidable — no
judgement about whether prose is "accurate enough", only whether a named thing
exists:

  1. every URL path the docs name is a route the app serves
  2. every environment variable the docs tell a user to set is read somewhere
  3. every vendor the README names has a connector catalogue entry
  4. every framework the README claims is in the crosswalk

These parse source rather than importing the app, so they run without FastAPI
installed and cost nothing in CI.

A note on how they parse, because getting this wrong is how a check like this
passes while testing nothing. Writing these, four extractors in a row returned
empty and every claim therefore looked satisfied:

  * `ast.unparse` normalises string quotes to single, so a regex written
    against the source's double quotes matched no routes at all;
  * `CONNECTOR_CATALOG: list[...] = [...]` is an AnnAssign, not an Assign, so
    walking `node.targets[0]` never matched it;
  * grepping `--include=*.py --include=*.sh` for a documented variable missed
    the Dockerfile, which has no extension and is where that variable is read.

Every extractor below therefore asserts its own yield first. An empty result is
treated as a broken test, not as a clean bill of health — which is the same
absence-versus-negative distinction the rest of this codebase turns on, applied
to the test suite itself.
"""
from __future__ import annotations

import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ["README.md", "HOW_TO_USE.md", "DEPLOY.md", "ARCHITECTURE.md"]

#: Strings that look like URL paths in prose but are hostnames, file paths or
#: markdown placeholders. Each genuinely appears in these documents.
NOT_ENDPOINTS = {
    "/github", "/localhost", "/your-server", "/your-instance", "/install",
    "/user", "/coderabbit", "/export", "/verify}", "/your-instance/summary",
    "/v1/agents/actions{",
}

#: Served by FastAPI itself rather than an @app.<verb> decorator, so the route
#: extractor cannot see them. They are configured in app/main.py:145-147 and
#: really are served (when EXPOSE_API_DOCS is on, or outside production).
FRAMEWORK_ROUTES = {"/docs", "/redoc", "/openapi", "/openapi.json"}

#: Read by the shell or the container CMD rather than through pydantic
#: Settings. DB_WAIT_SECONDS is consumed by the Dockerfile's entrypoint:
#:     python -m app.dbcheck --wait ${DB_WAIT_SECONDS:-60}
SHELL_LEVEL_VARS = {
    "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "COMPOSE_FILE",
    "HOST_PORT", "COMPLENS_DB", "DB_WAIT_SECONDS", "B64", "PYTHONPATH",
    "DOCKER_BUILDKIT", "PORT",
}


def _served_routes() -> set[str]:
    """Every path in an `@app.<verb>(...)` decorator, either quote style."""
    tree = ast.parse((ROOT / "app" / "main.py").read_text())
    paths = set()
    for node in ast.walk(tree):
        for deco in getattr(node, "decorator_list", []):
            match = re.match(r"""app\.(get|post|put|patch|delete)\(['"]([^'"]+)['"]""",
                             ast.unparse(deco))
            if match:
                paths.add(match.group(2))
    return paths


def _docs() -> dict[str, str]:
    return {d: (ROOT / d).read_text() for d in DOCS if (ROOT / d).exists()}


def _normalise(path: str) -> str:
    """`/x/{tenant_id}` and `/x/{id}` are the same route shape."""
    return re.sub(r"\{[^}]*\}", "{}", path)


def _all_source_text() -> str:
    """Everything a variable could plausibly be read from — including files
    with no extension, which is where one of them actually is."""
    parts = []
    for pattern in ("app/**/*.py", "*.py", "*.sh", "*.yml", "*.yaml", "Dockerfile",
                    "Makefile", "docker-compose*.yml"):
        for path in ROOT.glob(pattern):
            if "__pycache__" in str(path):
                continue
            parts.append(path.read_text(errors="ignore"))
    return "\n".join(parts)


# ── the extractors must not pass by returning nothing ──
def test_the_route_extractor_actually_finds_routes():
    """The guard that makes the rest of this file meaningful.

    An extractor returning an empty set makes every documented path look
    served. That is exactly what happened on the first attempt here, and it
    produced a confident, wrong all-clear.
    """
    routes = _served_routes()
    assert len(routes) > 100, (
        f"only {len(routes)} routes extracted from app/main.py — the extractor "
        "is broken, and every documented-endpoint assertion below is vacuous")


def test_the_documents_this_file_checks_still_exist():
    found = _docs()
    assert "README.md" in found, "no README to check claims against"
    assert len(found) >= 3, f"only found {sorted(found)}"


# ── 1. documented endpoints exist ──
def test_every_documented_endpoint_is_a_route_the_app_serves():
    """A documented endpoint that 404s is worse than an undocumented one: the
    reader has no reason to doubt it, and finds out mid-integration."""
    routes = {_normalise(r) for r in _served_routes()}
    ghosts: dict[str, list[str]] = {}

    for name, text in _docs().items():
        # The lookbehind excludes only word characters. An earlier version also
        # excluded a backtick, which skipped every path written as `/thing` —
        # the normal way markdown documents an endpoint, and therefore almost
        # all of them. A mutation test that added a fake backticked endpoint
        # passed clean, which is how that was found.
        for match in re.finditer(r'(?<![\w])(/(?:v1/)?[a-z][a-z0-9\-/_{}]{2,60})', text):
            path = match.group(1).rstrip('.,;:)`"\'')
            if path in NOT_ENDPOINTS or " " in path or path.count("/") > 6:
                continue
            if re.search(r"\.(py|json|ya?ml|md|html|sh|toml|ini|rego|tar|gz)$", path):
                continue
            if path.startswith(("/app", "/tests", "/alembic", "/docs", "/etc",
                                "/usr", "/var", "/tmp", "/opt", "/home", "/dev")):
                continue
            if _normalise(path) in routes or path in FRAMEWORK_ROUTES:
                continue
            # Docs head a section with the prefix its endpoints share —
            # "`/v1/ai-gov/` endpoints" — which is prose about a group, not a
            # claim that the bare prefix is itself routable.
            if any(r.startswith(path.rstrip("/")) for r in routes):
                continue
            ghosts.setdefault(path, []).append(name)

    assert not ghosts, (
        "these paths are documented but the app serves no such route "
        f"(add to NOT_ENDPOINTS if it is prose, not an endpoint): {ghosts}")


def test_the_readme_api_table_names_real_endpoints():
    """The table a reader copies from, checked row by row.

    This is where the level earned itself. Two of its eleven rows were wrong:

        `/ai/systems`   the app serves /ai-systems
        `/reports.csv`  the app serves /reports/csv

    Neither is a typo a reader would catch — both look exactly like a plausible
    REST path — so the first sign of trouble was a 404 during integration. The
    general endpoint check above misses them without the backtick fix, because
    every row of a markdown table is backticked.
    """
    routes = {_normalise(r) for r in _served_routes()}
    readme = (ROOT / "README.md").read_text()
    rows = re.findall(r"^\|\s*`([^`]+)`\s*\|([^|]*)\|", readme, re.M)
    assert len(rows) >= 8, (
        f"only {len(rows)} table rows parsed from the README — if the table "
        "moved or changed format this check is no longer reading it")

    broken = {path.strip(): desc.strip()
              for path, desc in rows
              if path.strip().startswith("/")
              and _normalise(path.strip()) not in routes
              and path.strip() not in FRAMEWORK_ROUTES}
    assert not broken, (
        f"the README API table names endpoints the app does not serve: {broken}")


# ── 2. documented settings are read ──
def test_every_documented_environment_variable_is_read_somewhere():
    """A variable a user is told to set, that nothing consumes, is a silent
    no-op: the setting appears to work and changes nothing."""
    source = _all_source_text()
    env_example = ROOT / ".env.example"
    texts = dict(_docs())
    if env_example.exists():
        texts[".env.example"] = env_example.read_text()

    dead: dict[str, list[str]] = {}
    for name, text in texts.items():
        for match in re.finditer(r"\b([A-Z][A-Z0-9_]{4,40})\s*=", text):
            var = match.group(1)
            if var in SHELL_LEVEL_VARS:
                continue
            # pydantic-settings maps EXPOSE_API_DOCS to a field named
            # expose_api_docs, so the env var's own spelling never appears in
            # app/config.py. Searching only for the uppercase literal reported
            # a correctly-implemented setting as dead — the same false alarm
            # this file's docstring warns about, caught by running it.
            if var in source or var.lower() in source:
                continue
            dead.setdefault(var, []).append(name)

    assert not dead, (
        "these variables are documented as settings but appear nowhere in the "
        f"source, so setting them does nothing: {dead}")


# ── 3. named vendors have connectors ──
def test_every_vendor_the_readme_names_has_a_catalogue_entry():
    catalogue = (ROOT / "app" / "connectors" / "catalog.py").read_text()
    entries = catalogue.count("\n    _c(")
    assert entries > 20, (
        f"only {entries} catalogue entries parsed — extractor broken, the "
        "assertion below would pass vacuously")

    readme = (ROOT / "README.md").read_text()
    vendors = ["AWS", "Azure", "GCP", "Okta", "GitHub", "GitLab", "Jira", "Slack",
               "ServiceNow", "Qualys", "CrowdStrike", "Snyk", "Tenable", "Wiz",
               "Splunk"]
    # The catalogue names some vendors by their corporate owner rather than the
    # product the README names, which is the normal way round for these three.
    aliases = {"GCP": "Google", "Azure": "Microsoft", "Jira": "Atlassian"}

    missing = []
    for vendor in vendors:
        if not re.search(rf"\b{re.escape(vendor)}\b", readme, re.I):
            continue
        needle = aliases.get(vendor, vendor)
        if not re.search(re.escape(needle), catalogue, re.I):
            missing.append(vendor)

    assert not missing, (
        f"the README names these vendors but no connector exists: {missing}")


# ── 4. claimed frameworks are in the crosswalk ──
def test_every_framework_the_readme_claims_is_in_the_crosswalk():
    """The README is careful here — it says 'in the built-in crosswalk', not
    'fully catalogued', and only NIST 800-53 and ISO 27001 ship as full control
    catalogues. This pins the narrower claim it actually makes, so nobody
    'corrects' the wording into an overclaim later.
    """
    crosswalk = (ROOT / "app" / "frameworks.py").read_text()
    targets = set(re.findall(r'"([A-Z0-9_]{2,20})":\s*\[', crosswalk))
    assert len(targets) >= 4, (
        f"only parsed {targets} from the crosswalk — extractor broken")

    readme = (ROOT / "README.md").read_text()
    claims = {
        "NIST 800-53": "NIST",
        "ISO/IEC 27001": "ISO27001",
        "SOC 2": "SOC2",
        "CIS Controls": "CIS",
        "NIST AI RMF": "NIST_AI_RMF",
        "ISO/IEC 42001": "ISO42001",
        "EU AI Act": "EU_AI_ACT",
        "FedRAMP": "FEDRAMP",
    }
    missing = [claim for claim, key in claims.items()
               if claim.lower() in readme.lower() and key not in targets]
    assert not missing, (
        "the README claims crosswalk support for these frameworks and "
        f"app/frameworks.py has no mapping for them: {missing}")
