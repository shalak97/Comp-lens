"""The custom Semgrep rules must be well-formed.

`.semgrep/comp-lens.yml` is checked by `semgrep scan --validate` in
.github/workflows/semgrep.yml, but that job is advisory and runs after this
one. This file moves the check into the blocking gate, and it exists because
the failure it catches actually happened on the first run:

    [ERROR] Pattern parse error in rule
            comp-lens-filesystem-probe-inside-permission-handler:
     Invalid pattern for Python:
    --- pattern ---
    except PermissionError:
        ...
        $P.exists()
    --- end pattern ---
    Pattern error: Stdlib.Parsing.Parse_error

A bare `except ...:` block is not a parseable Python fragment; the handler has
to be written with its `try:`. The important part is what semgrep does next —
ONE malformed pattern invalidates the WHOLE configuration, so all nine rules
stop running. A rule file that silently reviews nothing is worse than no rule
file, because the green tick says otherwise.

Semgrep itself is not a dependency here and is not installed by the test job;
these checks are the ones that can be made without it. Every pattern is
rewritten into ordinary Python (metavariables become identifiers, `...` is
already legal as Ellipsis) and handed to `ast.parse`, which is a good enough
proxy for the parser error above.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml")

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULE_FILE = ROOT / ".semgrep" / "comp-lens.yml"

#: Keys whose value is a literal pattern rather than a nested structure.
PATTERN_KEYS = {"pattern", "pattern-not", "pattern-inside", "pattern-not-inside"}


def _patterns(node) -> list[str]:
    """Every literal pattern string anywhere inside a rule, at any depth."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in PATTERN_KEYS and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_patterns(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_patterns(value))
    return found


@pytest.fixture(scope="module")
def rules() -> list[dict]:
    document = yaml.safe_load(RULE_FILE.read_text())
    return document["rules"]


def test_the_rule_file_is_valid_yaml(rules):
    assert rules, "no rules loaded"


def test_every_pattern_is_parseable_python(rules):
    """The exact failure that broke the first run.

    One bad pattern takes the other eight down with it, so this is not a
    cosmetic check on one rule — it is the difference between the whole file
    running and none of it running.
    """
    broken = []
    for rule in rules:
        for pattern in _patterns(rule):
            # $UPPERCASE metavariables are not valid identifiers; everything
            # else in a semgrep pattern, `...` included, already is.
            source = re.sub(r"\$([A-Z_][A-Z0-9_]*)", r"MV_\1", pattern)
            try:
                ast.parse(source)
            except SyntaxError as exc:
                broken.append(f"{rule['id']}: {exc}\n    "
                              + source.replace("\n", "\n    "))
    assert not broken, (
        "these patterns are not parseable Python, so semgrep rejects the "
        "entire configuration and all rules stop running:\n"
        + "\n".join(broken))


def test_every_rule_has_the_fields_semgrep_requires(rules):
    for rule in rules:
        missing = {"id", "languages", "severity", "message"} - set(rule)
        assert not missing, f"{rule.get('id', '<unnamed>')} is missing {missing}"
        assert rule["severity"] in {"ERROR", "WARNING", "INFO"}, rule["id"]
        assert any(key in rule for key in ("pattern", "patterns", "pattern-either")), (
            f"{rule['id']} matches nothing")


def test_rule_ids_are_unique(rules):
    """Semgrep keeps the last definition silently, so a copy-pasted id
    disables the rule above it."""
    ids = [rule["id"] for rule in rules]
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    assert not duplicates, f"duplicate rule ids: {duplicates}"


def test_every_rule_explains_the_bug_it_came_from(rules):
    """These rules earn their place by naming a mistake made in this
    repository. A one-line message that only restates the pattern gets muted,
    and a muted rule mutes the useful ones next to it."""
    thin = [rule["id"] for rule in rules if len(rule["message"].split()) < 25]
    assert not thin, (
        "these messages are too short to tell a reader what went wrong and "
        f"what to do instead: {thin}")


def test_path_filters_are_anchored(rules):
    """Semgrep warned on the first run that an unanchored `paths.include` is
    about to change meaning:

        contains an include pattern 'app/connectors/' that will soon be
        interpreted as '/app/connectors/' to comply with the Semgrepignore v2
        and Gitignore specifications.

    Anchored is what these rules want — `app/` here means the `app/` package at
    the repository root, not any directory called `app` at any depth. Writing
    the leading slash makes that explicit, so a future release cannot silently
    change which files a security rule reads.
    """
    unanchored = []
    for rule in rules:
        for pattern in rule.get("paths", {}).get("include", []):
            if not pattern.startswith(("/", "**")):
                unanchored.append(f"{rule['id']}: {pattern}")
    assert not unanchored, (
        "these path filters will change meaning in a future semgrep release; "
        f"write '/app/...' to pin the current behaviour: {unanchored}")


def test_the_workflow_validates_before_it_scans():
    """The scan step is `continue-on-error`, so without a separate validating
    step a configuration error would be swallowed and the job would go green
    over a linter that reviewed nothing."""
    workflow = (ROOT / ".github" / "workflows" / "semgrep.yml").read_text()
    assert "--validate" in workflow
    validate_at = workflow.index("--validate")
    scan_at = workflow.index("--sarif")
    assert validate_at < scan_at, "the validating step must run first"
    # and it must NOT be advisory
    assert "continue-on-error" not in workflow[:validate_at].rsplit("- name:", 1)[-1], (
        "the validating step is marked continue-on-error, which defeats it")


def test_the_workflow_cannot_incur_a_cost():
    """`semgrep ci` requires a SEMGREP_APP_TOKEN and pulls policy from a hosted
    service. `semgrep scan` is the open-source engine and needs no account.
    This repo must stay free.

    Comments are stripped first, and the first version of this test was not
    doing that — so it failed on the workflow's own comment explaining why
    `semgrep ci` is NOT used. Prose about a mistake is not the mistake.
    """
    workflow = (ROOT / ".github" / "workflows" / "semgrep.yml").read_text()
    directives = "\n".join(line for line in workflow.splitlines()
                           if not line.lstrip().startswith("#"))
    assert "semgrep ci" not in directives, (
        "semgrep ci needs a hosted account; use semgrep scan")
    assert "SEMGREP_APP_TOKEN" not in directives
    assert "semgrep scan" in directives
