#!/bin/bash
# Run once from your Comp-lens-2.0 repo root.
set -e

echo "=== Step 1: app/ package ==="
mkdir -p app

for f in \
  __init__.py ai_governance.py assessment.py auth.py aws.py base.py \
  config.py database.py engine.py evidence.py forecast.py frameworks.py \
  github.py ingestion.py integrity.py inventory.py jira.py legacy.py \
  main.py mapping.py merkle.py mock.py models.py notifications.py \
  okta.py policy_authoring.py registry.py remediation.py reporting.py \
  retry.py risk.py scheduler.py secondary.py sources.py ssh_linux.py \
  transports.py trends.py waivers.py; do
  [ -f "$f" ] && mv "$f" app/ && echo "  $f → app/"
done

echo ""
echo "=== Step 2: alembic/ structure ==="
mkdir -p alembic/versions

[ -f env.py ]         && mv env.py         alembic/env.py         && echo "  env.py → alembic/"
[ -f script.py.mako ] && mv script.py.mako alembic/script.py.mako && echo "  script.py.mako → alembic/"

# Only move alembic migration files (pattern: <hex12>_<name>.py)
for f in [0-9a-f]*_*.py; do
  [ -f "$f" ] && mv "$f" alembic/versions/ && echo "  $f → alembic/versions/"
done

echo ""
echo "=== Step 3: Move test files to tests/ ==="
mkdir -p tests
for f in test_*.py; do
  [ -f "$f" ] && mv "$f" tests/ && echo "  $f → tests/"
done

echo ""
echo "=== Step 4: Cleanup ==="
rm -f vercel.json index.py
rm -f *.db *.db-shm *.db-wal
echo "  removed vercel.json, index.py, *.db files"

echo ""
echo "=== Done. Structure ==="
echo "app/ ($(ls app/*.py | wc -l) files)"
echo "alembic/ env.py + script.py.mako + versions/$(ls alembic/versions/ | wc -l) migration(s)"
echo "tests/ ($(ls tests/ | wc -l) files)"
echo ""
echo "Next: git add -A && git commit -m 'fix: reorganize into app/ package'"
