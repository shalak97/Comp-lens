# Comp-Lens patch bundle

## Files

- `comp-lens-updated-dashboard.html` — replacement single-file dashboard.
- `comp-lens-dashboard-v2.patch` — adds the same dashboard as `app/static/dashboard-v2.html`.
- `comp-lens-production-hardening.patch` — targeted backend/config hardening patch.

## Fastest dashboard install

```bash
cd Comp-lens-2.0
cp app/static/dashboard.html app/static/dashboard.backup.html
cp /path/to/comp-lens-updated-dashboard.html app/static/dashboard.html
```

Then run:

```bash
uvicorn app.main:app --reload --port 8000
# open http://localhost:8000/dashboard
```

## Git patch install

```bash
cd Comp-lens-2.0
git apply /path/to/comp-lens-dashboard-v2.patch
cp app/static/dashboard-v2.html app/static/dashboard.html

git apply /path/to/comp-lens-production-hardening.patch
python -m pytest tests/ -q
```

## Notes

The dashboard is intentionally single-file vanilla JS, matching the project README. It calls the existing API surface:

- `/summary`
- `/findings`
- `/connectors/status`
- `/controls`
- `/waivers`
- `/drift`
- `/remediation`
- `/evidence/verify`
- `/evidence/anchors`
- `/ai-systems`
- `/v1/threat/summary`
- `/v1/policy/list`
- `/trust/graph`
- `/reports/csv`, `/reports/pdf`, `/reports/oscal`

If `git apply` fails on the backend hardening patch because your current Python files are compressed into long single lines, apply the same edits manually or reformat with Black first, then apply the patch.
