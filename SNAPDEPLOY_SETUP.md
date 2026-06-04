# Deploy Comp-Lens on SnapDeploy (free, no credit card)

SnapDeploy runs your Docker container with no card required. It has no free
database, so you pair it with **Neon** (free Postgres, also no card). Total
cost: **$0**.

> **One caveat:** free containers sleep after ~45 min idle and wake in 10–30s.
> The app works on demand, but the background scheduler won't run continuously.
> Keep `ENABLE_SCHEDULER=false` and trigger assessments yourself (see step 6).
> For 24/7, upgrade to SnapDeploy Always-On ($12/mo) and flip the scheduler on.

---

## Before you start — your repo must be deploy-ready

SnapDeploy builds from your `Dockerfile`. That means the earlier repo fixes
must already be committed to `shalak97/Comp-lens-2.0`:

- source moved into `app/`, alembic into `alembic/` (run `reorganize.sh`)
- the full `requirements.txt`
- the updated `Dockerfile` (the one that `COPY`s `alembic/` and runs
  `alembic upgrade head` on start)

If you haven't pushed those yet, do that first — nothing below will build
without them.

---

## Step 1 — Create a free Neon database

1. Go to **https://neon.tech** → sign up (GitHub login, no card).
2. Create a project (any name, any region — pick the one near your users).
3. Open **Connection Details** and copy the connection string. It looks like:
   ```
   postgresql://alex:npg_xxx@ep-cool-bird-12345.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
4. **Change the prefix** from `postgresql://` to `postgresql+psycopg://`
   (this app uses the psycopg3 driver). Keep `?sslmode=require`. Final:
   ```
   postgresql+psycopg://alex:npg_xxx@ep-cool-bird-12345.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
   Save this — it's your `DATABASE_URL`.

---

## Step 2 — Create the SnapDeploy service

1. Go to **https://snapdeploy.dev** → sign up (no card).
2. **New → Deploy from GitHub** → authorize and pick `shalak97/Comp-lens-2.0`.
3. Build method: **Dockerfile** (it auto-detects your `Dockerfile`).
4. Branch: `main`. Leave the build context as the repo root.

Don't deploy yet — set the environment variables first.

---

## Step 3 — Set environment variables

In the service's **Environment Variables** section, add the values from
`.env.snapdeploy.example`. The minimum to get running:

| Key | Value |
|---|---|
| `APP_ENV` | `production` |
| `DATABASE_URL` | your Neon string from Step 1 (the `postgresql+psycopg://…` one) |
| `AUTO_CREATE_TABLES` | `false` |
| `ENABLE_SCHEDULER` | `false` |
| `EVIDENCE_BACKEND` | `local` |
| `EVIDENCE_LOCAL_PATH` | `/app/evidence_store` |

Do **not** set `PORT` — SnapDeploy injects it, and the Dockerfile already
listens on `${PORT:-8000}`.

---

## Step 4 — Deploy

Click **Deploy**. SnapDeploy will:

1. Build the image from your `Dockerfile`
2. Start the container, which runs `alembic upgrade head` against Neon
   (creating your schema on first boot), then starts the API.

Watch the build/deploy logs. A healthy start ends with a uvicorn line like
`Uvicorn running on http://0.0.0.0:<port>`.

When it's live you get a URL like `https://comp-lens-xxxx.snapdeploy.app`.

---

## Step 5 — Verify it works

- API docs:   `https://your-app.snapdeploy.app/docs`
- 3D dashboard: `https://your-app.snapdeploy.app/ontology`
  *(only if you committed `ontology-3d.html` into `app/static/` and wired the
  `/ontology` route — see `FRONTEND_SETUP.md`. Otherwise open the HTML locally
  and point its gear icon at the SnapDeploy URL.)*
- Health:    `https://your-app.snapdeploy.app/health/live` → should return ok

Run a demo assessment (no credentials needed — uses the DEMO connector):
```bash
curl -X POST https://your-app.snapdeploy.app/assessments \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"acme","control_id":"SC-7","source_system":"DEMO","asset_id":"my-bucket"}'
```

---

## Step 6 — Run assessments without the scheduler

Because the scheduler is off, trigger runs yourself one of two ways:

**A. Manually / from your own scripts** — `POST /assessments` (single) or
`POST /assessment-jobs` (batch), as above.

**B. Free external cron** — point a free scheduler (e.g. cron-job.org,
GitHub Actions on a schedule) at:
```
POST https://your-app.snapdeploy.app/schedules/{id}/run
```
This also wakes the container if it's asleep, so your checks still happen on a
cadence without paying for Always-On.

---

## When you outgrow the free tier

Flip two things and you have a continuous platform:

1. SnapDeploy service → **Always-On** ($12/mo) — no more sleeping.
2. Set `ENABLE_SCHEDULER=true` and redeploy — the background runner now runs 24/7.

Neon stays free. Total then is $12/mo, still no separate DB bill.

---

## Quick troubleshooting

- **Build fails immediately** → the repo isn't reorganized; `Dockerfile` can't
  find `app/` or `alembic/`. Run `reorganize.sh`, commit, push, redeploy.
- **App boots then crashes on DB** → `DATABASE_URL` prefix is still
  `postgresql://`. It must be `postgresql+psycopg://`.
- **`SSL required` / connection refused to Neon** → make sure `?sslmode=require`
  is still on the end of the string.
- **Evidence disappears after a redeploy** → expected on free local storage.
  Use `EVIDENCE_BACKEND=s3` for durable evidence (needs AWS).
- **First request after idle is slow** → that's the 10–30s wake from sleep.
  Normal on the free tier.
