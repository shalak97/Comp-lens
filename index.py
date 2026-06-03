from datetime import datetime, timezone
from typing import Optional
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="Comp-Lens GRC Platform",
    version="2.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Comp-Lens Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;min-height:100vh;padding:24px;color:#222}
.wrap{max-width:1100px;margin:0 auto}
header{background:#fff;padding:24px;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:24px}
h1{color:#5b4bd6;font-size:1.9rem;margin-bottom:4px}
.sub{color:#666;font-size:.95rem}
.badge{display:inline-block;padding:6px 14px;border-radius:20px;margin-top:12px;font-weight:600;font-size:.85rem}
.ok{background:#d4edda;color:#155724}.bad{background:#f8d7da;color:#721c24}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:20px}
.card{background:#fff;padding:20px;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.1)}
.card h2{color:#5b4bd6;font-size:1.1rem;margin-bottom:12px;padding-bottom:8px;border-bottom:2px solid #ede9ff}
button{padding:9px 16px;background:#5b4bd6;color:#fff;border:none;border-radius:6px;cursor:pointer;margin:4px 4px 0 0;font-weight:600;font-size:.9rem;transition:background .2s}
button:hover{background:#4a3cc0}
button.red{background:#dc3545}button.red:hover{background:#b02a37}
.resp{border-left:4px solid #5b4bd6;padding:12px;margin-top:12px;border-radius:0 6px 6px 0;max-height:260px;overflow:auto;font-size:.82rem;background:#f8f7ff;display:none}
.resp.ok{border-color:#28a745;background:#f3fff4}
.resp.err{border-color:#dc3545;background:#fff5f5;color:#721c24}
pre{white-space:pre-wrap;word-break:break-word}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{background:#f5f5f5;padding:8px;text-align:left;border-bottom:2px solid #ddd}
td{padding:8px;border-bottom:1px solid #eee}
.score{font-size:2.8rem;font-weight:700;text-align:center;margin:8px 0}
code{background:#eee;padding:2px 6px;border-radius:3px;font-size:.82rem}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Comp-Lens Dashboard</h1>
    <p class="sub">Compliance &amp; risk assessment &mdash; running on Vercel</p>
    <span id="badge" class="badge bad">Checking&hellip;</span>
  </header>
  <div class="grid">
    <div class="card">
      <h2>Connection</h2>
      <p>API: <code id="apiBase"></code></p>
      <button onclick="testConn()">Test connection</button>
      <div id="r0" class="resp"></div>
    </div>
    <div class="card">
      <h2>Controls</h2>
      <button onclick="loadControls()">Load controls</button>
      <div id="r1" class="resp"></div>
    </div>
    <div class="card">
      <h2>Run assessment</h2>
      <button onclick="runAssess(false)">Run (pass)</button>
      <button class="red" onclick="runAssess(true)">Run (fail)</button>
      <div id="r2" class="resp"></div>
    </div>
    <div class="card">
      <h2>Compliance summary</h2>
      <button onclick="loadSummary()">Load summary</button>
      <div id="r3" class="resp"></div>
    </div>
    <div class="card">
      <h2>Connectors</h2>
      <button onclick="loadConnectors()">Load connectors</button>
      <div id="r4" class="resp"></div>
    </div>
    <div class="card">
      <h2>Findings</h2>
      <button onclick="loadFindings()">Load findings</button>
      <div id="r5" class="resp"></div>
    </div>
  </div>
</div>
<script>
const BASE = window.location.origin;
document.getElementById('apiBase').textContent = BASE + '/api';

function show(id, success, html) {
  const el = document.getElementById(id);
  el.style.display = 'block';
  el.className = 'resp ' + (success ? 'ok' : 'err');
  el.innerHTML = html;
}

async function api(path, method, body) {
  const opts = { method: method || 'GET', headers: {'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(BASE + path, opts);
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

async function testConn() {
  try {
    const d = await api('/api/health/live');
    show('r0', true, '<strong>Connected</strong><pre>' + JSON.stringify(d, null, 2) + '</pre>');
    const b = document.getElementById('badge');
    b.className = 'badge ok'; b.textContent = 'Connected';
  } catch(e) {
    show('r0', false, 'Failed: ' + e.message);
    const b = document.getElementById('badge');
    b.className = 'badge bad'; b.textContent = 'Unavailable';
  }
}

async function loadControls() {
  try {
    const d = await api('/api/controls');
    let t = '<table><tr><th>ID</th><th>Title</th><th>Frameworks</th></tr>';
    d.forEach(c => t += '<tr><td>' + c.control_id + '</td><td>' + c.title + '</td><td>' + c.frameworks.join(', ') + '</td></tr>');
    show('r1', true, t + '</table>');
  } catch(e) { show('r1', false, e.message); }
}

async function runAssess(fail) {
  try {
    const d = await api('/api/assessments', 'POST', {
      tenant_id: 'demo', control_id: fail ? 'SC-28' : 'SC-7',
      source_system: 'DEMO', fail: fail
    });
    show('r2', true, '<strong>' + d.result + '</strong><pre>' + JSON.stringify(d, null, 2) + '</pre>');
  } catch(e) { show('r2', false, e.message); }
}

async function loadSummary() {
  try {
    const d = await api('/api/summary?tenant_id=demo');
    const col = d.compliance_score >= 80 ? '#28a745' : '#dc3545';
    show('r3', true,
      '<div class="score" style="color:' + col + '">' + d.compliance_score + '%</div>' +
      '<pre>' + JSON.stringify(d, null, 2) + '</pre>');
  } catch(e) { show('r3', false, e.message); }
}

async function loadConnectors() {
  try {
    const d = await api('/api/connectors');
    let t = '<table><tr><th>ID</th><th>Category</th><th>Status</th></tr>';
    d.forEach(c => t += '<tr><td>' + c.id + '</td><td>' + c.category + '</td><td>' + c.status + '</td></tr>');
    show('r4', true, t + '</table>');
  } catch(e) { show('r4', false, e.message); }
}

async function loadFindings() {
  try {
    const d = await api('/api/findings?tenant_id=demo');
    show('r5', true,
      '<strong>Total: ' + d.summary.total + ' | Critical: ' + d.summary.critical + ' | High: ' + d.summary.high + '</strong>' +
      '<pre>' + JSON.stringify(d, null, 2) + '</pre>');
  } catch(e) { show('r5', false, e.message); }
}

testConn();
</script>
</body>
</html>"""


# ── Dashboard ──────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    return _DASHBOARD


# ── Health ─────────────────────────────────────────────────────────────────
@app.get("/api/health/live")
async def liveness():
    return {"status": "alive", "platform": "Vercel", "time": _now()}


# ── Root ───────────────────────────────────────────────────────────────────
@app.get("/api")
async def root():
    return {
        "service": "Comp-Lens GRC Platform",
        "version": "2.0.0",
        "endpoints": [
            "/api/health/live", "/api/controls", "/api/connectors",
            "/api/assessments", "/api/findings", "/api/summary", "/api/docs",
        ],
    }


# ── Controls ───────────────────────────────────────────────────────────────
@app.get("/api/controls")
async def controls(framework: Optional[str] = None):
    data = [
        {"control_id": "SC-7",   "title": "No public exposure",     "frameworks": ["NIST", "ISO27001", "SOC2"]},
        {"control_id": "SC-28",  "title": "Encryption at rest",     "frameworks": ["NIST", "ISO27001"]},
        {"control_id": "AC-2-7", "title": "Privileged account MFA", "frameworks": ["NIST", "SOC2"]},
    ]
    if framework:
        fw = framework.upper()
        data = [c for c in data if fw in [f.upper() for f in c["frameworks"]]]
    return data


# ── Connectors ─────────────────────────────────────────────────────────────
@app.get("/api/connectors")
async def connectors():
    return [
        {"id": "DEMO", "category": "testing",  "status": "healthy",              "maturity": "stable"},
        {"id": "AWS",  "category": "cloud",    "status": "requires_credentials", "maturity": "production-ready"},
        {"id": "OKTA", "category": "identity", "status": "requires_credentials", "maturity": "production-ready"},
    ]


# ── Assessments ────────────────────────────────────────────────────────────
class AssessmentRequest(BaseModel):
    tenant_id: str = "default"
    control_id: str = "SC-7"
    source_system: str = "DEMO"
    asset_id: Optional[str] = None
    fail: bool = False


@app.post("/api/assessments")
async def run_assessment(req: AssessmentRequest):
    passed = not (req.source_system == "DEMO" and req.fail)
    return {
        "assessment_id": f"a-{uuid.uuid4().hex[:8]}",
        "tenant_id": req.tenant_id,
        "control_id": req.control_id,
        "source_system": req.source_system,
        "asset_id": req.asset_id,
        "status": "completed",
        "result": "PASSED" if passed else "FAILED",
        "timestamp": _now(),
    }


# ── Findings ───────────────────────────────────────────────────────────────
@app.get("/api/findings")
async def findings(tenant_id: str = "default"):
    items = [
        {"id": "f-001", "control_id": "SC-7",   "status": "OPEN", "severity": "HIGH"},
        {"id": "f-002", "control_id": "AC-2-7", "status": "OPEN", "severity": "CRITICAL"},
    ]
    return {
        "tenant_id": tenant_id,
        "findings": items,
        "summary": {"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0},
    }


# ── Summary ────────────────────────────────────────────────────────────────
@app.get("/api/summary")
async def summary(tenant_id: str = "default", framework: Optional[str] = None):
    return {
        "tenant_id": tenant_id,
        "framework": framework or "ALL",
        "compliance_score": 87.5,
        "controls_passed": 47,
        "controls_failed": 6,
        "total_controls": 53,
        "last_assessment": _now(),
    }
