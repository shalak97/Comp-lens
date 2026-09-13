#!/usr/bin/env python3
"""Drive the dashboard's write paths in a real browser and print what they send.

    python tools/ui_interactions.py

tools/ui_coverage.py proves every view renders and records what a render pass
fetches. That is only the read half: a create form, a delete button and a file
picker fire on click, so they never appear in a render pass and would otherwise
ship with nothing exercising them at all.

This loads the real dashboard with `fetch` replaced by a recorder, then clicks
through each write path and asserts what it should and should not have sent —
including the refusals (a waiver with no approver, an audit whose period ends
before it starts), because a control that silently accepts bad input is the
same class of defect as one that silently does nothing.

Needs a chromium binary; CI has none. The parts that can be checked without a
browser are in tests/test_dashboard_promises.py.
"""
import html as _html
import json
import pathlib
import re
import shutil
import subprocess

DASH = pathlib.Path("/home/user/Comp-lens/app/static/dashboard.html")
OUT = DASH.parent / ".interact_probe.html"
CHROME = next((c for c in ("/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
                           shutil.which("chromium") or "",
                           shutil.which("chromium-browser") or "",
                           shutil.which("google-chrome") or "")
                if c and pathlib.Path(c).exists()), "")

HEAD = """<script id="ip-head">
window.__calls = []; window.__errs = [];
window.fetch = function(u, o){
  var body = null;
  try { body = o && o.body ? JSON.parse(o.body) : null; } catch(e) { body = String(o.body).slice(0,80); }
  window.__calls.push({m:(o&&o.method)||"GET", u:String(u), body:body});
  return Promise.resolve({
    ok:true, status:200, statusText:"OK", url:String(u),
    headers:{get:function(){return null;}},
    json:function(){return Promise.resolve([]);},
    text:function(){return Promise.resolve("[]");},
    clone:function(){return this;}
  });
};
window.addEventListener("error", function(e){ window.__errs.push("JSERR: "+e.message); });
</script>
"""

TAIL = """<script id="ip-tail">
function click(sel){var e=document.querySelector(sel); if(!e){throw new Error("no element "+sel);} e.click();}
function set(id,v){var e=document.getElementById(id); if(!e){throw new Error("no field "+id);} e.value=v;}
function actBtn(name){
  var e=document.querySelector('[data-act="'+name+'"]');
  if(!e){throw new Error("no control for action "+name);}
  e.click();
}
window.addEventListener("load", function(){
  setTimeout(async function(){
    var steps = [];
    async function step(label, fn){
      var before = window.__calls.length;
      try { await fn(); await new Promise(function(r){setTimeout(r,400);});
            steps.push({step:label, ok:true, sent:window.__calls.slice(before)}); }
      catch(e){ steps.push({step:label, ok:false, err:String(e && e.message)}); }
    }

    STATE.demo = false;

    await step("render waivers view", async function(){ await RENDER.waivers(); });
    await step("open new-waiver dialog", async function(){ actBtn("openNewWaiver"); });
    await step("submit waiver with no control (must refuse)", async function(){
      await submitNewWaiver();
    });
    await step("submit a complete waiver", async function(){
      set("nw-control","CP-9"); set("nw-reason","tape backup, compensating control tested");
      set("nw-approver","CISO"); set("nw-asset","");
      await submitNewWaiver();
    });
    await step("revoke a waiver", async function(){ await revokeWaiver("w-1","CP-9"); });

    await step("open new-audit dialog", async function(){ await openNewAudit(); });
    await step("submit audit with no name (must refuse)", async function(){ await submitNewAudit(); });
    await step("submit audit with end before start (must refuse)", async function(){
      set("na-name","SOC 2 Type II"); set("na-start","2026-06-01"); set("na-end","2026-01-01");
      await submitNewAudit();
    });
    await step("submit a complete audit", async function(){
      set("na-name","SOC 2 Type II"); set("na-auditor","Prescott & Vale LLP");
      set("na-start","2026-01-01"); set("na-end","2026-06-30");
      await submitNewAudit();
    });

    await step("upload a PDF", async function(){
      var f = new File([new Uint8Array([0x25,0x50,0x44,0x46,0x2d,0x31,0x2e,0x34])],
                       "infosec-policy.pdf", {type:"application/pdf"});
      var dt = new DataTransfer(); dt.items.add(f);
      await RENDER.policy();
      var input = document.getElementById("pdfPolicyInput");
      input.files = dt.files;
      insertPolicyPdf(input);
      await new Promise(function(r){setTimeout(r,700);});
    });
    await step("extraction dialog is open and names the file", async function(){
      var d = document.querySelector("#settings .dialog");
      if(!d) throw new Error("no dialog opened");
      if(d.textContent.indexOf("infosec-policy.pdf") < 0) throw new Error("dialog does not name the file");
      if(d.textContent.indexOf("Imported") >= 0) throw new Error("dialog still claims an import");
    });

    await step("vendors view with live-shaped rows", async function(){
      window.fetch = function(u,o){
        window.__calls.push({m:(o&&o.method)||"GET", u:String(u), body:null});
        var live = [{id:"v1",name:"SmallTools Inc.",category:"Analytics",stage:"active",
                     risk_tier:"medium",assessment_state:"not_started",assessment_score:null,
                     computed_risk:"medium",data_access:"pii",has_dpa:false,has_soc2:false,
                     next_review:null}];
        var payload = String(u).indexOf("/summary")>=0
          ? {total:1,by_stage:{active:1},by_risk:{},needs_assessment:1,missing_dpa:1,overdue_reviews:0}
          : live;
        return Promise.resolve({ok:true,status:200,url:String(u),
          headers:{get:function(){return null;}},
          json:function(){return Promise.resolve(payload);},
          text:function(){return Promise.resolve("[]");},clone:function(){return this;}});
      };
      await RENDER.vendors();
      var t = document.querySelector("main").textContent;
      if(t.indexOf("Invalid Date") >= 0) throw new Error("still renders Invalid Date");
      if(t.indexOf("not assessed") < 0) throw new Error("unassessed vendor did not say so");
      if(t.indexOf("not scheduled") < 0) throw new Error("unscheduled review did not say so");
      if(/Reviews overdue[\\s\\S]{0,40}?1/.test(t)) throw new Error("an unscheduled review counted as overdue");
    });

    var pre=document.createElement("pre"); pre.id="__ip";
    pre.textContent=JSON.stringify({steps:steps, errs:window.__errs}, null, 1);
    document.body.appendChild(pre);
  }, 900);
});
</script>
"""

if not CHROME:
    raise SystemExit("no chromium binary found; this tool needs a browser")

src = DASH.read_text()
page = src.replace("<head>", "<head>" + HEAD, 1).replace("</body>", TAIL + "</body>", 1)
OUT.write_text(page)
try:
    out = subprocess.run(
        [CHROME, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
         "--virtual-time-budget=40000", "--dump-dom", OUT.as_uri()],
        capture_output=True, text=True, timeout=240).stdout
finally:
    OUT.unlink(missing_ok=True)

m = re.search(r'<pre id="__ip">(.*?)</pre>', out, re.S)
if not m:
    raise SystemExit("probe did not report")
d = json.loads(_html.unescape(m.group(1)))
for s in d["steps"]:
    mark = "ok  " if s["ok"] else "FAIL"
    print(f"{mark} {s['step']}")
    if not s["ok"]:
        print(f"       {s.get('err')}")
    for c in s.get("sent", []):
        body = json.dumps(c["body"])[:150] if c["body"] is not None else ""
        print(f"       -> {c['m']} {c['u']}  {body}")
print("\njs errors:", d["errs"] or "none")
