#!/usr/bin/env python3
"""Which backend operations can a user actually reach from the dashboard?

Run it:

    python tools/ui_coverage.py              # needs a chromium binary
    python tools/ui_coverage.py --static     # skip the browser, hand list only

The findings this produced are written up in UI-COVERAGE.md.

Why it is built this way
------------------------
Matching route paths against string literals in dashboard.html is wrong in both
directions. The dashboard builds paths by concatenation —

    api("/connectors/" + encodeURIComponent(key) + "/test", ...)

— so a literal search calls a wired endpoint unreachable; and it *mentions*
endpoints in prose it never calls ("A real evidence-concept graph exists at GET
/evidence/graph for a future version of this view"), so a literal search calls
an unreachable endpoint wired. Both errors point at the thing this script
exists to measure, so neither is acceptable.

Instead the reachable set is built twice, independently, and the two halves are
checked against each other:

1. DYNAMIC. dashboard.html is loaded in headless Chromium with `fetch` replaced
   by a recorder, and every RENDER.<view>() is invoked. Whatever it requests is
   reachable by demonstration. The recorder answers with a Proxy that behaves
   like an empty array AND like an object with any property, because a stub
   returning `{}` kills a view on its first `rows.filter(...)` and the view then
   never issues its second wave of requests. `ran` vs `views` in the output is
   the instrument's own yield: if they differ, the URL list is a floor, not an
   answer, and the script refuses to conclude anything.
2. MANUAL. WIRED below lists every api/apiGET/apiPOST/apiPATCH call site and
   every <a href> download link, each with the dashboard.html line it was read
   from. Interaction-only calls — a delete button, a form submit — never fire
   during a render pass, so the dynamic half alone would under-count them.

The script fails loudly if the browser requested anything the manual list does
not contain: that means the manual list has gone stale, and a stale list
silently converts wired endpoints into "gaps".
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import html as _html
import json
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DASH = ROOT / "app" / "static" / "dashboard.html"

# ── the manual half: (METHOD, path template) -> dashboard.html line ──────────
WIRED: dict[tuple[str, str], int] = {
    ("GET", "/health/live"): 866,
    ("GET", "/summary"): 1120,
    ("GET", "/trends"): 1121,
    ("GET", "/findings"): 1122,
    ("PATCH", "/findings/{}"): 2145,
    ("GET", "/catalog/frameworks"): 1123,
    ("GET", "/catalog"): 1821,
    ("GET", "/v1/grc-trust/unified"): 1124,
    ("GET", "/controls"): 1197,
    ("GET", "/connectors"): 1344,
    ("GET", "/connectors/status"): 1339,
    ("GET", "/connectors/catalog"): 1342,
    ("GET", "/connectors/capabilities"): 2487,
    ("GET", "/connectors/instances"): 1357,
    ("POST", "/connectors/instances"): 2275,
    ("POST", "/connectors/instances/ephemeral/sync"): 2283,
    ("POST", "/connectors/instances/ephemeral/test"): 2296,
    ("POST", "/connectors/instances/{}/sync"): 2290,
    ("POST", "/connectors/instances/{}/test"): 2301,
    ("DELETE", "/connectors/instances/{}"): 2308,
    ("POST", "/connectors/{}/test"): 3107,
    ("GET", "/ai-systems"): 1469,
    ("POST", "/v1/integrate/ai-systems/{}/to-risk"): 2132,
    ("GET", "/grc/risks"): 1524,
    ("GET", "/grc/risks/summary"): 1524,
    ("PATCH", "/grc/risks/{}"): 2176,
    ("GET", "/tprm/vendors"): 1600,
    ("GET", "/tprm/vendors/summary"): 1600,
    ("PATCH", "/tprm/vendors/{}"): 2181,
    ("GET", "/enforcement/status"): 1971,
    ("GET", "/enforcement/systems"): 1972,
    ("GET", "/enforcement/decisions"): 1973,
    ("POST", "/enforcement/systems/{}/mode"): 1958,
    ("GET", "/policies"): 2380,
    # POST /policies/import was listed here until the "Insert PDF" button was
    # repointed at /v1/documents/upload. It only ever received {name: filename},
    # which that endpoint acknowledges without importing anything, so the entry
    # was recording a call that did nothing. It is now genuinely unreachable and
    # belongs in the report as a gap.
    ("POST", "/v1/policy/evaluate"): 2208,
    ("GET", "/v1/agents/actions"): 2437,
    ("GET", "/v1/agents/actions/verify"): 2437,
    ("GET", "/coverage/automation"): 2487,
    ("GET", "/v1/scf/verify-crosswalk"): 2541,
    ("GET", "/evidence"): 2585,
    ("GET", "/evidence/{}/verify"): 2194,
    ("POST", "/v1/evidence/ingest"): 2662,
    ("POST", "/v1/documents/upload"): 2460,
    ("GET", "/v1/threat/kev"): 2682,
    ("GET", "/waivers"): 1533,
    ("POST", "/waivers"): 1594,
    ("DELETE", "/waivers/{}"): 1605,
    ("GET", "/audits"): 2763,
    ("POST", "/audits"): 2265,
    ("POST", "/audits/{}/refresh-posture"): 2214,
    ("GET", "/audits/{}/export"): 1883,
    ("GET", "/v1/grc-sync/status"): 2803,
    ("GET", "/v1/grc-sync/platforms"): 2803,
    ("POST", "/v1/grc-sync/{}"): 2924,
    ("GET", "/setup"): 3075,
    ("GET", "/v1/posture/as-of"): 1624,
    ("GET", "/v1/posture/timeline"): 1647,
    ("POST", "/assessments"): 2150,
    ("POST", "/remediation/tickets"): 2138,
    ("GET", "/reports/pdf"): 1575,
    ("GET", "/reports/csv"): 1576,
    ("GET", "/reports/oscal"): 1577,
    ("GET", "/reports/oscal-poam"): 1578,
    ("GET", "/reports/oscal-components"): 1579,
    # served to the browser rather than fetched by it
    ("GET", "/dashboard"): 0,
    ("GET", "/"): 0,
}

CHROMIUM_CANDIDATES = [
    "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
]

PROBE_HEAD = """<script id="uiprobe-head">
window.__urls = []; window.__errs = [];
(function(){
  var ARR = ["filter","map","slice","forEach","flatMap","find","findIndex","sort",
             "reduce","reduceRight","concat","join","includes","indexOf",
             "lastIndexOf","some","every","reverse","push","pop","shift",
             "unshift","splice","at","keys","values","entries","fill","flat"];
  var STR = ["toFixed","toLocaleString","toUpperCase","toLowerCase","trim","split",
             "replace","replaceAll","padStart","padEnd","startsWith","endsWith",
             "match","repeat","substring","substr","charAt"];
  function magic(){
    var arr = [], fn = function(){ return magic(); };
    return new Proxy(fn, {
      get: function(t, k){
        if (k === "length") return 0;
        if (k === "then") return undefined;
        if (k === "toJSON") return function(){ return []; };
        if (k === Symbol.iterator) return arr[Symbol.iterator].bind(arr);
        if (k === Symbol.toPrimitive) return function(){ return 0; };
        if (typeof k === "symbol") return undefined;
        if (ARR.indexOf(k) >= 0) return arr[k].bind(arr);
        if (STR.indexOf(k) >= 0) return function(){ return magic(); };
        if (k === "toString") return function(){ return ""; };
        if (k === "constructor") return Array;
        return magic();
      },
      apply: function(){ return magic(); },
      has: function(){ return true; }
    });
  }
  window.fetch = function(u, o){
    try { window.__urls.push(((o && o.method) || "GET") + " " + String(u)); } catch (e) {}
    return Promise.resolve({
      ok: true, status: 200, statusText: "OK", url: String(u),
      headers: { get: function(){ return null; } },
      json: function(){ return Promise.resolve(magic()); },
      text: function(){ return Promise.resolve("{}"); },
      clone: function(){ return this; }
    });
  };
})();
window.addEventListener("error", function(e){ window.__errs.push("JSERR: " + e.message); });
</script>
"""

PROBE_TAIL = """<script id="uiprobe-tail">
window.addEventListener("load", function(){
  setTimeout(async function(){
    var names = (typeof RENDER === "object" && RENDER) ? Object.keys(RENDER) : [];
    var ran = [], failed = [];
    for (var i = 0; i < names.length; i++) {
      var n = names[i];
      try { await RENDER[n](); ran.push(n); }
      catch (e) { failed.push(n); window.__errs.push(n + ": " + (e && e.message)); }
    }
    await new Promise(function(r){ setTimeout(r, 2000); });
    var pre = document.createElement("pre");
    pre.id = "__uiprobe";
    pre.textContent = JSON.stringify({views: names.length, ran: ran.length,
                                      failed: failed, urls: window.__urls,
                                      errs: window.__errs});
    document.body.appendChild(pre);
  }, 800);
});
</script>
"""


def find_chromium() -> str | None:
    for cand in CHROMIUM_CANDIDATES:
        path = cand if pathlib.Path(cand).exists() else shutil.which(cand)
        if path:
            return path
    return None


def run_probe(chrome: str) -> dict:
    """Render the dashboard and report every URL its 24 views request."""
    src = DASH.read_text()
    if "RENDER" not in src:
        sys.exit("probe premise broken: no RENDER table in dashboard.html")
    page = src.replace("<head>", "<head>" + PROBE_HEAD, 1)
    page = page.replace("</body>", PROBE_TAIL + "</body>", 1)

    # written next to the real page so relative asset paths still resolve
    tmp = DASH.parent / f".ui_coverage_probe_{id(page)}.html"
    tmp.write_text(page)
    try:
        out = subprocess.run(
            [chrome, "--headless", "--no-sandbox", "--disable-gpu",
             "--disable-dev-shm-usage", "--virtual-time-budget=40000",
             "--dump-dom", tmp.as_uri()],
            capture_output=True, text=True, timeout=240).stdout
    finally:
        tmp.unlink(missing_ok=True)

    m = re.search(r'<pre id="__uiprobe">(.*?)</pre>', out, re.S)
    if not m:
        sys.exit("the probe never reported — do not trust a coverage number "
                 "derived from a page that did not finish loading")
    return json.loads(_html.unescape(m.group(1)))


def backend_routes() -> list[dict]:
    """Every (method, path) the FastAPI app serves, read from the source."""
    methods = {"get", "post", "put", "patch", "delete"}
    routes, seen = [], set()
    for py in sorted(ROOT.glob("app/**/*.py")):
        try:
            tree = ast.parse(py.read_text())
        except SyntaxError:
            continue
        prefixes, tags = {}, {}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                    and getattr(node.value.func, "id",
                                getattr(node.value.func, "attr", "")) == "APIRouter"
                    and isinstance(node.targets[0], ast.Name)):
                for kw in node.value.keywords:
                    if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                        prefixes[node.targets[0].id] = kw.value.value
                    elif kw.arg == "tags":
                        with contextlib.suppress(Exception):
                            tags[node.targets[0].id] = ast.literal_eval(kw.value)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                fn = dec.func
                if not isinstance(fn, ast.Attribute) or fn.attr not in methods:
                    continue
                if not dec.args or not isinstance(dec.args[0], ast.Constant):
                    continue
                var = getattr(fn.value, "id", "")
                raw = prefixes.get(var, "") + dec.args[0].value
                norm = re.sub(r"\{[^}]*\}", "{}", raw).rstrip("/") or "/"
                key = (fn.attr.upper(), norm)
                if key in seen:
                    continue
                seen.add(key)
                tag = None
                for kw in dec.keywords:
                    if kw.arg == "tags":
                        with contextlib.suppress(Exception):
                            tag = (ast.literal_eval(kw.value) or [None])[0]
                routes.append({
                    "method": key[0], "path": raw, "norm": norm,
                    "tag": tag or (tags.get(var) or [None])[0],
                    "file": str(py.relative_to(ROOT)), "line": node.lineno,
                    "desc": " ".join((ast.get_docstring(node) or "").split())[:120],
                })
    return routes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--static", action="store_true",
                    help="skip the headless run; trust the hand-built list alone")
    ap.add_argument("--json", type=pathlib.Path,
                    help="write the unreachable operations here")
    args = ap.parse_args()

    if args.static:
        print("static mode: the hand-built WIRED list is not being cross-checked "
              "against a real render pass, so a stale entry cannot be detected")
    else:
        chrome = find_chromium()
        if not chrome:
            print("no chromium binary found; re-run with --static to use the "
                  "hand-built list alone", file=sys.stderr)
            return 2
        probe = run_probe(chrome)
        if probe["ran"] != probe["views"]:
            print(f"PROBE INCOMPLETE: {probe['ran']}/{probe['views']} views ran "
                  f"({probe['failed']}); its URL list is a floor, not an answer",
                  file=sys.stderr)
            return 1
        observed = set()
        for entry in probe["urls"]:
            method, _, url = entry.partition(" ")
            observed.add((method,
                          re.sub(r"^\w+://", "/", url).split("?")[0].rstrip("/")))
        holes = sorted(observed - set(WIRED))
        print(f"cross-check: {probe['ran']}/{probe['views']} views ran and made "
              f"{len(observed)} distinct requests; "
              f"missing from the hand-built list: {holes or 'none — OK'}")
        if holes:
            print("the WIRED list is stale, which would report wired endpoints "
                  "as gaps — add the entries above before trusting this run",
                  file=sys.stderr)
            return 1

    routes = backend_routes()
    unreachable = [r for r in routes if (r["method"], r["norm"]) not in WIRED]
    print(f"\n{len(routes)} distinct backend operations · "
          f"{len(routes) - len(unreachable)} wired into the dashboard · "
          f"{len(unreachable)} with no UI path\n")

    by_tag: dict[str, list[dict]] = {}
    for route in unreachable:
        by_tag.setdefault(route["tag"] or "(untagged)", []).append(route)
    for tag in sorted(by_tag, key=lambda k: -len(by_tag[k])):
        print(f"### {tag} ({len(by_tag[tag])})")
        for route in sorted(by_tag[tag], key=lambda r: r["path"]):
            print(f"  {route['method']:6} {route['path']:44} {route['desc']}")
        print()

    if args.json:
        args.json.write_text(json.dumps(unreachable, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
