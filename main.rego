# =============================================================================
# Comp-Lens · Dual-Master Access Policy  (Envoy ext_authz entrypoint)
#
# ONE Rego artifact, TWO masters:
#   - Detective : the Comp-Lens middleware evaluates the same rules against
#                 historical state to produce signed compliance evidence.
#   - Preventive: this file, loaded by OPA behind Envoy, returns allow/deny
#                 for live requests.
#
# SHADOW-FIRST: each protected system carries a `mode` in bundle data
# (data.systems[host].mode). In "shadow" the policy ALWAYS returns allowed=true
# (zero blast radius) but records the *would-be* verdict in the decision log via
# response headers. Flip a single system to "enforce" from the control plane and
# the very same rules begin to block — nothing else changes.
# =============================================================================
package envoy.authz

import rego.v1

# ---- request facts -------------------------------------------------------
http    := input.attributes.request.http
method  := http.method
path    := http.path
host    := http.host

# headers are lower-cased by Envoy ext_authz
headers       := object.get(http, "headers", {})
auth_header   := object.get(headers, "authorization", "")
bearer        := trim_space(trim_prefix(auth_header, "Bearer "))

# ---- per-system config (pushed from the control plane in the bundle) -----
# Unconfigured hosts default to shadow + fail-open: we never block something
# we were not explicitly told how to govern.
syscfg := object.get(
	data.systems, host,
	{"mode": "shadow", "fail": "open", "policy_id": "unconfigured", "allowed_roles": []},
)

mode      := object.get(syscfg, "mode", "shadow")
policy_id := object.get(syscfg, "policy_id", "unconfigured")

# ---- identity ------------------------------------------------------------
# Reference uses HS256 with a shared secret in data.idp for a self-contained
# demo. For production swap to RS256 + JWKS:
#   token := io.jwt.decode_verify(bearer, {"cert": data.idp.jwks, "alg": "RS256"})
token       := io.jwt.decode_verify(bearer, {"secret": data.idp.hs256_secret, "alg": "HS256"})
token_valid := token[0] == true
claims      := token[2]
subject     := object.get(claims, "sub", "anonymous")
role        := object.get(claims, "role", "")

# ---- the REAL verdict (identical logic the detective side would assert) ---
allowed_roles := object.get(syscfg, "allowed_roles", [])
role_ok       := role in allowed_roles

default real_allow := false
real_allow if {
	token_valid
	role_ok
}

reason := "permitted" if real_allow
reason := "missing or invalid bearer token" if not token_valid
reason := sprintf("role '%s' not permitted on %s", [role, host]) if {
	token_valid
	not role_ok
}

# ---- shadow gate: what Envoy is actually told ----------------------------
# shadow (or any non-enforce mode)  -> always allow
# enforce                            -> the real verdict
enforced_allow := true if mode != "enforce"
enforced_allow := real_allow if mode == "enforce"

# would_block is the signal the dashboard counts: "we WOULD have denied this,
# and in shadow we let it through."
would_block := not real_allow

# ---- entrypoint Envoy reads (path: envoy/authz/allow) --------------------
# The whole object is captured in the OPA decision log, so the would-be verdict
# travels back to the control plane as evidence even when nothing was blocked.
allow := {
	"allowed": enforced_allow,
	"http_status": 403,
	"body": sprintf(
		`{"error":"forbidden","policy":"%s","reason":"%s"}`,
		[policy_id, reason],
	),
	"headers": {
		"x-complens-mode": mode,
		"x-complens-system": host,
		"x-complens-policy": policy_id,
		"x-complens-subject": subject,
		"x-complens-would-allow": sprintf("%v", [real_allow]),
		"x-complens-enforced-allow": sprintf("%v", [enforced_allow]),
		"x-complens-would-block": sprintf("%v", [would_block]),
		"x-complens-reason": reason,
	},
}
