# Comp-Lens compliance policy (Open Policy Agent / Rego).
#
# Load into OPA:  opa run --server policies/
# Point the app at it: POLICY_ENGINE=opa  OPA_URL=http://localhost:8181  OPA_PACKAGE=compliance
#
# The app POSTs:  {"input": {"control_id": "...", "telemetry": {...}}}
# and reads back: data.compliance.decision -> {"status": "...", "reason": "..."}

package compliance

import rego.v1

# default: unknown control
default decision := {"status": "error", "reason": "Unknown control"}

decision := d if {
	input.control_id == "AC-2-7"
	d := bool_check(input.telemetry.mfa_enforced, "MFA enforced", "MFA not enforced")
}

decision := d if {
	input.control_id == "SC-28"
	d := bool_check(input.telemetry.encryption_at_rest, "Encrypted at rest", "Not encrypted at rest")
}

decision := d if {
	input.control_id == "SC-7"
	d := bool_check(input.telemetry.public_access_blocked, "Public access blocked", "Publicly accessible")
}

decision := d if {
	input.control_id == "AU-2"
	d := bool_check(input.telemetry.logging_enabled, "Logging enabled", "Logging disabled")
}

decision := d if {
	input.control_id == "RA-5"
	count_crit := object.get(input.telemetry, "critical_vulnerabilities", 0)
	d := {"status": "pass", "reason": "No critical vulnerabilities"} if count_crit == 0
}

decision := {"status": "fail", "reason": "Critical vulnerabilities open"} if {
	input.control_id == "RA-5"
	object.get(input.telemetry, "critical_vulnerabilities", 0) > 0
}

# helper: pass if the boolean field is true, else fail
bool_check(val, pass_msg, fail_msg) := {"status": "pass", "reason": pass_msg} if val == true

bool_check(val, pass_msg, fail_msg) := {"status": "fail", "reason": fail_msg} if val != true
