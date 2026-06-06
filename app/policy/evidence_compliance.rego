# Comp-Lens evidence compliance policy (Open Policy Agent / Rego).
#
# Mirrors app/data/evidence_policy.json. Used only when POLICY_ENGINE/OPA is enabled
# (OPA_URL set). The app POSTs:
#   {"input": {"control_id","framework","evidence_hits":[...],"attestation":{...}}}
# and reads back: data.evidence_compliance.decision
#
#   evidence_hits[_] = {"concept","confirmed","confidence","method"}
#
package evidence_compliance

import rego.v1

default min_confidence := 0.6
default require_confirmation := true

# a hit qualifies if confirmed (when required) and meets the confidence floor
qualifying contains concept if {
	some h in input.evidence_hits
	concept := h.concept
	h.confidence >= min_confidence
	not (require_confirmation == true; not h.confirmed)
}

attested if {
	input.attestation.status == "compliant"
}

decision := {"status": "compliant", "satisfied": true,
	"reason": "Evidence satisfies control", "qualifying_concepts": qc} if {
	count(qualifying) > 0
	qc := [c | some c in qualifying]
}

decision := {"status": "compliant", "satisfied": true,
	"reason": "Met via human attestation", "qualifying_concepts": []} if {
	count(qualifying) == 0
	attested
}

decision := {"status": "insufficient_evidence", "satisfied": false,
	"reason": "Evidence exists but does not meet policy thresholds", "qualifying_concepts": []} if {
	count(qualifying) == 0
	not attested
	count(input.evidence_hits) > 0
}

decision := {"status": "not_assessed", "satisfied": false,
	"reason": "No evidence or attestation on record", "qualifying_concepts": []} if {
	count(qualifying) == 0
	not attested
	count(input.evidence_hits) == 0
}
