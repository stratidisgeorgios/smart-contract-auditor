"""
Shared constants for the agentic pipeline.
Import these wherever thresholds or limits are needed to keep them in sync.
"""

# Per-category REJECTION thresholds used in critique_node and verify_node.
# A finding is REJECTED when critique/verify scores it BELOW this value.
# Higher = stricter (harder to survive = better precision, lower recall).
# Lower = more permissive (easier to survive = better recall, lower precision).
CRITIQUE_CATEGORY_REJECT: dict[str, float] = {
    "bad_randomness":             0.25,  # block property in lottery = objective; lean toward keeping
    "access_control":             0.30,  # constructor pattern subtle but well-defined
    "reentrancy":                 0.35,  # well-defined 5-condition rule
    "arithmetic":                 0.35,  # well-defined version rule
    "unchecked_low_level_calls":  0.35,  # well-defined: return value checked or not
    "short_addresses":            0.35,  # well-defined
    "other":                      0.42,  # vague; require at least some evidence
    "denial_of_service":          0.45,  # FP-prone from theoretical loops; require clear blocking path
    "time_manipulation":          0.50,  # high FP rate; easily confused with bad_randomness
    "front_running":              0.55,  # highest FP rate; often duplicates bad_randomness
}

# Per-category CONFIRMATION thresholds used in critique_node and verify_node.
# A finding is CONFIRMED when critique/verify scores it AT OR ABOVE this value.
# Higher = harder to confirm without going through the full debate.
CRITIQUE_CATEGORY_CONFIRM: dict[str, float] = {
    "bad_randomness":             0.65,  # objective block-property check; easier to confirm
    "reentrancy":                 0.70,  # 5-condition rule is clear
    "arithmetic":                 0.70,  # version rule is clear
    "unchecked_low_level_calls":  0.70,  # return value check is clear
    "short_addresses":            0.70,  # well-defined
    "access_control":             0.72,  # constructor pattern clear once identified
    "other":                      0.75,  # vague; require more confidence to confirm
    "denial_of_service":          0.75,  # FP-prone; require higher confidence
    "time_manipulation":          0.78,  # often conflated with bad_randomness; require strong evidence
    "front_running":              0.82,  # highest FP rate; require very strong evidence
}

