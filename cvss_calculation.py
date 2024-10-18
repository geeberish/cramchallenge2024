# cvss_calculation.py
import math

# Helper function to round up to one decimal place
def roundup(x):
    return math.ceil(x * 10) / 10

# Base Score Calculation
def base_score(impact_subscore, exploitability_subscore, scope_changed):
    if impact_subscore <= 0:
        return 0
    if scope_changed:
        return roundup(min(1.08 * (impact_subscore + exploitability_subscore), 10))
    else:
        return roundup(min(impact_subscore + exploitability_subscore, 10))

# Impact Subscore Calculation
def impact_subscore(impact_conf, impact_integ, impact_avail, scope_changed):
    isc_base = 1 - ((1 - impact_conf) * (1 - impact_integ) * (1 - impact_avail))
    if scope_changed:
        return roundup(7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02)**15)
    else:
        return roundup(6.42 * isc_base)

# Exploitability Subscore Calculation
def exploitability_subscore(attack_vector, attack_complexity, privilege_required, user_interaction):
    return roundup(8.22 * attack_vector * attack_complexity * privilege_required * user_interaction)

# Temporal Score Calculation
def temporal_score(base_score, exploit_code_maturity, remediation_level, report_confidence):
    return roundup(base_score * exploit_code_maturity * remediation_level * report_confidence)

# Environmental Score Calculation with new weights
def environmental_score(modified_impact_subscore, modified_exploitability_subscore, scope_changed, exploit_code_maturity, remediation_level, report_confidence, criticality, physical_security, personnel_training, policies):
    if modified_impact_subscore <= 0:
        return 0
    base_environmental = 0
    if scope_changed:
        base_environmental = roundup(min(1.08 * (modified_impact_subscore + modified_exploitability_subscore), 10))
    else:
        base_environmental = roundup(min(modified_impact_subscore + modified_exploitability_subscore, 10))
    
    # Apply criticality and weight factors (physical security, personnel training, policies)
    weighted_score = base_environmental + criticality - physical_security - personnel_training - policies
    
    # Normalize the final score back to a 0.0-10.0 scale
    return roundup(min(weighted_score * exploit_code_maturity * remediation_level * report_confidence, 10))

# Modified Impact Subscore Calculation
def modified_impact_subscore(m_impact_conf, cr, m_impact_integ, ir, m_impact_avail, ar, scope_changed):
    isc_modified = min(1 - ((1 - m_impact_conf * cr) * (1 - m_impact_integ * ir) * (1 - m_impact_avail * ar)), 0.915)
    if scope_changed:
        return roundup(7.52 * (isc_modified - 0.029) - 3.25 * (isc_modified * 0.9731 - 0.02)**13)
    else:
        return roundup(6.42 * isc_modified)

# Modified Exploitability Subscore Calculation
def modified_exploitability_subscore(m_attack_vector, m_attack_complexity, m_privilege_required, m_user_interaction):
    return 8.22 * m_attack_vector * m_attack_complexity * m_privilege_required * m_user_interaction
