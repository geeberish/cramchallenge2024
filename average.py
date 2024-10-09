import math
import sys
sys.path.append(".")
from cvss_calculation import *
import cvss_calculation as cvss

# impact_conf = 0
# impact_integ = 0
# impact_avail = 0
# scope_changed = 0

# attack_vector = 0
# attack_complexity = 0
# privilege_required = 0
# user_interaction = 0

# exploit_code_maturity = 0
# remediation_level = 0
# report_confidence =0

# # Modified environmental inputs
# m_impact_conf = 0
# cr = 1.0
# m_impact_integ = 0
# ir = 1.0
# m_impact_avail = 0
# ar = 1.0
# m_attack_vector = 0
# m_attack_complexity = 0
# m_privilege_required = 0
# m_user_interaction = 0

# criticality = 0
# physical_security = 0
# personnel_training = 0
# policies = 0

# # Calculate the CVSS scores
# impact_sub = 0
# exploitability_sub = 0
# base = 0
# temporal = 0
# modified_impact_sub = 0
# modified_exploitability_sub = 0
# environmental = 0
# average_cvss =0

def get_user_input(prompt, default=None):
    try:
        user_input = input(f"{prompt} (default {default}): ")
        return float(user_input) if user_input else default
    except ValueError:
        print("Invalid input. Using default value.")
        return default

def get_valid_iterations(prompt):
    while True:
        try:
            num_iterations = int(input(prompt))
            if num_iterations > 0:
                return num_iterations
            else:
                print("Please enter an integer greater than 0.")
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

# def rtntemporal_score():
#     # Example calculation of temporal score
#     return temporal  # Adjust as needed

# def rtnenvironmental_score():
#     # Example calculation of environmental score
#     return environmental  # Adjust as needed

# def rtnimpact_subscore():
#     return impact_sub

# def rtnexploitability_sub():
#     return exploitability_sub

# def rtnbase_score():
#     return base

# def rtnphysical_security():
#     return physical_security

# def rtncriticality():
#     return criticality

# def rtnpersonnel():
#     return personnel_training

# def rtnpolicies():
#     return policies

# def rtnoverall():
#     return average_cvss

def main():
    # Get the number of iterations with input validation
    num_iterations = get_valid_iterations("How many iterations of scoring would you like to run? ")

    total_score = 0

    for i in range(num_iterations):
        print(f"\n--- Iteration {i+1} ---")

        # Get user input for the variables
        impact_conf = get_user_input("Impact Confidentiality (0.0-1.0)", 0.7)
        impact_integ = get_user_input("Impact Integrity (0.0-1.0)", 0.5)
        impact_avail = get_user_input("Impact Availability (0.0-1.0)", 0.2)
        scope_changed = get_user_input("Scope Changed (1 for True, 0 for False)", 1) == 1

        attack_vector = get_user_input("Attack Vector (0.0-1.0)", 0.5)
        attack_complexity = get_user_input("Attack Complexity (0.0-1.0)", 0.2)
        privilege_required = get_user_input("Privilege Required (0.0-1.0)", 0.2)
        user_interaction = get_user_input("User Interaction (0.0-1.0)", 0.85)

        exploit_code_maturity = get_user_input("Exploit Code Maturity (0.0-1.0)", 0.94)
        remediation_level = get_user_input("Remediation Level (0.0-1.0)", 0.95)
        report_confidence = get_user_input("Report Confidence (0.0-1.0)", 0.96)

        # Modified environmental inputs
        m_impact_conf = get_user_input("Modified Impact Confidentiality (0.0-1.0)", 0.5)
        cr = 1.0
        m_impact_integ = get_user_input("Modified Impact Integrity (0.0-1.0)", 0.2)
        ir = 1.0
        m_impact_avail = get_user_input("Modified Impact Availability (0.0-1.0)", 0.35)
        ar = 1.0
        m_attack_vector = get_user_input("Modified Attack Vector (0.0-1.0)", 0.85)
        m_attack_complexity = get_user_input("Modified Attack Complexity (0.0-1.0)", 0.9)
        m_privilege_required = get_user_input("Modified Privilege Required (0.0-1.0)", 0.62)
        m_user_interaction = get_user_input("Modified User Interaction (0.0-1.0)", 0.85)

        criticality = get_user_input("Criticality (1-Low, 2-Medium, 3-High)", 1)
        physical_security = get_user_input("Physical Security (0.0-1.0)", 0.9)
        personnel_training = get_user_input("Personnel Training (0.0-1.0)", 0.9)
        policies = get_user_input("Policies (0.0-1.0)", 0.9)

        # Calculate the CVSS scores
        impact_sub = cvss.impact_subscore(impact_conf, impact_integ, impact_avail, scope_changed)
        exploitability_sub = cvss.exploitability_subscore(attack_vector, attack_complexity, privilege_required, user_interaction)
        base = cvss.base_score(impact_sub, exploitability_sub, scope_changed)
        temporal = cvss.temporal_score(base, exploit_code_maturity, remediation_level, report_confidence)
        modified_impact_sub = cvss.modified_impact_subscore(m_impact_conf, cr, m_impact_integ, ir, m_impact_avail, ar, scope_changed)
        modified_exploitability_sub = cvss.modified_exploitability_subscore(m_attack_vector, m_attack_complexity, m_privilege_required, m_user_interaction)
        environmental = cvss.environmental_score(modified_impact_sub, modified_exploitability_sub, scope_changed, exploit_code_maturity, remediation_level, report_confidence, criticality, physical_security, personnel_training, policies)

        # Select overall CVSS score
        overall_cvss = environmental if environmental > 0 else (temporal if temporal > 0 else base)

        print(f"Overall CVSS Score for iteration {i+1}: {overall_cvss}")
        total_score += overall_cvss

        # Calculate average score
        average_cvss = total_score / num_iterations
        print(f"\nAverage CVSS Score after {num_iterations} iterations: {average_cvss}")
        #return average_cvss
        return base, impact_sub, exploitability_sub, temporal, environmental, physical_security, personnel_training, policies, average_cvss

if __name__ == "__main__":
    main()
