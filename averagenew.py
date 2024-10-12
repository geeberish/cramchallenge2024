import sys
import json
from invoke_model import invoke_model  # Import the function to invoke the SageMaker model
sys.path.append(".")
from cvss_calculation import *
import cvss_calculation as cvss

def get_model_output(files_to_submit, endpoint_name):
    """
    This function loads the submitted JSON files, invokes the SageMaker model,
    and returns the model's output.
    """
    # Aggregate data from the submitted files
    input_data = {}
    for file_type, file_path in files_to_submit.items():
        with open(file_path, 'r') as file:
            input_data[file_type] = json.load(file)

    # Invoke the SageMaker model and return the result
    return invoke_model(input_data, endpoint_name)

def main(files_to_submit):
    """
    This function gets the model output, performs the CVSS score calculations,
    and returns the results.
    """
    endpoint_name = 'WhiteRabbitNeo'  # SageMaker endpoint name
    model_output = get_model_output(files_to_submit, endpoint_name)  # Invoke model with the submitted files

    # Extract variables from the model output for CVSS calculations
    impact_conf = model_output.get("impact_conf", 0.7)
    impact_integ = model_output.get("impact_integ", 0.5)
    impact_avail = model_output.get("impact_avail", 0.2)
    scope_changed = model_output.get("scope_changed", 1) == 1

    attack_vector = model_output.get("attack_vector", 0.5)
    attack_complexity = model_output.get("attack_complexity", 0.2)
    privilege_required = model_output.get("privilege_required", 0.2)
    user_interaction = model_output.get("user_interaction", 0.85)

    exploit_code_maturity = model_output.get("exploit_code_maturity", 0.94)
    remediation_level = model_output.get("remediation_level", 0.95)
    report_confidence = model_output.get("report_confidence", 0.96)

    # Environmental inputs
    m_impact_conf = model_output.get("m_impact_conf", 0.5)
    cr = 1.0
    m_impact_integ = model_output.get("m_impact_integ", 0.2)
    ir = 1.0
    m_impact_avail = model_output.get("m_impact_avail", 0.35)
    ar = 1.0
    m_attack_vector = model_output.get("m_attack_vector", 0.85)
    m_attack_complexity = model_output.get("m_attack_complexity", 0.9)
    m_privilege_required = model_output.get("m_privilege_required", 0.62)
    m_user_interaction = model_output.get("m_user_interaction", 0.85)

    criticality = model_output.get("criticality", 1)
    physical_security = model_output.get("physical_security", 0.9)
    personnel_training = model_output.get("personnel_training", 0.9)
    policies = model_output.get("policies", 0.9)

    # Calculate the CVSS scores
    impact_sub = cvss.impact_subscore(impact_conf, impact_integ, impact_avail, scope_changed)
    exploitability_sub = cvss.exploitability_subscore(attack_vector, attack_complexity, privilege_required, user_interaction)
    base = cvss.base_score(impact_sub, exploitability_sub, scope_changed)
    temporal = cvss.temporal_score(base, exploit_code_maturity, remediation_level, report_confidence)
    modified_impact_sub = cvss.modified_impact_subscore(m_impact_conf, cr, m_impact_integ, ir, m_impact_avail, ar, scope_changed)
    modified_exploitability_sub = cvss.modified_exploitability_subscore(m_attack_vector, m_attack_complexity, m_privilege_required, m_user_interaction)
    environmental = cvss.environmental_score(modified_impact_sub, modified_exploitability_sub, scope_changed, exploit_code_maturity, remediation_level, report_confidence, criticality, physical_security, personnel_training, policies)

    overall_cvss = environmental if environmental > 0 else (temporal if temporal > 0 else base)

    return base, impact_sub, exploitability_sub, temporal, environmental, physical_security, personnel_training, policies, overall_cvss
