import math
import json

def main(combined_vulnerabilities_data, node_criticality_mapping, system_evaluation_scores, apt_cve_evaluation_scores):
  # iterate through vulnerabilites calculating modified 
  for vulnerability in combined_vulnerabilities_data:
    node_name = vulnerability['Node Name']
    cve_number = vulnerability['CVE Number']
    
    # CVSS base scoring metrics
    scope = vulnerability['scope_changed']
    base_score = vulnerability['base_score']
    impact_score = vulnerability['impact_score']
    attack_vector = calculate_attack_vector_scores(vulnerability['attack_vector'])
    attack_complexity = calculate_attack_complexity_scores(vulnerability['attack_complexity'])
    impact_confidentiality = calculate_impact_CIA_scores(vulnerability['impact_conf'])
    impact_integrity = calculate_impact_CIA_scores(vulnerability['impact_integ'])
    impact_availability = calculate_impact_CIA_scores(vulnerability['impact_avail'])
    user_interaction = calculate_user_interaction_scores(vulnerability['user_interaction'])
    privilege_required = calculate_privilege_required_scores(vulnerability['privilege_required'], scope)
    exploitability_score = vulnerability['exploitability_score']

    # call function to calculate the CIA requirement scores
    confidentiality_requirement = calculate_CIA_requirement_scores(node_name, node_criticality_mapping)
    integrity_requirement = calculate_CIA_requirement_scores(node_name, node_criticality_mapping)
    availability_requirement = calculate_CIA_requirement_scores(node_name, node_criticality_mapping)

    # call functions to calculate the CIA modified impact scores
    modified_impact_confidentiality = calculate_modified_impact_confidentiality(impact_confidentiality)
    modified_impact_integrity = calculate_modified_impact_integrity(impact_integrity)
    modified_impact_availability = calculate_modified_impact_availability(impact_availability)

    # modified scoring metrics
    modified_scope = scope
    modified_attack_vector = attack_vector
    modified_attack_complexity = attack_complexity
    modified_privilege_required = privilege_required
    modified_user_interaction = user_interaction
    modified_impact_score = calculate_modified_impact_sub_score(
      modified_impact_confidentiality, confidentiality_requirement, modified_impact_integrity, integrity_requirement,
      modified_impact_availability, availability_requirement, modified_scope
    )
    modified_exploitability_score = calculate_exploitability_sub_score(
      attack_vector, attack_complexity, privilege_required, user_interaction
    )

    # custom CVSS modified scoring metrics
    exploit_code_maturity = 1 # NOT DEFINED
    remediation_level = 1 # NOT DEFINED
    report_confidence = 1 # NOT DEFINED

    # ACRES scoring metrics
    personel_training_score = system_evaluation_scores['personel_training_score'] # FIXME
    physical_security_score = system_evaluation_scores['physical_security_score'] # FIXME
    policy_procedures_score = system_evaluation_scores['policy_procedures_score'] # FIXME
    apt_score = apt_cve_evaluation_scores[cve_number]['apt_score'] # FIXME

    ### BASE SCORE ###
    # call function to calculate the impact sub score using CVSSv3.1 equations
    impact_sub_score = calculate_impact_sub_score(impact_confidentiality, impact_integrity, impact_availability, scope)
    
    # call function to calculate the exploitability sub score using CVSSv3.1 equations
    exploitability_sub_score = calculate_exploitability_sub_score(
      attack_vector, attack_complexity, privilege_required, user_interaction
    )

    # define function to calculate base score using CVSSv3.1 environmental score formulas
    base_score = calculate_base_score(
      impact_sub_score, impact_score, exploitability_score, scope, exploit_code_maturity, remediation_level,
      report_confidence
    )

    ### TEMPORAL SCORE ###
    # call function to calculate the temporal score using CVSSv3.1 equations
    temporal_score = calculate_temporal_score(base_score, exploit_code_maturity, remediation_level, report_confidence)
    print(temporal_score)
    input()
    
    ### ENVIRONMENTAL SCORE ###
    # call function to calculate the modified impact sub score using CVSSv3.1 equations
    modified_impact_sub_score = calculate_modified_impact_sub_score(
      modified_impact_confidentiality, confidentiality_requirement, modified_impact_integrity, integrity_requirement,
      modified_impact_availability, availability_requirement, modified_scope
    )

    # call function to calculate the modified exploitability sub score using CVSSv3.1 equations
    modified_exploitability_sub_score = calculate_modified_exploitability_sub_score(
      modified_attack_vector, modified_attack_complexity, modified_privilege_required, modified_user_interaction
    )

    # call function to calculate the environmental score using CVSSv3.1 equations
    environmental_score = calculate_environmental_score(
      modified_impact_sub_score, modified_impact_score, modified_exploitability_score, modified_scope,
      exploit_code_maturity, remediation_level, report_confidence, scope
    )

  print(cve_number)

  # return modified score variables via combined vulnerabilities data to orchestration script
  return combined_vulnerabilities_data

 # # # # # # # # # # #
# # # BASE  SCORE # # #
 # # # # # # # # # # #

# define function to calculate the impact sub score using CVSSv3.1 equations
def calculate_impact_sub_score(impact_confidentiality, impact_integrity, impact_availability, scope):
  ic_ii_ia = min((1 - (1 - impact_confidentiality) * (1 - impact_integrity) * (1 - impact_availability)), 0.915)

  if scope == 'UNCHANGED':
    impact_sub_score = (6.42 * ic_ii_ia)
  elif scope == 'CHANGED':
    impact_sub_score = (7.52 * (ic_ii_ia - 0.029) - (3.25 * pow((ic_ii_ia - 0.02), 15)))
  
  return impact_sub_score

# define function to calculate the exploitability sub score using CVSSv3.1 equations
def calculate_exploitability_sub_score(attack_vector, attack_complexity, privilege_required, user_interaction):
  exploitability_sub_score = (8.22 * attack_vector * attack_complexity * privilege_required * user_interaction)
  return exploitability_sub_score

# define function to calculate base score using CVSSv3.1 environmental score formulas
def calculate_base_score(
    impact_sub_score, impact_score, exploitability_score, scope, exploit_code_maturity, remediation_level, report_confidence
):
  if impact_sub_score <= 0:
    base_score = 0

  elif scope == 'UNCHANGED':
    isXes = (impact_score * exploitability_score)
    min_isXes = min(isXes, 10)
    rnd_min_isXes = round_up(min_isXes)
    rnd_min_isXes_ecm_rl_rc = (rnd_min_isXes * exploit_code_maturity * remediation_level * report_confidence)
    base_score = round_up(rnd_min_isXes_ecm_rl_rc)

  elif scope == 'CHANGED':
    isXes = (1.08 * (impact_score * exploitability_score))
    min_isXes = min(isXes, 10)
    rnd_min_isXes = round_up(min_isXes)
    rnd_min_isXes_ecm_rl_rc = (rnd_min_isXes * exploit_code_maturity * remediation_level * report_confidence)
    base_score = round_up(rnd_min_isXes_ecm_rl_rc)

  return base_score

 # # # # # # # # # # # # #
# # # TEMPORAL  SCORE # # #
 # # # # # # # # # # # # #

# define function to calculate the temporal score using CVSSv3.1 equations
def calculate_temporal_score(base_score, exploit_code_maturity, remediation_level, report_confidence):
  temporal_score = round_up(base_score * exploit_code_maturity * remediation_level * report_confidence)
  print(base_score, exploit_code_maturity, remediation_level, report_confidence)
  input()

  return temporal_score

 # # # # # # # # # # # # # # #
# # # ENVIRONMENTAL SCORE # # #
 # # # # # # # # # # # # # # #

# define function to calculate the modified impact sub score using CVSSv3.1 equations
def calculate_modified_impact_sub_score(
  modified_impact_confidentiality, confidentiality_requirement, modified_impact_integrity, integrity_requirement,
  modified_impact_availability, availability_requirement, modified_scope
):
  mic_cr = (1 - (modified_impact_confidentiality * confidentiality_requirement))
  mii_ir = (1 - (modified_impact_integrity * integrity_requirement))
  mia_ar = (1 - (modified_impact_availability * availability_requirement))
  mic_cr_mii_ir_mia_ar = (1 - (mic_cr * mii_ir * mia_ar))
  min_mic_cr_mii_ir_mia_ar = min(mic_cr_mii_ir_mia_ar, 0.915)

  if modified_scope == 'UNCHANGED':
    modified_impact_sub_score = (6.42 * min_mic_cr_mii_ir_mia_ar)
  elif modified_scope == 'CHANGED':
    modified_impact_sub_score = ((7.52 * (min_mic_cr_mii_ir_mia_ar - 0.029)) - 
                                  (3.25 * pow(((min_mic_cr_mii_ir_mia_ar * 0.9731) - 0.02), 13)))
  
  return modified_impact_sub_score

# def function to calculate the modified exploitability sub score using CVSSv3.1 equations
def calculate_modified_exploitability_sub_score(
  modified_attack_vector, modified_attack_complexity, modified_privilege_required, modified_user_interaction
):
  modified_exploitability_sub_score = (8.22 * modified_attack_vector * modified_attack_complexity *
                                       modified_privilege_required * modified_user_interaction)
  
  return modified_exploitability_sub_score

# define function to calculate the environmental score using CVSSv3.1 equations
def calculate_environmental_score(
  modified_impact_sub_score, modified_impact_score, modified_exploitability_score, modified_scope,exploit_code_maturity,
  remediation_level, report_confidence, scope
):
  if modified_impact_sub_score <= 0:
    environmental_score = 0

  elif modified_scope == 'UNCHANGED':
    misXmes = (modified_impact_score * modified_exploitability_score)
    min_misXmes = min(misXmes, 10)
    rnd_min_misXmes = round_up(min_misXmes)
    rnd_min_misXmes_ecm_rl_rc = (rnd_min_misXmes * exploit_code_maturity * remediation_level * report_confidence)
    environmental_score = round_up(rnd_min_misXmes_ecm_rl_rc)

  elif scope == 'CHANGED':
    misXmes = (1.08 * (modified_impact_score * modified_exploitability_score))
    min_misXmes = min(misXmes, 10)
    rnd_min_misXmes = round_up(min_misXmes)
    rnd_min_misXmes_ecm_rl_rc = (rnd_min_misXmes * exploit_code_maturity * remediation_level * report_confidence)
    environmental_score = round_up(rnd_min_misXmes_ecm_rl_rc)

  return environmental_score

 # # # # # # # # # # # # # # # # # # #
# # # MODIFIED SCORE CALCULATIONS # # #
 # # # # # # # # # # # # # # # # # # #

def calculate_modified_impact_confidentiality(impact_confidentiality):
  modified_impact_confidentiality = impact_confidentiality

  return modified_impact_confidentiality

def calculate_modified_impact_availability(impact_availability):
  modified_impact_availability = impact_availability

  return modified_impact_availability

def calculate_modified_impact_integrity(impact_integrity):
  modified_impact_integrity = impact_integrity

  return modified_impact_integrity

 # # # # # # # # # # # # # # #
# # # OTHER  CALCULATIONS # # #
 # # # # # # # # # # # # # # #

# define function to calculate the modifiable range for the score
def calculate_modify_range(score):
  if score >= 5 and score <= 10:
    modify_range = 10 - score
  elif score < 5 and score >= 0:
    modify_range = score
  elif score < 0:
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_modify_range() OF calculate_modified_scores.py:")
    print("<!>                          THE PROVIDED SCORE IS BELOW 0. HANDLING THE ERROR BY SETTING") 
    print("<!>                          MODIFY RANGE TO 0 AND THE SCORE to 0; CHECK THE SCORES DATA.")
    score = 0
    modify_range = 0
  else: # score > 10
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_modify_range() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED SCORE IS ABOVE 10. HANDLING THE ERROR BY SETTING")
    print("<!>                          MODIFY RANGE TO 0 AND THE SCORE to 10; CHECK THE SCORES DATA.")
    score = 10
    modify_range = 0
  
  return modify_range

# define function to calculate the CIA impact scores
def calculate_impact_CIA_scores(named_score):
  if named_score in ['HIGH', 'COMPLETE']:
    numbered_score = 0.56
  elif named_score in ['LOW', 'PARTIAL']:
    numbered_score = 0.22
  elif named_score == 'NONE':
    numbered_score = 0
  else:
    numbered_score = 0.56
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_impact_CIA_scores() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED NAMED SCORE IS NOT VALID. HANDLING THE ERROR BY SETTING")
    print("<!>                          NUMBERED SCORE TO 0.56; CHECK THE NAMED SCORES DATA FOR CIA IMPACT.")
  return numbered_score

# define function to calculate the attack vector scores
def calculate_attack_vector_scores(named_score):
  if named_score in ['NETWORK']:
    numbered_score = 0.85
  elif named_score in ['ADJACENT', 'ADJACENT_NETWORK']:
    numbered_score = 0.62
  elif named_score in ['LOCAL']:
    numbered_score = 0.55
  elif named_score in ['PHYSICAL']:
    numbered_score = 0.20
  else:
    numbered_score = 0.85
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_attack_vector_scores() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED NAMED SCORE IS NOT VALID. HANDLING THE ERROR BY SETTING")
    print("<!>                          NUMBERED SCORE TO 0.85; CHECK THE NAMED SCORES DATA FOR ATTACK VECTOR.")
  return numbered_score

# define function to calculate the attack complexity scores
def calculate_attack_complexity_scores(named_score):
  if named_score in ['HIGH']:
    numbered_score = 0.44
  elif named_score in ['MEDIUM']:
    numbered_score = 0.605
  elif named_score in ['LOW']:
    numbered_score = 0.77
  else:
    numbered_score = 0.77
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_attack_complexity_scores() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED NAMED SCORE IS NOT VALID. HANDLING THE ERROR BY SETTING")
    print("<!>                          NUMBERED SCORE TO 0.77; CHECK THE NAMED SCORES DATA FOR ATTACK COMPLEXITY.")
  return numbered_score

# define function to calculate the user interaction scores
def calculate_user_interaction_scores(named_score):
  if named_score in ['NONE', False]:
    numbered_score = 0.85
  elif named_score in ['REQUIRED', True]:
    numbered_score = 0.62
  else:
    numbered_score = 0.85
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_user_interaction_scores() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED NAMED SCORE IS NOT VALID. HANDLING THE ERROR BY SETTING")
    print("<!>                          NUMBERED SCORE TO 0.85; CHECK THE NAMED SCORES DATA FOR USER INTERACTION.")
  return numbered_score

# define function to calculate the user interaction scores
def calculate_privilege_required_scores(named_score, scope):
  if scope == "UNCHANGED":
    if named_score in ['HIGH', 'MULTIPLE']:
      numbered_score = 0.27
    elif named_score in ['LOW', 'SINGLE']:
      numbered_score = 0.62
    elif named_score in ['NONE']:
      numbered_score = 0.85
  elif scope == "CHANGED":
    if named_score in ['HIGH', 'MULTIPLE']:
      numbered_score = 0.50
    elif named_score in ['LOW', 'SINGLE']:
      numbered_score = 0.68
    elif named_score in ['NONE']:
      numbered_score = 0.85
  else:
    numbered_score = 0.85
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_privilege_required_scores() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED NAMED SCORE IS NOT VALID. HANDLING THE ERROR BY SETTING")
    print("<!>                          NUMBERED SCORE TO 0.85; CHECK THE NAMED SCORES DATA FOR PRIVILEGE REQUIRED.")
  return numbered_score

# define function to calculate the CIA requirement scores
def calculate_CIA_requirement_scores(node_name, node_criticality_mapping):
  criticality_requirement = node_criticality_mapping[node_name]

  if criticality_requirement == 3:
    CIA_requirement_scores = 1.5
  elif criticality_requirement == 2:
    CIA_requirement_scores = 1.0
  elif criticality_requirement == 1:
    CIA_requirement_scores = 0.5
  else:
    CIA_requirement_scores = 1.0
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_CIA_requirement_scores() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED NUMBERED SCORE IS NOT VALID. HANDLING THE ERROR BY SETTING")
    print("<!>                          REQUIREMENTS SCORE TO 1; CHECK THE SCORES DATA FOR CRITICALITY MAPPING.")

  return CIA_requirement_scores

# define function to round up to one decimal
def round_up(number):
  integer_number = math.trunc(number) # integer portion of provided number
  decimal_number = number - integer_number # decimal portion of provided number
  
  # rounding equation if round() would naturally round up
  if decimal_number >= 0.5:
    number = round(number, 1)
  
  # rounding equation if round() would naturally round down, but force to round up
  else: # decimal_number < 0.5:
    number = round(number, 1) + 0.1

  return number

# set file locations if this code is run directly/not called from another script
if __name__ == "__main__":
  with open('./sue_data/json_data/individual_files_archive/combined_vulnerabilities_data_file.json') as detected_vulnerabilities_file:
    combined_vulnerabilities_data = json.load(detected_vulnerabilities_file)
  cves = set([item["CVE Number"] for item in combined_vulnerabilities_data])
  with open('./sue_data/json_data/individual_files_archive/node_criticality_mapping_file.json') as node_criticality_mapping_file:
    node_criticality_mapping = json.load(node_criticality_mapping_file)
  system_evaluation_scores = {
    'personel_training_score': 0.5,
    'physical_security_score': 0.5,
    'policy_procedures_score': 0.5
  }
  apt_cve_evaluation_scores = {}

  for cve in cves:
    cve_number = cve
    apt_score = 0.5
    reasoning = "reasoning ... ... ... blah blah blah ... APT's BAD!!!"
    dictionary = {'apt_score': apt_score, 'reasoning': reasoning}
    apt_cve_evaluation_scores[cve_number] = dictionary

  main(combined_vulnerabilities_data, node_criticality_mapping, system_evaluation_scores, apt_cve_evaluation_scores)