import json # a module to work with JSON data
import math # a module to add additional math functionality

def main(combined_vulnerabilities_data, node_criticality_mapping, system_evaluation_scores, apt_cve_evaluation_scores):
  # iterate through vulnerabilites calculating modified scores for each vulnerability
  for vulnerability in combined_vulnerabilities_data:
    node_name = vulnerability['Node Name']
    cve_number = vulnerability['CVE Number']

    # ACRES scoring metrics
    personnel_training_score = system_evaluation_scores['personnel_score'] # FIXME
    physical_security_score = system_evaluation_scores['physical_security_score'] # FIXME
    operations_policies_score = system_evaluation_scores['policies_score'] # FIXME
    apt_score = apt_cve_evaluation_scores[cve_number]['apt_score'] # FIXME
    apt_reasoning = apt_cve_evaluation_scores[cve_number]['reasoning']

    # custom CVSS modified scoring metrics
    exploit_code_maturity = 1 # NOT DEFINED
    remediation_level = 1 # NOT DEFINED
    report_confidence = 1 # NOT DEFINED
    
    # CVSS base scoring metrics
    scope = vulnerability['scope_changed']
    base_score = vulnerability['base_score']
    impact_score = vulnerability['impact_score']
    exploitability_score = vulnerability['exploitability_score']
    attack_vector = vulnerability['attack_vector']
    attack_complexity = vulnerability['attack_complexity']
    impact_confidentiality = calculate_impact_CIA_scores(vulnerability['impact_conf'])
    impact_integrity = calculate_impact_CIA_scores(vulnerability['impact_integ'])
    impact_availability = calculate_impact_CIA_scores(vulnerability['impact_avail'])
    user_interaction = vulnerability['user_interaction']
    privilege_required = vulnerability['privilege_required']
    
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
    modified_attack_vector = calculate_attack_vector_scores(attack_vector, physical_security_score)
    modified_attack_complexity = calculate_attack_complexity_scores(attack_complexity)
    modified_privilege_required = calculate_privilege_required_scores(privilege_required, scope)
    modified_user_interaction = calculate_user_interaction_scores(user_interaction, personnel_training_score, operations_policies_score)

    ### ENVIRONMENTAL SCORE ###

    # call function to calculate the modified impact sub score (component of environmental score)
    modified_impact_sub_score = calculate_modified_impact_sub_score(
      modified_impact_confidentiality, confidentiality_requirement, modified_impact_integrity, integrity_requirement,
      modified_impact_availability, availability_requirement, modified_scope
    )

    # call function to calculate the modified exploitability sub score (component of environmental score)
    modified_exploitability_sub_score = calculate_modified_exploitability_sub_score(
      modified_attack_vector, modified_attack_complexity, modified_privilege_required, modified_user_interaction
    )

    # call function to calculate the environmental score (~ modified base score)
    environmental_score = calculate_environmental_score(
      modified_impact_sub_score, modified_exploitability_sub_score, modified_scope,
      exploit_code_maturity, remediation_level, report_confidence
    )

    # call function to modify environmental score based on APT threat score
    apt_threat_index = modify_environmental_score(environmental_score, apt_score)

    ### TEMPORAL SCORE ###
    # call function to calculate the temporal score using CVSSv3.1 equations
    temporal_score = calculate_temporal_score(base_score, exploit_code_maturity, remediation_level, report_confidence)

    scores_to_upload = {
      'temporal_score': temporal_score, 'environmental_score': environmental_score, 'apt_threat_index': apt_threat_index,
      'apt_score': apt_score, 'apt_reasoning': apt_reasoning
    }

    # append modified scores to combined vulnerabilities data
    for score in scores_to_upload:
      vulnerability[score] = scores_to_upload[score]

  # return modified score variables via combined vulnerabilities data to orchestration script
  return combined_vulnerabilities_data

 # # # # # # # # # # # # #
# # # TEMPORAL  SCORE # # #
 # # # # # # # # # # # # #

# define function to calculate the temporal score using CVSSv3.1 equations
def calculate_temporal_score(base_score, exploit_code_maturity, remediation_level, report_confidence):
  temporal_score = round_up_ten(base_score * exploit_code_maturity * remediation_level * report_confidence)

  return temporal_score

 # # # # # # # # # # # # # # #
# # # ENVIRONMENTAL SCORE # # #
 # # # # # # # # # # # # # # #

# NOTE: Environmental scores are using stock CVSSv3.1 equations

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
  modified_exploitability_sub_score = (
    8.22 * modified_attack_vector * modified_attack_complexity * modified_privilege_required * modified_user_interaction
  )
  
  return modified_exploitability_sub_score

# define function to calculate the environmental score using CVSSv3.1 equations
def calculate_environmental_score(
  modified_impact_sub_score, modified_exploitability_sub_score, modified_scope,
  exploit_code_maturity, remediation_level, report_confidence
):
  if modified_impact_sub_score <= 0:
    environmental_score = 0

  elif modified_scope == 'UNCHANGED':
    misXmes = (modified_impact_sub_score + modified_exploitability_sub_score)
    min_misXmes = min(misXmes, 10)
    rnd_min_misXmes = round_up_ten(min_misXmes)
    rnd_min_misXmes_ecm_rl_rc = (rnd_min_misXmes * exploit_code_maturity * remediation_level * report_confidence)
    environmental_score = round_up_ten(rnd_min_misXmes_ecm_rl_rc)

  elif modified_scope == 'CHANGED':
    misXmes = (1.08 * (modified_impact_sub_score + modified_exploitability_sub_score))
    min_misXmes = min(misXmes, 10)
    rnd_min_misXmes = round_up_ten(min_misXmes)
    rnd_min_misXmes_ecm_rl_rc = (rnd_min_misXmes * exploit_code_maturity * remediation_level * report_confidence)
    environmental_score = round_up_ten(rnd_min_misXmes_ecm_rl_rc)

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

# define function to calculate the APT threat index per vulnerability
# a.k.a. vulnerability threat when considering a specific APT provided
def modify_environmental_score(environmental_score, apt_score):
  modify_range, checked_environmental_score = calculate_modify_range(environmental_score)
  apt_score_modifier = modify_range * ((apt_score * 2) - 1)
  
  if apt_score_modifier < 0:
    apt_score_modifier = max(apt_score_modifier, -3.3)
  else:
    apt_score_modifier = min(apt_score_modifier, 3.3)

  apt_threat_index = round_up_ten(checked_environmental_score + apt_score_modifier)

  return apt_threat_index

# define function to calculate the modifiable range for the score
def calculate_modify_range(score):
  # calculate the range a score may vary (no more than the range to the nearest of 0 or 10)
  if score >= 0 and score <= 10:
    checked_score = score
    modify_range = min(abs(10 - score), abs(score - 10))

  # print error message to terminal if score is less than 0 and handle error
  elif score < 0:
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_modify_range() OF calculate_modified_scores.py:")
    print("<!>                          THE PROVIDED SCORE IS BELOW 0. HANDLING THE ERROR BY SETTING") 
    print("<!>                          MODIFY RANGE TO 0 AND THE SCORE to 0; CHECK THE SCORES DATA.")
    checked_score = 0 # corrects for possible errors in upstream function (score below 0)
    modify_range = 0

  # print error message to terminal if score is greater than 10 and handle error
  else: # score > 10
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_modify_range() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED SCORE IS ABOVE 10. HANDLING THE ERROR BY SETTING")
    print("<!>                          MODIFY RANGE TO 0 AND THE SCORE to 10; CHECK THE SCORES DATA.")
    checked_score = 10 # corrects for possible errors in upstream function (score above 10)
    modify_range = 0
  
  return modify_range, checked_score

# define function to calculate the CIA impact scores
def calculate_impact_CIA_scores(named_score):
  if named_score in ['HIGH', 'COMPLETE']:
    numbered_score = 0.56
  elif named_score in ['LOW', 'PARTIAL']:
    numbered_score = 0.22
  elif named_score == 'NONE':
    numbered_score = 0
  else: # handles error in the event the named score is not in the provided lists
    numbered_score = 0.56
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_impact_CIA_scores() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED NAMED SCORE IS NOT VALID. HANDLING THE ERROR BY SETTING")
    print("<!>                          NUMBERED SCORE TO 0.56; CHECK THE NAMED SCORES DATA FOR CIA IMPACT.")
  return numbered_score

# define function to calculate the attack vector scores
def calculate_attack_vector_scores(named_score, physical_security_score):
  if named_score in ['NETWORK']:
    numbered_score = 0.85
  elif named_score in ['ADJACENT', 'ADJACENT_NETWORK']:
    numbered_score = 0.62
  elif named_score in ['LOCAL']:
    numbered_score = 0.55 - round_up_hun((physical_security_score - 0.5) / 10)
  elif named_score in ['PHYSICAL']:
    numbered_score = 0.20 - round_up_hun((physical_security_score - 0.5) / 5)
  else: # handles error in the event the named score is not in the provided lists
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
  else: # handles error in the event the named score is not in the provided lists
    numbered_score = 0.77
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_attack_complexity_scores() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED NAMED SCORE IS NOT VALID. HANDLING THE ERROR BY SETTING")
    print("<!>                          NUMBERED SCORE TO 0.77; CHECK THE NAMED SCORES DATA FOR ATTACK COMPLEXITY.")
  return numbered_score

# define function to calculate the user interaction scores
def calculate_user_interaction_scores(named_score, personnel_training_score, operations_policies_score):
  if named_score in ['NONE', False]:
    numbered_score = 0.85
  elif named_score in ['REQUIRED', True]:
    personnel_training_modifier = round_up_hun((personnel_training_score - 0.5) / 2.5) # up to 0.20 points based on personnel training score
    operations_policies_modifier = round_up_hun((operations_policies_score - 0.5) / 5) # up to 0.10 points based on operations policies score
    numbered_score = 0.62 - personnel_training_modifier - operations_policies_modifier
  else:
    numbered_score = 0.85 # handles error in the event the named score is not in the provided lists
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_user_interaction_scores() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED NAMED SCORE IS NOT VALID. HANDLING THE ERROR BY SETTING")
    print("<!>                          NUMBERED SCORE TO 0.85; CHECK THE NAMED SCORES DATA FOR USER INTERACTION.")
  return numbered_score

# define function to calculate the user interaction scores
def calculate_privilege_required_scores(named_score, scope):
  # NOTE: CVSSv2 to v3.1 logic - both user privillege and authentication can be harded with strict policies.
  #       Both items are being used interchangeably for simplified scoring in this model.
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
    numbered_score = 0.85 # handles error in the event the named score is not in the provided lists
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
    CIA_requirement_scores = 1.0 # handles error in the event the named score is not in the provided lists
    print("<!> <TERMINAL ERROR MESSAGE> IN calculate_CIA_requirement_scores() OF calculate_modified_scores.py: ")
    print("<!>                          THE PROVIDED NUMBERED SCORE IS NOT VALID. HANDLING THE ERROR BY SETTING")
    print("<!>                          REQUIREMENTS SCORE TO 1; CHECK THE SCORES DATA FOR CRITICALITY MAPPING.")

  return CIA_requirement_scores

# define function to round up to one decimal precision
def round_up_ten(number):
  number = math.ceil(number * 10) / 10
  return number

# define function to round up to two decimal precision
def round_up_hun(number):
  number = math.ceil(number * 100) / 100
  return number

# set file locations/hard code some variables if this code is run to test
if __name__ == "__main__":
  with open('./sue_data/json_data/individual_files_archive/combined_vulnerabilities_data_file.json') as detected_vulnerabilities_file:
    combined_vulnerabilities_data = json.load(detected_vulnerabilities_file) # manually load combined_vulnerabilities_data
  cves = set([item["CVE Number"] for item in combined_vulnerabilities_data]) # disting set of detected CVE's
  with open('./sue_data/json_data/individual_files_archive/node_criticality_mapping_file.json') as node_criticality_mapping_file:
    node_criticality_mapping = json.load(node_criticality_mapping_file) # manually load node_criticality_mapping
  system_evaluation_scores = { # simulate being passed the 3P's
    'personnel_score': 0.45,
    'physical_security_score': 0.5,
    'policies_score': 0.55
  }
  apt_cve_evaluation_scores = {} # create empty dictionary for LLM APT score metrics

  for cve in cves:
    cve_number = cve # simulate CVE being analyzed against APT data
    apt_score = .52 # simulate creating LLM apt score for specified CVE
    reasoning = "reasoning ... ... ... blah blah blah ... APT's BAD!!!" # simulate creating LLM reasoning for APT score
    dictionary = {'apt_score': apt_score, 'reasoning': reasoning} # build sub-dictionary
    apt_cve_evaluation_scores[cve_number] = dictionary # append sub-dictionary to dictionary

  main(combined_vulnerabilities_data, node_criticality_mapping, system_evaluation_scores, apt_cve_evaluation_scores)

  # Print table of scores when running tests to verify results
  print_scores = ['CVE Number', 'base_score', 'temporal_score', 'environmental_score', 'apt_threat_index']

  print_table = [['CVE Number', 'Base', 'Temporal', 'Environmental', 'APT Threat Index']]

  for vulnerability in combined_vulnerabilities_data:
    table_append = []
    for score in print_scores:
      table_append.append(vulnerability[score])
    print_table.append(table_append)
  print_table.append(table_append)

  for row in print_table:
    print('|  {:<14}  |  {:^4}  |  {:^8}  |  {:^13}  |  {:^16}  |'.format(*row))
