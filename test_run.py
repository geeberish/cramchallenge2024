from get_nvd_data import main as get_nvd_data_main
from set_max_node_criticalites import main as set_max_node_criticalities_main
from average_nvd_data import main as average_nvd_data_main
from calculate_modified_scores import main as calculate_modified_scores_main

combined_vulnerabilities_data = get_nvd_data_main(
  '../.aws/nvd_api_key.txt', # path of NIST NVD API KEY text file
  './sue_data/json_data/detected_vulnerabilities.json' # path of detected vulnerabilities file
)

###################################### TEMPORARY FILLER DATA ######################################
# FIXME
system_evaluation_scores = {
    'personnel_score': 0.5,
    'physical_security_score': 0.5,
    'policies_score': 0.5
  }
cves = set([item["CVE Number"] for item in combined_vulnerabilities_data])
apt_cve_evaluation_scores = {}
for cve in cves:
  cve_number = cve
  apt_score = 0.5
  reasoning = "reasoning ... ... ... blah blah blah ... APT's BAD!!!"
  dictionary = {'apt_score': apt_score, 'reasoning': reasoning}
  apt_cve_evaluation_scores[cve_number] = dictionary
# FIXME
###################################### TEMPORARY FILLER DATA ######################################

node_criticality_mapping = set_max_node_criticalities_main(
  combined_vulnerabilities_data, # list of dictionaries of vulnerability data
  './sue_data/json_data/critical_functions_definition.json', # path of critical functions definitions file
  './sue_data/json_data/critical_functions_mapping.json', # path of critical functions mapping file
)

scored_combined_vulnerabilities_data = calculate_modified_scores_main(
  combined_vulnerabilities_data, # list of dictionaries of vulnerability data
  node_criticality_mapping, # dictionary of nodes with max node criticality rating per node
  system_evaluation_scores,
  apt_cve_evaluation_scores
)

score_component_averages = average_nvd_data_main(
  scored_combined_vulnerabilities_data # list of dictionaries of vulnerability data with modified scores
)