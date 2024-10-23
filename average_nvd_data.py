import json
import math

# define main orchestration function
def main(combined_vulnerabilities_data):
  print(f"<TERMINAL MESSAGE> RUNNING 'average_nvd_data.py'; PLEASE STAND BY...")
  # define score componets from vulnerabilities data to average
  score_components = [
    'base_score', 'impact_score', 'exploitability_score', 'temporal_score', 'environmental_score', 'apt_threat_index'
  ]

  # build dictionary of average component scores
  score_components_averages = build_score_components_averages_dictionary(
    combined_vulnerabilities_data, # list of dictionaries of detected vulnerabilites with NVD data
    score_components # list of score components to average
  )

  print(f"<TERMINAL MESSAGE> RETURNING NVD SCORE COMPONENT AVERAGES...")
  return score_components_averages

def build_score_components_averages_dictionary(combined_vulnerabilities_data, score_components):
  print(f"<TERMINAL MESSAGE> CALCULATING NVD SCORE AVERAGES...")
  vulnerability_counter = 0 # variable to keep track of number of vulnerabilities
  score_components_averages = {} # create empty dictionary to store score compoenent averages in

  # initialize score components averages dictionary with components and set values to 0
  for component in score_components:
    score_components_averages[component] = 0

  # iterate through all vulnerabilites within vulnerabilities data adding component scores
  for vulnerability in combined_vulnerabilities_data:
    vulnerability_counter += 1 # add 1 to counter for each vulnerability iterated through

    # iterate through all components of score components list
    for component in score_components:
      # score_components_averages[component] += combined_vulnerabilities_data[vulnerability_counter-1].get(component)
      score_components_averages[component] += vulnerability.get(component)
  
  # divide each component score sum by total vulnerabilities
  for component_sum in score_components_averages:
    score_components_averages[component_sum] /= vulnerability_counter
    score_components_averages[component_sum] = math.ceil(score_components_averages[component_sum]*10)/10

  return score_components_averages # return score component averages to main()

# set file locations if this code is run directly/not called from another script
if __name__ == "__main__":
  combined_vulnerabilities_data_location = './sue_data_2.0/json_data/individual_files_archive/combined_vulnerabilities_data_file.json'

  with open(combined_vulnerabilities_data_location) as vulnerabilities_file: # open file
    combined_vulnerabilities_data = json.loads(vulnerabilities_file) # read file and save to variable

  # combined_vulnerabilities_list = ast.literal_eval(combined_vulnerabilities_data)
  main(combined_vulnerabilities_data)