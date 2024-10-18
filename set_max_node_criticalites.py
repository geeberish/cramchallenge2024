import math
import json

def main(
  combined_vulnerabilities_data,
  critical_functions_definitions_location,
  critical_functions_mapping_location
):
  with open(critical_functions_definitions_location) as critical_functions_definitions_file:
    critical_functions_definitions = json.load(critical_functions_definitions_file)
    print(f"type(critical_functions_definitions): {type(critical_functions_definitions)}")
    input()
  
  with open(critical_functions_mapping_location) as critical_functions_mapping_file:
    critical_functions_mapping = json.load(critical_functions_mapping_file)
    print(f"type(critical_functions_mapping): {type(critical_functions_mapping)}")
    input()

  nodes = set([item["CVE Number"] for item in combined_vulnerabilities_data]) # create distinct list of nodes
  categories = set([item["Node Category"] for item in combined_vulnerabilities_data]) # create distinct list node categories

  for vulnerability in combined_vulnerabilities_data:
    function_counter = 1
    vulnerability_max_criticality = 0

    for endpoint in critical_functions_mapping:
      endpoint_max_criticality = 0
      if endpoint["endpoint_node_name"] == vulnerability["Node Name"]:
        short_function_number = f"F{function_counter}"
        long_function_number = f"function_F{function_counter}"
        function_counter += 1

        for function in critical_functions_definitions:
          if function["function_number"] == short_function_number:
            if endpoint_max_criticality < function["criticality_value"]:
              endpoint_max_criticality = function["criticality_value"]
      if vulnerability_max_criticality < endpoint_max_criticality:
        vulnerability_max_criticality = endpoint_max_criticality
    print(f"Node: {vulnerability["Node Name"]} has a max criticality of {vulnerability_max_criticality}")

          

          


  
  for category in categories:
    for node in nodes:
      max_criticality = 0 # initiate max_criticality to store highest critical function value per node

      for vulnerability in combined_vulnerabilities_data:
        if vulnerability['Node Name'] == node:
          print("TBD")

        

  print("TBD")


if __name__ == "__main__":
  with open('./sue_data/json_data/detected_vulnerabilities.json') as detected_vulnerabilities_file:
    combined_vulnerabilities_data = json.load(detected_vulnerabilities_file)
  critical_functions_definitions_location = './sue_data/json_data/critical_functions_definition.json'
  critical_functions_mapping_location = './sue_data/json_data/critical_functions_mapping.json'
  
  main(
    combined_vulnerabilities_data,
    critical_functions_definitions_location,
    critical_functions_mapping_location
  )