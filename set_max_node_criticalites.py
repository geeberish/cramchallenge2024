import math

def main(
  combined_vulnerabilities_data,
  critical_functions_definitions_location,
  critical_functions_mapping_location
):
  with open(critical_functions_definitions_location) as critical_functions_definitions_file:
    critical_functions_definitions = critical_functions_definitions_file.read()
    print(f"type(critical_functions_definitions): {type(critical_functions_definitions)}")
    input()
  
  with open(critical_functions_mapping_location) as critical_functions_mapping_file:
    critical_functions_mapping = critical_functions_mapping_file.read()
    print(f"type(critical_functions_mapping): {type(critical_functions_mapping)}")
    input()

  for vulnerability in combined_vulnerabilities_data:
    max_criticality = 0 # initiate max_criticality to store highest critical function value per node
  print("TBD")


if __name__ == "__main__":
  print("TBD")