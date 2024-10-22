import json

def main(
  combined_vulnerabilities_data, # list of dictionaries of vulnerability data
  critical_functions_definitions_location, # path of critical functions definitions file
  critical_functions_mapping_location # path of critical functions mapping file
):
  # open critical functions definitions file and create variable of list of dictionaries
  with open(critical_functions_definitions_location) as critical_functions_definitions_file:
    critical_functions_definitions = json.load(critical_functions_definitions_file)
  
  # open critical functions mapping file and create variable of list of dictionaries
  with open(critical_functions_mapping_location) as critical_functions_mapping_file:
    critical_functions_mapping = json.load(critical_functions_mapping_file)

  # call function to create dictionary mapping functions to nodes
  node_function_mapping = create_node_function_mapping(
    combined_vulnerabilities_data, # list of dictionaries of detected vulnerabilities
    critical_functions_mapping # list of dictionaries of endpoint node name to function number(s)
  )

  # call function to create dictionary mapping nodes to categories
  node_category_mapping = create_node_category_mapping(
    combined_vulnerabilities_data, # list of dictionaries of detected vulnerabilities
  )
  
  # call function to create dictionary mapping functions to criticality 
  function_criticality_mapping = create_function_criticality_mapping(
    critical_functions_definitions # list of dictionaries of function number to criticality value
  )

  # call function to map dictionary mapping nodes to criticality
  node_criticality_mapping = create_node_criticality_mapping(
    node_function_mapping, # dictionary of node to list of function number list mappings
    function_criticality_mapping # dictionary of function number to criticiality score
  )

  # call function to create dictionary mapping functions to node categories
  category_criticality_mapping = create_category_criticality_mapping(
    node_category_mapping,
    node_criticality_mapping
  )

  # call function to update dictionary mapping criticality to node categories
  node_criticality_mapping = update_node_criticality_mapping(
    node_criticality_mapping,
    node_category_mapping,
    category_criticality_mapping
  )

  return node_criticality_mapping

# define function to create dictionary mapping functions to nodes
# format is {node_name: [function_numbers]} i.e. {Test SAN Archive: [F4, F8, F9]}
def create_node_function_mapping(combined_vulnerabilities_data, critical_functions_mapping):
  node_function_mapping = {} # create empty dictionary for node function values

  for vulnerability in combined_vulnerabilities_data:
    node_function_mapping[vulnerability["Node Name"]] = []
    for function in critical_functions_mapping:
      if vulnerability["Node Name"] == function["endpoint_node_name"]:
        for entry in function:
            if function[entry] == 1:
              node_function_mapping[vulnerability["Node Name"]].append(entry.replace("function_", ""))
        break

  return node_function_mapping

# define function to create dictionary mapping nodes to categories
# format is {category: [function_numbers]} i.e. {Test SAN Archive: [F4, F8, F9]}
def create_node_category_mapping(combined_vulnerabilities_data):
  node_category_mapping = {} # create empty dictionary for node category function values
  categories = set([item["Node Category"] for item in combined_vulnerabilities_data]) # create distinct list of CVE's detected

  for category in categories:
    node_category_mapping[category] = []

    for vulnerability in combined_vulnerabilities_data:
      if vulnerability["Node Category"] == category:
        if vulnerability["Node Name"] not in node_category_mapping[category]:
          node_category_mapping[category].append(vulnerability["Node Name"])

  return node_category_mapping


# define function to create dictionary mapping functions to criticality
def create_function_criticality_mapping(critical_functions_definitions):
  function_criticality_mapping = {} # create empty dictionary for function criticality values

  for function in critical_functions_definitions:
    function_criticality_mapping[function["function_number"]] = function["criticality_value"]
  
  return function_criticality_mapping

# define function to map dictionary mapping nodes to criticality
def create_node_criticality_mapping(node_function_mapping, function_criticality_mapping):
  node_criticality_mapping = {} # create empty dictionary for node to max criticality value
  max_node_criticality = 0

  for node in node_function_mapping:
    for function in node_function_mapping[node]:
      if function_criticality_mapping[function] > max_node_criticality:
        max_node_criticality = function_criticality_mapping[function]
    
    node_criticality_mapping[node] = max_node_criticality
    max_node_criticality = 0
  
  return node_criticality_mapping

# define function to create dictionary mapping functions to nodes
# format is {category: [function_numbers]} i.e. {Test SAN Archive: [F4, F8, F9]}
def create_category_criticality_mapping(node_category_mapping, node_criticality_mapping):
  category_criticality_mapping = {} # create empty dictionary for node category function values
  category_max_criticality = 0

  for category in node_category_mapping:
    for node in node_category_mapping[category]:
      if node_criticality_mapping[node] > category_max_criticality:
        category_max_criticality = node_criticality_mapping[node]
    
    category_criticality_mapping[category] = category_max_criticality

    category_max_criticality = 0

  return category_criticality_mapping

def  update_node_criticality_mapping(node_criticality_mapping, node_category_mapping, category_criticality_mapping):
  for node in node_criticality_mapping:
    if node_criticality_mapping[node] == 0:
      for category in node_category_mapping:
        if node in node_category_mapping[category]:
          node_criticality_mapping[node] = category_criticality_mapping[category]
          break
  
  # output json representation of node criticality mapping
  # with open('./sue_data/json_data/individual_files_archive/node_criticality_mapping_file.json', 'w') as json_file:
  #   json.dump(node_criticality_mapping, json_file, indent=4)  # 'indent=4' for pretty-printing

  # FIXME
  # return category_criticality_mapping

  return node_criticality_mapping

if __name__ == "__main__":
  with open('./sue_data_1.0/json_data/detected_vulnerabilities.json') as detected_vulnerabilities_file:
    combined_vulnerabilities_data = json.load(detected_vulnerabilities_file)
  critical_functions_definitions_location = './sue_data_1.0/json_data/critical_functions_definition.json'
  critical_functions_mapping_location = './sue_data_1.0/json_data/critical_functions_mapping.json'
  
  main(
    combined_vulnerabilities_data,
    critical_functions_definitions_location,
    critical_functions_mapping_location
  )