import json
import os

def load_nvd_data(directory):
    nvd_data = {}
    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            file_path = os.path.join(directory, filename)
            try:
                with open(file_path, 'r') as file:
                    year_data = json.load(file)
                    for cve_item in year_data.get("CVE_Items", []):
                        cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
                        nvd_data[cve_id] = cve_item
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON from file {filename}: {e}")
    return nvd_data

def load_cve_list(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def extract_vulnerability_data(cve_data):
    data = {}
    
    # Extract CVSS v3 data if available
    impact_v3 = cve_data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
    impact_v2 = cve_data.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {})
    
    # Use v3 if available, otherwise fall back to v2
    data["vector_string"] = impact_v3.get("vectorString") or impact_v2.get("vectorString")
    data["impact_integ"] = impact_v3.get("integrityImpact") or impact_v2.get("integrityImpact")
    data["cvss_version"] = impact_v3.get("version") or impact_v2.get("version")
    data["user_interaction"] = impact_v3.get("userInteraction") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("userInteractionRequired")
    
    # Convert scores to float
    data["base_score"] = float(impact_v3.get("baseScore") or impact_v2.get("baseScore") or 0.0)
    data["impact_conf"] = impact_v3.get("confidentialityImpact") or impact_v2.get("confidentialityImpact")
    data["impact_score"] = float(cve_data.get("impact", {}).get("baseMetricV3", {}).get("impactScore") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("impactScore") or 0.0)
    data["privilege_required"] = impact_v3.get("privilegesRequired") or impact_v2.get("authentication")
    data["attack_vector"] = impact_v3.get("attackVector") or impact_v2.get("accessVector")
    data["impact_avail"] = impact_v3.get("availabilityImpact") or impact_v2.get("availabilityImpact")
    data["scope_changed"] = impact_v3.get("scope")
    data["exploitability_score"] = float(cve_data.get("impact", {}).get("baseMetricV3", {}).get("exploitabilityScore") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("exploitabilityScore") or 0.0)
    
    # Keep base_severity as a string
    data["base_severity"] = impact_v3.get("baseSeverity") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("severity")
    
    data["attack_complexity"] = impact_v3.get("attackComplexity") or impact_v2.get("accessComplexity")

    description_data = cve_data.get('cve', {}).get('description', {}).get('description_data', [])
    if description_data:
        data["description"] = description_data[0].get('value')
    
    return data

# Adjust other parts of the script to ensure they handle strings correctly

def combine_node_and_cve_info(node_info, found_vulnerabilities):
    combined_info_list = []
    
    for node in node_info:
        cve_id = node['CVE Number']
        if cve_id in found_vulnerabilities:
            combined_info = {**node, **found_vulnerabilities[cve_id]}
            combined_info_list.append(combined_info)
    
    return combined_info_list

def main(dv_file_path):
    nvd_data_directory = "/Users/mattpenn/Downloads/NIST NVD DATA"  # Adjust this path as needed
    nvd_data = load_nvd_data(nvd_data_directory)
    
    # Load CVE list from a file
    node_info_file_path = dv_file_path  # Adjust this path as needed
    node_info_list = load_cve_list(node_info_file_path)
    
    found_vulnerabilities = {}
    
    for node in node_info_list:
        cve_id = node['CVE Number']
        if cve_id in nvd_data:
            found_vulnerabilities[cve_id] = extract_vulnerability_data(nvd_data[cve_id])
    
    combined_info_list = combine_node_and_cve_info(node_info_list, found_vulnerabilities)
    
    # Store the combined information in a variable for later use
    stored_combined_information = combined_info_list
    return stored_combined_information
    
    # Example: Print the stored information
    # for info in stored_combined_information:
    #     print(json.dumps(info, indent=4))
    #     print('---')

if __name__ == "__main__":
    test = main('sue_data_2.0/json_data/detected_vulnerabilities.json')
    print(test)





# import json
# import os

# def load_nvd_data(directory):
#     nvd_data = {}
#     for filename in os.listdir(directory):
#         if filename.endswith(".json"):
#             file_path = os.path.join(directory, filename)
#             try:
#                 with open(file_path, 'r') as file:
#                     year_data = json.load(file)
#                     for cve_item in year_data.get("CVE_Items", []):
#                         cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
#                         nvd_data[cve_id] = cve_item
#             except json.JSONDecodeError as e:
#                 print(f"Error decoding JSON from file {filename}: {e}")
#     return nvd_data

# def load_cve_list(file_path):
#     with open(file_path, 'r') as file:
#         return json.load(file)

# def extract_vulnerability_data(cve_data):
#     data = {}
    
#     # Extract CVSS v3 data if available
#     impact_v3 = cve_data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
#     impact_v2 = cve_data.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {})
    
#     # Use v3 if available, otherwise fall back to v2
#     data["vector_string"] = impact_v3.get("vectorString") or impact_v2.get("vectorString")
#     data["impact_integ"] = impact_v3.get("integrityImpact") or impact_v2.get("integrityImpact")
#     data["cvss_version"] = impact_v3.get("version") or impact_v2.get("version")
#     data["user_interaction"] = impact_v3.get("userInteraction") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("userInteractionRequired")
#     data["base_score"] = impact_v3.get("baseScore") or impact_v2.get("baseScore")
#     data["impact_conf"] = impact_v3.get("confidentialityImpact") or impact_v2.get("confidentialityImpact")
#     data["impact_score"] = cve_data.get("impact", {}).get("baseMetricV3", {}).get("impactScore") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("impactScore")
#     data["privilege_required"] = impact_v3.get("privilegesRequired") or impact_v2.get("authentication")
#     data["attack_vector"] = impact_v3.get("attackVector") or impact_v2.get("accessVector")
#     data["impact_avail"] = impact_v3.get("availabilityImpact") or impact_v2.get("availabilityImpact")
#     data["scope_changed"] = impact_v3.get("scope")
#     data["exploitability_score"] = cve_data.get("impact", {}).get("baseMetricV3", {}).get("exploitabilityScore") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("exploitabilityScore")
#     data["base_severity"] = impact_v3.get("baseSeverity") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("severity")
#     data["attack_complexity"] = impact_v3.get("attackComplexity") or impact_v2.get("accessComplexity")

#     description_data = cve_data.get('cve', {}).get('description', {}).get('description_data', [])
#     if description_data:
#         data["description"] = description_data[0].get('value')
    
#     return data

# def combine_node_and_cve_info(node_info, found_vulnerabilities):
#     combined_info_list = []
    
#     for node in node_info:
#         cve_id = node['CVE Number']
#         if cve_id in found_vulnerabilities:
#             combined_info = {**node, **found_vulnerabilities[cve_id]}
#             combined_info_list.append(combined_info)
    
#     return combined_info_list

# def main(detected_vuln_path):
#     nvd_data_directory = "/Users/mattpenn/Downloads/NIST NVD DATA"  # Adjust this path as needed
#     nvd_data = load_nvd_data(nvd_data_directory)
    
#     # Load CVE list from a file
#     node_info_file_path = detected_vuln_path # Adjust this path as needed
#     node_info_list = load_cve_list(node_info_file_path)
    
#     found_vulnerabilities = {}
    
#     for node in node_info_list:
#         cve_id = node['CVE Number']
#         if cve_id in nvd_data:
#             found_vulnerabilities[cve_id] = extract_vulnerability_data(nvd_data[cve_id])
    
#     combined_info_list = combine_node_and_cve_info(node_info_list, found_vulnerabilities)
    
#     # Store the combined information in a variable for later use
#     stored_combined_information = combined_info_list
#     #print(stored_combined_information)
#     return stored_combined_information
    
#     # Example: Print the stored information
#     # for info in stored_combined_information:
#     #     print(json.dumps(info, indent=4))
#     #     print('---')

# if __name__ == "__main__":
#     test = main('sue_data_2.0/json_data/detected_vulnerabilities.json')
#     print(test)








# import json
# import os

# def load_nvd_data(directory):
#     nvd_data = {}
#     for filename in os.listdir(directory):
#         if filename.endswith(".json"):
#             file_path = os.path.join(directory, filename)
#             try:
#                 with open(file_path, 'r') as file:
#                     year_data = json.load(file)
#                     for cve_item in year_data.get("CVE_Items", []):
#                         cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
#                         nvd_data[cve_id] = cve_item
#             except json.JSONDecodeError as e:
#                 print(f"Error decoding JSON from file {filename}: {e}")
#     return nvd_data

# def load_cve_list(file_path):
#     with open(file_path, 'r') as file:
#         return json.load(file)

# def extract_vulnerability_data(cve_data):
#     data = {}
    
#     # Extract CVSS v3 data if available
#     impact_v3 = cve_data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
#     impact_v2 = cve_data.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {})
    
#     # Use v3 if available, otherwise fall back to v2
#     data["vector_string"] = impact_v3.get("vectorString") or impact_v2.get("vectorString")
#     data["impact_integ"] = impact_v3.get("integrityImpact") or impact_v2.get("integrityImpact")
#     data["cvss_version"] = impact_v3.get("version") or impact_v2.get("version")
#     data["user_interaction"] = impact_v3.get("userInteraction") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("userInteractionRequired")
#     data["base_score"] = impact_v3.get("baseScore") or impact_v2.get("baseScore")
#     data["impact_conf"] = impact_v3.get("confidentialityImpact") or impact_v2.get("confidentialityImpact")
#     data["impact_score"] = cve_data.get("impact", {}).get("baseMetricV3", {}).get("impactScore") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("impactScore")
#     data["privilege_required"] = impact_v3.get("privilegesRequired") or impact_v2.get("authentication")
#     data["attack_vector"] = impact_v3.get("attackVector") or impact_v2.get("accessVector")
#     data["impact_avail"] = impact_v3.get("availabilityImpact") or impact_v2.get("availabilityImpact")
#     data["scope_changed"] = impact_v3.get("scope")
#     data["exploitability_score"] = cve_data.get("impact", {}).get("baseMetricV3", {}).get("exploitabilityScore") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("exploitabilityScore")
#     data["base_severity"] = impact_v3.get("baseSeverity") or cve_data.get("impact", {}).get("baseMetricV2", {}).get("severity")
#     data["attack_complexity"] = impact_v3.get("attackComplexity") or impact_v2.get("accessComplexity")

#     description_data = cve_data.get('cve', {}).get('description', {}).get('description_data', [])
#     if description_data:
#         data["description"] = description_data[0].get('value')
    
#     return data

# def find_vulnerabilities(nvd_data, cve_list):
#     found_vulnerabilities = {}
#     for cve_id in cve_list:
#         if cve_id in nvd_data:
#             found_vulnerabilities[cve_id] = extract_vulnerability_data(nvd_data[cve_id])
#         else:
#             print(f"No data found for {cve_id}")
#     return found_vulnerabilities

# def main():
#     nvd_data_directory = "/Users/mattpenn/Downloads/NIST NVD DATA"  # Adjust this path as needed
#     nvd_data = load_nvd_data(nvd_data_directory)
    
#     # Load CVE list from a file
#     cve_list_file = "cve_list.json"  # Adjust this path as needed
#     cve_list = load_cve_list(cve_list_file)
    
#     found_vulnerabilities = find_vulnerabilities(nvd_data, cve_list)
#     print(found_vulnerabilities)
    
#     # Print or process the found vulnerabilities
#     # for cve_id, details in found_vulnerabilities.items():
#     #     print(f"CVE Number: {cve_id}")
#     #     for key, value in details.items():
#     #         print(f"{key}: {value}")
#     #     print('---')

# if __name__ == "__main__":
#     main()
