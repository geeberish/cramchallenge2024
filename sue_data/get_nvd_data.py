import subprocess
import sys

# function to install a package
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

install('nvdlib') # install nvdlib

import json
import nvdlib

# Read the NIST NVD API key from the file
with open('../.aws/nvd_api_key.txt') as key_file:
    nvd_api_key = key_file.read() # NIST NVD API key file location
vulnerabilities_list = list() # create an empty list to use for detected vulnerabilities data
combined_list = list() # create an empy list to use for combined nodes with vulnerabilities

# pull NVD data for all detected vulnerabilities
with open('./sue_data/json_data/detected_vulnerabilities.json') as data_file:    
    data = json.load(data_file) # load data from detected vulnerabilities json file
    cves =set([item["CVE Number"] for item in data]) # create distinct list of CVE's detected

    # iterate through CVE's detected and pull data for each CVE
    for cve_id in cves:
        cve_search = nvdlib.searchCVE(cveId=cve_id, key=nvd_api_key, delay=1)[0] # search current CVE
        vulnerabilities_list.append(cve_search) # append current CVE data to vulnerabilities list

    combined_list = data # create a copy of data as combined_list

    # combined vulnerabilities discovered and required score components to combined list
    for index in range(len(combined_list)):
        current_cve = combined_list[index].get("CVE Number")
        
        # assign value for confidentiality impact
        for vulnerability in vulnerabilities_list:
            if vulnerability.id == current_cve:
                current_metrics = vulnerability.metrics # create dictionary of current vulnerability metrics

                # combine detected vulnerabilities list with score component data into combined list
                if hasattr(vulnerability.metrics, "cvssMetricV31"):
                    # assign score component values
                    combined_list[index]["cvss_version"] = 3.1
                    combined_list[index]["vector_string"] = vulnerability.v31vector
                    combined_list[index]["impact_conf"] = vulnerability.v31confidentialityImpact 
                    combined_list[index]["impact_integ"] = vulnerability.v31integrityImpact 
                    combined_list[index]["impact_avail"] = vulnerability.v31availabilityImpact 
                    combined_list[index]["scope_changed"] = vulnerability.v31scope 
                    combined_list[index]["attack_vector"] = vulnerability.v31attackVector 
                    combined_list[index]["attack_complexity"] = vulnerability.v31attackComplexity 
                    combined_list[index]["privilege_required"] = vulnerability.v31privilegesRequired 
                    combined_list[index]["user_interaction"] = vulnerability.v31userInteraction 
                    # combined_list[index]["exploit_code_maturity"] = vulnerability.
                    # combined_list[index]["remediation_level"] = vulnerability.
                    # combined_list[index]["report_confidence"] = vulnerability.
                
                elif hasattr(vulnerability.metrics, "cvssMetricV30"):
                    # assign score component values
                    combined_list[index]["cvss_version"] = 3.0
                    combined_list[index]["vector_string"] = vulnerability.v30vector
                    combined_list[index]["impact_conf"] = vulnerability.v31confidentialityImpact
                    combined_list[index]["impact_integ"] = vulnerability.v31integrityImpact
                    combined_list[index]["impact_avail"] = vulnerability.v31availabilityImpact
                    combined_list[index]["scope_changed"] = vulnerability.v31scope
                    combined_list[index]["attack_vector"] = vulnerability.v31attackVector
                    combined_list[index]["attack_complexity"] = vulnerability.v31attackComplexity
                    combined_list[index]["privilege_required"] = vulnerability.v31privilegesRequired
                    combined_list[index]["user_interaction"] = vulnerability.v31userInteraction
                    # combined_list[index]["exploit_code_maturity"] = vulnerability.
                    # combined_list[index]["remediation_level"] = vulnerability.
                    # combined_list[index]["report_confidence"] = vulnerability.

                else:  
                    # assign score component values
                    combined_list[index]["cvss_version"] = 2.0
                    combined_list[index]["vector_string"] = vulnerability.v2vector
                    combined_list[index]["impact_conf"] = vulnerability.v2confidentialityImpact
                    combined_list[index]["impact_integ"] = vulnerability.v2integrityImpact
                    combined_list[index]["impact_avail"] = vulnerability.v2availabilityImpact
                    # combined_list[index]["scope_changed"] = vulnerability.
                    combined_list[index]["attack_vector"] = vulnerability.v2accessVector
                    combined_list[index]["attack_complexity"] = vulnerability.v2accessComplexity 
                    # combined_list[index]["privilege_required"] = vulnerability.
                    # combined_list[index]["user_interaction"] = vulnerability.
                    # combined_list[index]["exploit_code_maturity"] = vulnerability.
                    # combined_list[index]["remediation_level"] = vulnerability.
                    # combined_list[index]["report_confidence"] = vulnerability.
                break
            print(combined_list)
