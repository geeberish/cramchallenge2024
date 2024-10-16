import subprocess
import sys

# function to install a package
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

install('nvdlib')

import json
import nvdlib

vulnerabilities_list = list() # create an empty list to use for detected vulnerabilities data
combined_list = list() # create an empy list to use for combined nodes with vulnerability data

def main(nvd_api_key_file_location, vulnerabilities_detected_file_location):
    # read the NIST NVD API key from the file
    with open(nvd_api_key_file_location) as key_file:
        nvd_api_key = key_file.read() # read API key file to variable
    # call function to extract distinct CVE numbers from detected vulnerabilities file
    get_detected_vulnerabilities(nvd_api_key, vulnerabilities_detected_file_location)
    build_vulnerability_data()

def get_detected_vulnerabilities(nvd_api_key, vulnerabilities_detected_file_location):
    global combined_list
    # pull NVD data for all detected vulnerabilities
    with open(vulnerabilities_detected_file_location) as data_file:   
        data = json.load(data_file) # load data from detected vulnerabilities json file
        combined_list = data # load combined list with detected vulnerabilities
        cves =set([item["CVE Number"] for item in data]) # create distinct list of CVE's detected

        # iterate through CVE's detected and pull data for each CVE
        for cve_id in cves:
            cve_search = nvdlib.searchCVE(cveId=cve_id, key=nvd_api_key, delay=10)[0] # search current CVE
            # cve_search = nvdlib.searchCVE(cveId=cve_id)[0]
            vulnerabilities_list.append(cve_search) # append current CVE data to vulnerabilities list

def build_vulnerability_data():
    global combined_list
    # combined vulnerabilities discovered and CVE score components to combined list
    for index in range(len(combined_list)):
        current_cve = combined_list[index].get("CVE Number")     
        
        # assign score component values
        combined_list[index]["cvss_version"] = append_cve_data(current_cve, "version", "version")
        combined_list[index]["vector_string"] = append_cve_data(current_cve, "vectorString", "vectorString")
        combined_list[index]["attack_vector"] = append_cve_data(current_cve, "attackVector", "accessVector")
        combined_list[index]["attack_complexity"] = append_cve_data(current_cve, "attackComplexity", "accessComplexity")
        combined_list[index]["privilege_required"] = append_cve_data(current_cve, "privilegesRequired", "authentication")
        combined_list[index]["user_interaction"] = append_cve_data(current_cve, "userInteraction", "userInteractionRequired")
        combined_list[index]["scope_changed"] = append_cve_data(current_cve, "scope", "NA")
        combined_list[index]["impact_conf"] = append_cve_data(current_cve, "confidentialityImpact", "confidentialityImpact")
        combined_list[index]["impact_integ"] = append_cve_data(current_cve, "integrityImpact", "integrityImpact")
        combined_list[index]["impact_avail"] = append_cve_data(current_cve, "availabilityImpact", "availabilityImpact")
        combined_list[index]["base_score"] = append_cve_data(current_cve, "baseScore", "baseScore")
        combined_list[index]["base_severity"] = append_cve_data(current_cve, "baseSeverity", "baseSeverity")
        combined_list[index]["exploitability_score"] = append_cve_data(current_cve, "exploitabilityScore", "exploitabilityScore")
        combined_list[index]["impact_score"] = append_cve_data(current_cve, "impactScore", "impactScore")
        # combined_list[index]["exploit_code_maturity"] = vulnerability.
        # combined_list[index]["remediation_level"] = vulnerability.
        # combined_list[index]["report_confidence"] = vulnerability.
        
def append_cve_data(current_cve, v3score_component, v2score_component):
    global vulnerabilities_list

    for vulnerability in vulnerabilities_list:
        if vulnerability.id == current_cve:
            metrics = getattr(vulnerability, 'metrics')

            if metrics:  # Check if metrics attribute exists and is not None
                first_metric = next((m for m in metrics if hasattr(m, 'cvssData')), None)
                if first_metric:
                    if hasattr(first_metric.cvssData, v3score_component):
                        return getattr(first_metric.cvssData, v3score_component)
                    elif hasattr(first_metric.cvssData, v2score_component):
                        return getattr(first_metric.cvssData, v2score_component)
                    else:
                        return "NO_METRIC"
                else:
                    return "ERROR: No cvssData found in metrics"
            else:
                return "ERROR: No metrics attribute found in vulnerability"

# set file locations if this code is run directly/not called from another script
if __name__ == "__main__":
    nvd_api_key_file_location = '../.aws/nvd_api_key.txt' # sets NIST NVD API key location
    vulnerabilities_detected_file_location = './sue_data/json_data/detected_vulnerabilities.json' # sets vulnerabilities detected file location
    main(nvd_api_key_file_location, vulnerabilities_detected_file_location) # passes both variables to main() to run script
    print("************************BEGIN DETECTED VULNERABILITIES SUMMARY************************")
    print()
    for entry in combined_list:
        print(entry)
        print()
        print("**********************************************************************************")
        print()