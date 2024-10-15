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
                if hasattr(current_metrics, "cvssMetricV31") or hasattr(current_metrics, "cvssMetricV30"):
                    # set highest CVSS version for current vulnerability
                    if hasattr(current_metrics, "cvssMetricV31"):
                        cvss_version = "cvssMetricV31"
                    else:
                        cvss_version = "cvssMetric30"

                    # assign score component values
                    combined_list[index]["cvss_version"] = current_metrics[cvss_version][cvssData].get("version")
                    combined_list[index]["vector_string"] = current_metrics[cvss_version][cvssData].get("vectorString")
                    combined_list[index]["impact_conf"] = current_metrics[cvss_version][cvssData].get("confidentialityImpact")
                    combined_list[index]["impact_integ"] = current_metrics[cvss_version][cvssData].get("integrityImpact")
                    combined_list[index]["impact_avail"] = vulnerability.metrics[cvss_version].get("availabilityImpact")
                    combined_list[index]["scope_changed"] = current_metrics[cvss_version][cvssData].get("scope")
                    combined_list[index]["attack_vector"] = current_metrics[cvss_version][cvssData].get("attackVector")
                    combined_list[index]["attack_complexity"] = current_metrics[cvss_version][cvssData].get("attackComplexity")
                    combined_list[index]["privilege_required"] = current_metrics[cvss_version][cvssData].get("privilegesRequired")
                    combined_list[index]["user_interaction"] = current_metrics[cvss_version][cvssData].get("userInteraction")
                    # combined_list[index]["exploit_code_maturity"] = current_metrics[cvss_version][cvssData].get("confidentialityImpact")
                    # combined_list[index]["remediation_level"] = current_metrics[cvss_version][cvssData].get("confidentialityImpact")
                    # combined_list[index]["report_confidence"] = current_metrics[cvss_version][cvssData].get("confidentialityImpact")
                
                else:
                    # set highest CVSS version for current vulnerability
                    cvss_version = "cvssMetricV2"
                
                    # assign score component values
                    combined_list[index]["cvss_version"] = current_metrics[cvss_version][cvssData].get("version")
                    combined_list[index]["vector_string"] = current_metrics[cvss_version][cvssData].get("vectorString")
                    combined_list[index]["impact_conf"] = current_metrics[cvss_version][cvssData].get("confidentialityImpact")
                    combined_list[index]["impact_integ"] = current_metrics[cvss_version][cvssData].get("integrityImpact")
                    combined_list[index]["impact_avail"] = vulnerability.metrics[cvss_version].get("availabilityImpact")
                    # combined_list[index]["scope_changed"] = current_metrics[cvss_version][cvssData].get("scope")
                    combined_list[index]["attack_vector"] = current_metrics[cvss_version][cvssData].get("accessVector")
                    combined_list[index]["attack_complexity"] = current_metrics[cvss_version][cvssData].get("accessComplexity")
                    combined_list[index]["privilege_required"] = current_metrics[cvss_version][cvssData].get("authentication")
                    combined_list[index]["user_interaction"] = current_metrics[cvss_version][cvssData].get("userInteractionRequired")
                    # combined_list[index]["exploit_code_maturity"] = current_metrics[cvss_version][cvssData].get("confidentialityImpact")
                    # combined_list[index]["remediation_level"] = current_metrics[cvss_version][cvssData].get("confidentialityImpact")
                    # combined_list[index]["report_confidence"] = current_metrics[cvss_version][cvssData].get("confidentialityImpact")
            # print(combined_list)
