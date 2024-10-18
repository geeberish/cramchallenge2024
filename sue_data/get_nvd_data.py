import subprocess # a module used to run new codes and applications by creating new processes
import sys # a module that provides access to system-specific parameters and functions
import json # a module to work with JSON data

# function to install a package
# def install(package):
#     subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# NEW VERSION
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package], stdout=subprocess.DEVNULL)

install('nvdlib') # call function to install nvdlib

import nvdlib # a module to interface with the NIST NVD database to pull CVEs and CPEs as objects

def main(nvd_api_key_file_location, vulnerabilities_detected_file_location):
    # read the NIST NVD API key from the file
    with open(nvd_api_key_file_location) as key_file:
        nvd_api_key = key_file.read() # read API key file to variable
    vulnerabilities_list = list() # create an empty list to use for detected vulnerabilities data
    combined_vulnerabilities_data = []

    # call function to extract data from detected vulnerabilities file
    vulnerability_data = make_detected_vulnerabilities_data(vulnerabilities_detected_file_location)

    # call function to extract distinct CVE numbers from detected vulnerabilities file
    vulnerabilities_list = get_detected_vulnerabilities_list(
        nvd_api_key, # API key for NIST NVD API
        vulnerability_data, # detected vulnerabilities data
        vulnerabilities_list, # empty vulnerabilities list
    )

    # take detected vulnerabilities data and append individual CVE metrics score component data to it
    combined_vulnerabilities_data = build_vulnerability_data(vulnerabilities_list, vulnerability_data)

    return combined_vulnerabilities_data

def make_detected_vulnerabilities_data(vulnerabilities_detected_file_location):
    # open detected vulnerabilities file and assign to data variable
    with open(vulnerabilities_detected_file_location) as vulnerabilities_detected_file:   
        vulnerability_data = json.load(vulnerabilities_detected_file) # load data from detected vulnerabilities json file
    return vulnerability_data

def get_detected_vulnerabilities_list(nvd_api_key, vulnerabilities_data, vulnerabilities_list):
        cves = set([item["CVE Number"] for item in vulnerabilities_data]) # create distinct list of CVE's detected

        # iterate through CVE's detected and pull data for each CVE
        for cve_id in cves:
            cve_search = nvdlib.searchCVE(cveId=cve_id, key=nvd_api_key, delay=1.2)[0] # search current CVE
            # cve_search = nvdlib.searchCVE(cveId=cve_id)[0] # options for searching without an NVD API key
            vulnerabilities_list.append(cve_search) # append current CVE data to vulnerabilities list
        
        return vulnerabilities_list # return filled vulnerabilities_list to main function

def build_vulnerability_data(vulnerabilities_list, vulnerability_data):
    combined_vulnerabilities_data = []
    # combined vulnerabilities discovered and CVE score components to combined list
    for vulnerability_detected in range(len(vulnerability_data)):
        current_cve = vulnerability_data[vulnerability_detected].get("CVE Number")
        
        # # assign score component values
        # vulnerability_data[vulnerability_detected][component_variable] = append_cve_data(
        #     current_cve_metrics_data, # current CVE's highest CVSS version metrics data
        #     score_component_version_names # list of CVSS score component variables and version names
        # )

        # mapping of componenet variables to CVSSv3 and v2 attribute names
        score_component_version_names = [ # ['component_variable', 'component_v3_name', 'component_v2_name']
            ["vector_string", "vectorString", "vectorString"], ["impact_integ", "integrityImpact", "integrityImpact"],
            ["cvss_version", "version", "version"], ["user_interaction", "userInteraction", "userInteractionRequired"],
            ["base_score", "baseScore", "baseScore"], ["impact_conf", "confidentialityImpact", "confidentialityImpact"],
            ["impact_score", "impactScore", "impactScore"], ["privilege_required", "privilegesRequired", "authentication"],
            ["attack_vector", "attackVector", "accessVector"], ["impact_avail", "availabilityImpact", "availabilityImpact"],
            ["scope_changed", "scope", "NA_METRIC"], ["exploitability_score", "exploitabilityScore", "exploitabilityScore"],
            ["base_severity", "baseSeverity", "baseSeverity"], ["attack_complexity", "attackComplexity", "accessComplexity"]
        ]

        # call function to pull metrics for current CVE
        current_cve_metrics_dictionary = select_cve_data(current_cve, vulnerabilities_list, score_component_version_names, vulnerability_data)
        combined_vulnerabilities_data.append(current_cve_metrics_dictionary)

        # for score_component in score_component_version_names:
        #     vulnerability_data[vulnerability_detected][score_component[0]] = append_cve_data(
        #         current_cve_metrics_data, # CVSS metrics data for current CVE
        #         score_component[1], # score component CVSSv3 naming convention
        #         score_component[2]  # score component CVSSv2 naming convention
        #     )

    return combined_vulnerabilities_data

def select_cve_data(current_cve, vulnerabilities_list, score_component_version_names, vulnerability_data):
    for vulnerability in vulnerabilities_list:

        if vulnerability.id == current_cve:
            metrics = getattr(vulnerability, 'metrics')

            if hasattr(metrics, 'cvssMetricV31'): # check if CVSSv3.1 exists in metrics
                metrics_version = getattr(metrics, 'cvssMetricV31') # Prefer CVSSv3.1 over v3.0/v2
            elif hasattr(metrics, 'cvssMetricV30'): # check if CVSSv3.0 exists in metrics
                metrics_version = getattr(metrics, 'cvssMetricV30') # Prefer CVSSv3.0 over v2
            elif hasattr(metrics, 'cvssMetricV2'): # check if CVSSv2 exists in metrics
                metrics_version = getattr(metrics, 'cvssMetricV2') # Defer to CVSSv2
            else:
                print('<!> ERROR: no CVSS score data exists for this vulnerability <!>')
                break
            
            current_cve_metrics_data = getattr(metrics_version[0], 'cvssData') # highest CVSS version's CVE data
            current_cve_metrics_dictionary = {} # create empty dictionary for CVE metrics data

            for detected_vulnerability in vulnerability_data:
                if detected_vulnerability['CVE Number'] == current_cve:
                    current_cve_metrics_dictionary.update(detected_vulnerability)
                    break

            for score_component in score_component_version_names:
                if getattr(current_cve_metrics_data, 'version') in ['3.1', '3.0']:
                    current_cve_metrics_dictionary[score_component[0]] = getattr(current_cve_metrics_data, score_component[1], 'NO_DATA')
                elif getattr(current_cve_metrics_data, 'version') == '2.0':
                    current_cve_metrics_dictionary[score_component[0]] = getattr(current_cve_metrics_data, score_component[2], 'NO_DATA')
                else:
                    print('<!> Within function append_cve_data:                          <!>')
                    print('<!> ERROR: no CVSS version data exists for this vulnerability <!>')

            # append components not included within "cvssData" attribute for all CVSS versions
            current_cve_metrics_dictionary['impact_score'] = getattr(metrics_version[0], 'impactScore')
            current_cve_metrics_dictionary['exploitability_score'] = getattr(metrics_version[0], 'exploitabilityScore')



            # append components not included within "cvssData" attribute for CVSSv2.0 only
            if getattr(current_cve_metrics_data, 'version') == '2.0':
                current_cve_metrics_dictionary['user_interaction'] = getattr(metrics_version[0], 'userInteractionRequired')
                current_cve_metrics_dictionary['base_severity'] = getattr(metrics_version[0], 'baseSeverity')
                if (getattr(metrics_version[0], 'obtainAllPrivilege') == True or
                    getattr(metrics_version[0], 'obtainUserPrivilege') == True or
                    getattr(metrics_version[0], 'obtainOtherPrivilege') == True):
                    current_cve_metrics_dictionary['scope_changed'] = "CHANGED"
                else:
                    current_cve_metrics_dictionary['scope_changed'] = "UNCHANGED"

            return current_cve_metrics_dictionary # return the selected version's data dictionary

def print_vulnerability_data(combined_vulnerabilities_data):
    print('                     DETECTED VULNERABILITIES WITH NIST NVD DATA                     ')
    print('*************************************************************************************')

    for vulnerability in combined_vulnerabilities_data:
        print()
        print(f'CVE Number: {vulnerability['CVE Number']}\t\t\tNode Name: {vulnerability['Node Name']}')
        print(f'CVSSv{vulnerability['cvss_version']} Vector String: {vulnerability['vector_string']}')
        print(f'\tIMPACT:\tConfidentiality - {vulnerability['impact_conf']}\t\tSCORES:\tBase - {vulnerability['base_score']}')
        print(f'\t\tIntegrity - {vulnerability['impact_integ']}\t\t\tImpact - {vulnerability['impact_score']}')
        print(f'\t\tAvailability - {vulnerability['impact_avail']}\t\t\tExploitability - {vulnerability['exploitability_score']}')
        print(f'\tUser Interaction: {vulnerability['user_interaction']}\t\t\tPrivilege Required: {vulnerability['privilege_required']}')
        print(f'\tAttack Vector: {vulnerability['attack_vector']}\t\t\tAttack Complexity: {vulnerability['attack_complexity']}')
        print(f'\tScope: {vulnerability['scope_changed']}\t\t\tBase Severity: {vulnerability['base_severity']}')
        print()
        print('*************************************************************************************')

# set file locations if this code is run directly/not called from another script
if __name__ == "__main__":
    nvd_api_key_file_location = '../.aws/nvd_api_key.txt' # sets NIST NVD API key location
    vulnerabilities_detected_file_location = './sue_data/json_data/detected_vulnerabilities.json' # sets vulnerabilities detected file location
    combined_vulnerabilities_data = main(nvd_api_key_file_location, vulnerabilities_detected_file_location) # passes both variables to main() to run script
    # print_vulnerability_data(combined_vulnerabilities_data)
    print(combined_vulnerabilities_data)
else:
    main(sys.argv[0], sys.argv[1])