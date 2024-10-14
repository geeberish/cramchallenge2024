import subprocess
import sys

# function to install a package
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

install('nvdlib') # install nvdlib

import json
import nvdlib

nvd_api_key = open('../.aws/nvd_api_key.txt').read() # NIST NVD API key file location
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

    for index in range(len(data)):
        combined_list.append({}) # adds a new empty dictionary to end of list
        combined_list[index]['CVE Number'] = data[index].get('CVE Number')
        combined_list[index]['Node Name'] = data[index].get('Node Name')
        combined_list[index]['NVD Score'] = data[index].get('NVD Score')

    # print(combined_list)
    print(vulnerabilities_list[0])
    print(len(vulnerabilities_list))