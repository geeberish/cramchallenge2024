import nvdlib

def main(vulnerability_data, vulnerabilities_list, nvd_api_key, cves):
  # pull all CPE's from detected CVE data
  detected_cve_cpes = get_detected_cve_cpes(cves)

  # suspected_cpes = get_suspected_cpes()

  # r = nvdlib.searchCPEmatch(cveId='CVE-2014-7999')
  # for eachCPE in r:
  #     print(eachCPE)

def get_detected_cve_cpes(cves):
  detected_cpes = [] # create empty list for CPE's from detected vulnerabilities
  
  for cve in cves:
    search_result = nvdlib.searchCPEmatch(cveId=cve)
    for eachCPE in search_result:
      print(eachCPE.criteria)


  # detected_cpes = [] # create empty list for CPE's from detected vulnerabilities
  # # cves = set([item["CVE Number"] for item in vulnerabilities_data])
  # for vulnerability in vulnerabilities_list:
  #   current_cpe_list = []
  #   configurations = getattr(vulnerability, 'configurations')
  #   nodes = getattr(configurations[0], 'nodes')
  #   cpeMatch = getattr(nodes[0], 'cpeMatch')
  #   for cpe in cpeMatch:
  #     if getattr(cpe, 'vulnerable') == True:
  #       current_cpe_list.append(getattr(cpe, 'criteria'))
  #   detected_cpes.append({vulnerability.id: current_cpe_list})
  # detected_cpes = detected_cpes
  # return detected_cpes

if __name__ == '__main__':
  main('na', 'na', 'na', 'na')