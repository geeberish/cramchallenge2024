import os, json

directory = '../../../Desktop/NIST NVD DATA'

# # List of CVEs
cves = [
    "CVE-2007-2152", "CVE-2009-5118", "CVE-2010-0727", "CVE-2010-1256", "CVE-2010-1439", 
    "CVE-2010-3972", "CVE-2011-0714", "CVE-2011-1576", "CVE-2011-2942", "CVE-2011-3347", 
    "CVE-2012-0158", "CVE-2012-0217", "CVE-2012-1145", "CVE-2012-1568", "CVE-2012-1856", 
    "CVE-2012-2697", "CVE-2012-3440", "CVE-2013-1935", "CVE-2013-2188", "CVE-2013-2224", 
    "CVE-2013-5056", "CVE-2013-5058", "CVE-2014-0301", "CVE-2014-0315", "CVE-2014-0323", 
    "CVE-2014-5177", "CVE-2014-7993", "CVE-2014-7994", "CVE-2014-7995", "CVE-2014-7999", 
    "CVE-2015-1762", "CVE-2015-1763", "CVE-2015-3216", "CVE-2015-7553", "CVE-2015-7833", 
    "CVE-2016-1425", "CVE-2016-3699", "CVE-2016-6473", "CVE-2016-9604", "CVE-2017-1000353", 
    "CVE-2017-1000354", "CVE-2017-1000356", "CVE-2017-12166", "CVE-2017-12193", "CVE-2017-12607", 
    "CVE-2017-15121", "CVE-2017-3803", "CVE-2017-6606", "CVE-2017-8543", "CVE-2018-0284", 
    "CVE-2018-21124", "CVE-2018-21125", "CVE-2018-21126", "CVE-2018-21127", "CVE-2018-21128", 
    "CVE-2018-21129", "CVE-2018-21130", "CVE-2018-21131", "CVE-2018-21132", "CVE-2018-21133", 
    "CVE-2019-10171", "CVE-2019-10214", "CVE-2019-17098", "CVE-2019-17518", "CVE-2019-19768", 
    "CVE-2020-13958", "CVE-2020-14312", "CVE-2020-15078", "CVE-2020-1702", "CVE-2020-20813", 
    "CVE-2020-5765", "CVE-2020-7337", "CVE-2021-20135", "CVE-2021-33035", "CVE-2022-0547", 
    "CVE-2022-1665", "CVE-2022-37401", "CVE-2023-0101", "CVE-2023-20015", "CVE-2023-20095", 
    "CVE-2023-20200", "CVE-2023-20247", "CVE-2023-20256", "CVE-2023-20269", "CVE-2023-20934", 
    "CVE-2023-24998", "CVE-2023-37401", "CVE-2023-4042", "CVE-2023-40592", "CVE-2023-40593", 
    "CVE-2023-47804", "CVE-2024-1495", "CVE-2024-23675", "CVE-2024-23676", "CVE-2024-2576", 
    "CVE-2024-2743"
]



  

for cve_id in cves:
  print(f'cve_id = {cve_id}')
  input()
  print(f'os.listdir(directory) = {os.listdir(directory)}')
  input()
  for filename in os.listdir(directory):
    print(f'filename = {filename}')
    input()
    if filename.endswith('.json'):  # Only process JSON files
      filepath = os.path.join(directory, filename)
      print(f'filepath = {filepath}')
      input()
      with open(filepath, 'r') as file:
        cve_data = json.load(file)
        print(cve_data["CVE_Items"])
        input()
        for cve in cve_data["CVE_Items"]:
          print(cve['cve'])
          input()



        # if cve_id == []:
        #   print(f"Processed file: {filename}")
        #   input()

        #   for item in cve_data.get('CVE_Items', []):
        #     # Extract CVE metadata
        #     cve_id = item['cve']['CVE_data_meta']['ID']
        #     description = item['cve']['description']['description_data'][0]['value']
        #     published_date = item.get('publishedDate', 'N/A')
        #     base_score = item['impact']['baseMetricV2']['cvssV2']['baseScore']
        #     severity = item['impact']['baseMetricV2']['severity']

        #     print(cve_id, description)