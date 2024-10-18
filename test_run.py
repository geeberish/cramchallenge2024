from get_nvd_data import main as get_nvd_data_main
from average_nvd_data import main as average_nvd_data_main

combined_vulnerabilities_data = get_nvd_data_main(
  '../.aws/nvd_api_key.txt',
  './sue_data/json_data/detected_vulnerabilities.json'
)

score_component_averages = average_nvd_data_main(combined_vulnerabilities_data)