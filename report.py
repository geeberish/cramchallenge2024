def main(combined_vulnerabilities_data):
  print_scores = ['CVE Number', 'base_score', 'temporal_score', 'environmental_score', 'apt_threat_index']

  print_table = [['CVE Number', 'Base', 'Temporal', 'Environmental', 'APT Threat Index']]

  for vulnerability in combined_vulnerabilities_data:
    table_append = []
    for score in print_scores:
      table_append.append(vulnerability[score])
    print_table.append(table_append)
  print_table.append(table_append)

  for row in print_table:
    print('|  {:<14}  |  {:^4}  |  {:^8}  |  {:^13}  |  {:^16}  |'.format(*row))