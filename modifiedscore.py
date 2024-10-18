import math
from LLamaPPP import get_security_scores


test = get_security_scores('frameworks/CSF_Best_Prac_KV.json','sue_data/json_data/summaries.json')
print(test)
# import cvss base average score from the nist database, as well as variables needed for criticality
def get_base(score_component_averages):
    base = score_component_averages['base_score']

# import 3 p's from llama api
def get_p(security_best_prac):
    physical = security_best_prac['physical_security_score']
    personnel = security_best_prac['personnel_score']
    policies = security_best_prac['policies_score']

# add criticality code here

# modify cvss base average score with criticality and 3 p's

# return