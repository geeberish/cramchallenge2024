import math
from LLamaPPP import get_security_analysis

test = get_security_analysis('frameworks/CSF_Best_Prac_KV.json','sue_data/json_data/summaries.json')
print(test)
# import cvss base average score from the nist database, as well as variables needed for criticality

# import 3 p's from llama api

# add criticality code here

# modify cvss base average score with criticality and 3 p's

# return