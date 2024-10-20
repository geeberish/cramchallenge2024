import math
from LLamaPPP import get_security_scores
from get_nvd_data import main as get_nvd_data_main
from average_nvd_data import main as average_nvd_data_main
from LLamaPPP import get_security_scores


def call_get_nvd_data(api_key_file_path, dv_file_path):
    combined_vulnerabilities_data = get_nvd_data_main(
        api_key_file_path,
        dv_file_path,
    )
    return combined_vulnerabilities_data

def get_score_averages(combined_vulnerabilities_data):
     score_component_averages = average_nvd_data_main(combined_vulnerabilities_data)
     return score_component_averages

def api(sum_file_path):
        # 3. Send dictionary to modified score    
        #get_base(score_component_averages)

        # 4. Send files to API
        security_best_prac = get_security_scores('frameworks\CSF_Best_Prac_KV.json', sum_file_path)

        return security_best_prac
    
        # 5. GUI Sends to modified score
        #get_p(security_best_prac)

        
        


        # 7. Modified Score sends rest of scores to GUI


# modify cvss base average score with criticality and 3 p's
def main(cfd_file_path, cfm_file_path, dv_file_path, h_file_path, s_file_path, sum_file_path, nvd_file_path, groq_file_path):
    score_component_averages = call_get_nvd_data(dv_file_path)

    base = score_component_averages['base_score']
    impact_sub = score_component_averages['impact_score']
    exploitability_sub = score_component_averages['exploitability_score']

    

    # 6. GUI Sends scores to Modified scored to be calculated
    physical = api['physical_security']
    personnel = api['personnel_score']
    policies = api['policies_score']

    #return base, impact_sub, exploitability_sub, physical, personnel, policies
    return base, impact_sub, exploitability_sub, physical, personnel, policies