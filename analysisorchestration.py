
from LLamaPPP import get_security_scores
from get_nvd_data import main as get_nvd_data_main
from LLamaPPP import get_security_scores
from APT import main as apt_main
from set_max_node_criticalites import main as criticality_main
from calculate_modified_scores import main as modify_main
from average_nvd_data import main as average_main
from LLamaPPP import get_explanations
from LLamaPPP import get_recommendations
import os
from local_nvd import main as local_main



def call_get_nvd_data(api_key_file_path, dv_file_path):
    combined_vulnerabilities_data = get_nvd_data_main(
        api_key_file_path,
        dv_file_path,
    )
    return combined_vulnerabilities_data

# def get_score_averages(combined_vulnerabilities_data):
#      score_component_averages = average_nvd_data_main(combined_vulnerabilities_data)
#      return score_component_averages

def ppp_api(sum_file_path, groq_api_path):
    # Get the directory of the current script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Construct the full path to the framework file
    framework_file_path = os.path.join(base_dir, 'frameworks', 'CSF_Best_Prac_KV.json')
    
    # 4. Send files to API
    security_best_prac = get_security_scores(framework_file_path, sum_file_path, groq_api_path)

    return security_best_prac

def call_apt_api(cve_desc, groq_file_path, apt_group_from_GUI):
     #cve_desc is a list of dictionaries with cve number and their description from combined dict
     apt_scores_desc_dict = apt_main(cve_desc, apt_group_from_GUI, groq_file_path)
     
     return apt_scores_desc_dict


def call_criticalities_max(combined_vulnerability_data, crit_func_def_path, crit_func_map_path):
     max_criticalities = criticality_main(combined_vulnerability_data, crit_func_def_path, crit_func_map_path)

     return max_criticalities

def call_calc_modify(combined_vuln,max_criticality, ppp_system_scores, apt_scores_desc):
     
    calculate_modified_scores = modify_main(combined_vuln, max_criticality, ppp_system_scores, apt_scores_desc)
    return calculate_modified_scores
    

        # 7. Modified Score sends rest of scores to GUI
def call_average_nvd(modified_combined_data):
     average_scores = average_main(modified_combined_data)
     
     return average_scores

# modify cvss base average score with criticality and 3 p's
def main(cfd_file_path, cfm_file_path, dv_file_path, sum_file_path, nvd_file_path, groq_file_path, apt_group):
    combined_vuln_data = local_main(dv_file_path)

    apt_scores_desc = call_apt_api(combined_vuln_data, groq_file_path, apt_group)
    #print(apt_scores_desc)

    ppp_scores = ppp_api(sum_file_path, groq_file_path)
    #print(ppp_scores)
    

    criticality = call_criticalities_max(combined_vuln_data, cfd_file_path,cfm_file_path)
    #print(criticality)

    modified_scores = call_calc_modify(combined_vuln_data, criticality, ppp_scores, apt_scores_desc)
    #print(f"*********\n\n{modified_scores}")
    average_scores = call_average_nvd(modified_scores)
    #print(average_scores)
    base = average_scores['base_score']
    average = average_scores['environmental_score']
    apt = average_scores['apt_threat_index']
    physical = ppp_scores['physical_security_score']
    personnel = ppp_scores['personnel_score']
    policies = ppp_scores['policies_score']
    #print(f"base = {base}\naverage = {average}\napt threat index = {apt}\nphysical = {physical}\npersonnel = {personnel}\npolicies = {policies}")

    report = report_generation(base, physical, personnel, policies, average, apt, sum_file_path, modified_scores,groq_file_path)
    return  base, physical, personnel, policies, average, apt, report



def report_generation(base, physical, personnel, policies, average, apt, sum_file_path, modified_scores, groq_api_path):
    # Get the directory of the current script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Construct the full path to the framework file
    framework_file_path = os.path.join(base_dir, 'frameworks', 'CSF_Best_Prac_KV.json')
    
    # Get explanations and recommendations
    ppp_explanations = get_explanations(framework_file_path, sum_file_path, groq_api_path)
    ppp_recommendations = get_recommendations(framework_file_path, sum_file_path, groq_api_path)
    
    # Start the report with static base information (this part will only print once)
    full_report = (f"Base Score: {base}\n"
                   f"Environmental Score: {average}\n"
                   f"APT Threat Index: {apt}\n"
                   f"Physical Security Score: {physical}\n"
                   f"\t*Explanation: {ppp_explanations['physical_security_explanation']}\n"
                   f"\n\t*Recommendations for Remediation: {ppp_recommendations['physical_security_recommendations']}\n\n"
                   f"Personnel Score: {personnel}\n"
                   f"\t*Explanation: {ppp_explanations['personnel_explanation']}\n"
                   f"\n\t*Recommendations for Remediation: {ppp_recommendations['personnel_recommendations']}\n\n"
                   f"Operational Policies Score: {policies}\n"
                   f"\t*Explanation: {ppp_explanations['policies_explanation']}\n"
                   f"\n\t*Recommendations for Remediation: {ppp_recommendations['policies_recommendations']}\n\n")

    # Add a section for just the APT scores and reasoning
    full_report += "\nAPT Scores and Reasoning:\n"
    
    # Iterate over the list of modified scores to extract apt_score and apt_reasoning only
    for idx, scores_to_upload in enumerate(modified_scores):
        # Extract the APT-related information
        cve_number = scores_to_upload.get('CVE Number', 'N/A')
        apt_score = scores_to_upload.get('apt_score', 'N/A')
        apt_reasoning = scores_to_upload.get('apt_reasoning', 'N/A')
        
        # Append APT-specific information to the report
        full_report += (f"CVE Number: {cve_number}\n"
                        f"APT Score: {apt_score}\n"
                        f"APT Reasoning: {apt_reasoning}\n\n")
    
    # Return the full report as a string
    return full_report




     

    #base = score_component_averages['base_score']
    #impact_sub = score_component_averages['impact_score']
    #exploitability_sub = score_component_averages['exploitability_score']

    

    # 6. GUI Sends scores to Modified scored to be calculated
    #physical = ppp_api['physical_security']
    ##policies = ppp_api['policies_score']

    #return base, impact_sub, exploitability_sub, physical, personnel, policies
    #return base, impact_sub, exploitability_sub, physical, personnel, policies


if __name__ == "__main__":
    print("running")
    #report_generation('sue_data/json_data/summaries.json')
    #main('sue_data/json_data/critical_functions_definition.json','sue_data/json_data/critical_functions_mapping.json','sue_data/json_data/detected_vulnerabilities.json','sue_data/json_data/summaries.json','sue_data/json_data/nvd_api.txt','sue_data/json_data/groq_api.txt')