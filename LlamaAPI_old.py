import json
import sys
sys.path.append(".")
from cvss_calculation import *
import cvss_calculation as cvss
from groq import Groq

# AI model configuration
GROQ_API_KEY = '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'  # Replace with your actual API key
client = Groq(api_key=GROQ_API_KEY)

def generate(system_message, user_message):
    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message}
    ]
    chat_completion = client.chat.completions.create(
        messages=messages,
        model="llama-3.1-70b-versatile",
    )
    return chat_completion.choices[0].message.content

def ai_predict_factors(cve_number, node_category, node_name, software_make, software_description, software_version, nvd_score):
    system_message = """
    You are a cybersecurity expert tasked with analyzing vulnerability information and determining criticality scores.
    Based on the provided information, determine the following scores on a scale of 0 to 1:
    1. Criticality: How critical is this vulnerability to the system's operation?
    2. Physical Security: How much does physical security impact this vulnerability?
    3. Personnel Training: How much can personnel training mitigate this vulnerability?
    4. Policies: How much can organizational policies help in addressing this vulnerability?
    
    Provide your response in the following format:
    Criticality: [score]
    Physical Security: [score]
    Personnel Training: [score]
    Policies: [score]
    
    Explanation: [brief explanation of your reasoning]
    """
    
    user_message = f"""
    Analyze the following vulnerability:
    CVE Number: {cve_number}
    Node Category: {node_category}
    Node Name: {node_name}
    Software Make: {software_make}
    Software Description: {software_description}
    Software Version: {software_version}
    NVD Score: {nvd_score}
    """
    
    ai_response = generate(system_message, user_message)
    print(ai_response)
    return parse_ai_response(ai_response)

def parse_ai_response(response):
    import re
    
    factors = {}
    patterns = {
        "criticality": r"Criticality:\s*(\d+(?:\.\d+)?)",
        "physical_security": r"Physical Security:\s*(\d+(?:\.\d+)?)",
        "personnel_training": r"Personnel Training:\s*(\d+(?:\.\d+)?)",
        "policies": r"Policies:\s*(\d+(?:\.\d+)?)"
    }
    
    for factor, pattern in patterns.items():
        match = re.search(pattern, response, re.IGNORECASE)
        if match:
            factors[factor] = float(match.group(1))
        else:
            factors[factor] = 0.5  # Default value if not found
    
    return factors

def calculate_cvss(impact_conf, impact_integ, impact_avail, scope_changed, criticality, physical_security, personnel_training, policies):
    impact_sub = cvss.impact_subscore(impact_conf, impact_integ, impact_avail, scope_changed)
    exploitability_sub = cvss.exploitability_subscore(0.5, 0.2, 0.2, 0.85)
    base = cvss.base_score(impact_sub, exploitability_sub, scope_changed)
    temporal = cvss.temporal_score(base, 0.94, 0.95, 0.96)
    modified_impact_sub = cvss.modified_impact_subscore(0.5, 1.0, 0.2, 1.0, 0.35, 1.0, scope_changed)
    modified_exploitability_sub = cvss.modified_exploitability_subscore(0.85, 0.9, 0.62, 0.85)
    environmental = cvss.environmental_score(modified_impact_sub, modified_exploitability_sub, scope_changed, 0.94, 0.95, 0.96, criticality, physical_security, personnel_training, policies)

    return base, impact_sub, exploitability_sub, temporal, environmental

def load_json_from_files(json_file_list):
    combined_json_data = {}
    for file_path in json_file_list:
        try:
            with open(file_path, 'r') as file:
                file_data = json.load(file)
                if isinstance(file_data, dict):
                    combined_json_data.update(file_data)
                elif isinstance(file_data, list):
                    combined_json_data[file_path] = file_data
                else:
                    print(f"Unsupported JSON structure in {file_path}")
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
    return combined_json_data

def main():
    json_file_list = [
        'sue_data/json_data/critical_functions_definition.json',
        'sue_data/json_data/critical_functions_mapping.json',
        'sue_data/json_data/detected_vulnerabilities.json',
        'sue_data/json_data/hardware.json',
        'sue_data/json_data/summaries.json'
    ]

    combined_json_data = load_json_from_files(json_file_list)
    vulnerabilities = combined_json_data.get('sue_data/json_data/detected_vulnerabilities.json', [])

    if not vulnerabilities:
        print("No vulnerabilities found.")
        return

    total_score = 0

    for i, vulnerability in enumerate(vulnerabilities):
        print(f"\n--- Processing Vulnerability {i+1} ---")

        cve_number = vulnerability.get("CVE Number", "Unknown")
        nvd_score = vulnerability.get("NVD Score", 0.0)
        node_category = vulnerability.get("Node Category", "Unknown")
        node_name = vulnerability.get("Node Name", "Unknown")
        software_make = vulnerability.get("Software Make", "Unknown")
        software_description = vulnerability.get("Software Description", "Unknown")
        software_version = vulnerability.get("Software Version", "Unknown")

        try:
            ai_factors = ai_predict_factors(
                cve_number, node_category, node_name, software_make,
                software_description, software_version, nvd_score
            )
            
            criticality = ai_factors.get("criticality", 0.5)
            physical_security = ai_factors.get("physical_security", 0.5)
            personnel_training = ai_factors.get("personnel_training", 0.5)
            policies = ai_factors.get("policies", 0.5)

            impact_conf = 0.7  # Example static value
            impact_integ = 0.5
            impact_avail = 0.2
            scope_changed = True

            base, impact_sub, exploitability_sub, temporal, environmental = calculate_cvss(
                impact_conf, impact_integ, impact_avail, scope_changed, 
                criticality, physical_security, personnel_training, policies
            )

            print(f"CVSS Scores for {cve_number}:")
            print(f"Base: {base:.2f}")
            print(f"Impact Subscore: {impact_sub:.2f}")
            print(f"Exploitability Subscore: {exploitability_sub:.2f}")
            print(f"Temporal: {temporal:.2f}")
            print(f"Environmental: {environmental:.2f}")

            total_score += environmental

        except Exception as e:
            print(f"Error processing vulnerability {cve_number}: {e}")

    if vulnerabilities:
        average_cvss = total_score / len(vulnerabilities)
        print(f"\nAverage Environmental CVSS Score: {average_cvss:.2f}")

if __name__ == "__main__":
    main()