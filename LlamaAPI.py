import json
import math
import sys
import os
from groq import Groq

sys.path.append(".")
from cvss_calculation import *
import cvss_calculation as cvss

def handle_files(files_to_submit):
    for file_type, file_path in files_to_submit.items():
        print(f"Handling {file_type}: {file_path}")
        # You can add custom logic to process each file here
        # For example, open and read the files, or pass them to another function
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                print(f"Contents of {file_type}: {content[:100]}...")  # Print first 100 characters
        except Exception as e:
            print(f"Error handling {file_type}: {e}")

# Groq API configuration
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

def load_json_from_files(json_file_list):
    combined_json_data = {}
    for file_path in json_file_list:
        try:
            with open(file_path, 'r') as file:
                file_data = json.load(file)
                file_name = os.path.basename(file_path)
                combined_json_data[file_name] = file_data
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
    return combined_json_data

def prepare_context(combined_json_data, vulnerability):
    context = f"Analyzing vulnerability: {json.dumps(vulnerability, indent=2)}\n\n"
    context += "Related information from other files:\n"
    
    if 'critical_functions_definition.json' in combined_json_data:
        context += "Critical Functions:\n"
        for func in combined_json_data['critical_functions_definition.json']:
            context += f"- {func.get('function_name', 'Unknown')}: {func.get('description', 'No description')}\n"
    
    if 'critical_functions_mapping.json' in combined_json_data:
        context += "\nCritical Functions Mapping:\n"
        for mapping in combined_json_data['critical_functions_mapping.json']:
            context += f"- {mapping.get('function_name', 'Unknown')} -> Criticality: {mapping.get('criticality', 'Unknown')}\n"
    
    if 'hardware.json' in combined_json_data:
        context += "\nHardware Information:\n"
        for hw in combined_json_data['hardware.json']:
            if hw.get('node_name') == vulnerability.get('Node Name'):
                context += f"- {hw.get('node_name', 'Unknown')}: {hw.get('description', 'No description')}\n"
    
    if 'summaries.json' in combined_json_data:
        context += "\nSummaries:\n"
        for summary in combined_json_data['summaries.json']:
            context += f"- {summary.get('title', 'Unknown')}: {summary.get('description', 'No description')}\n"
    
    return context

def ai_predict_factors(combined_json_data, vulnerability):
    context = prepare_context(combined_json_data, vulnerability)
    
    system_message = """
    You are a cybersecurity expert tasked with analyzing vulnerability information and determining criticality scores.
    Based on the provided information, determine the following scores on a scale of 0 to 1: 
    1. Physical Security: How much does physical security impact this vulnerability?
    2. Personnel Training: How much can personnel training mitigate this vulnerability?
    3. Policies: How much can organizational policies help in addressing this vulnerability?

    Based on the provided information regarding criticality mapping, determine the following score on a scale of 1 to 3:
    1. Criticality: How critical is this vulnerability to the system's operation?
    
    Provide your response in the following format:
    Criticality: [score]
    Physical Security: [score]
    Personnel Training: [score]
    Policies: [score]
    
    Explanation: [brief explanation of your reasoning]
    """
    
    user_message = f"""
    {context}
    
    Based on the above information, please provide the scores for the vulnerability as requested.
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

def main():
    json_file_list = [
        'sue_data/json_data/critical_functions_definition.json',
        'sue_data/json_data/critical_functions_mapping.json',
        'sue_data/json_data/detected_vulnerabilities.json',
        'sue_data/json_data/hardware.json',
        'sue_data/json_data/summaries.json'
    ]

    combined_json_data = load_json_from_files(json_file_list)
    vulnerabilities = combined_json_data.get('detected_vulnerabilities.json', [])

    if not vulnerabilities:
        print("No vulnerabilities found.")
        return

    total_score = 0
    processed_vulnerabilities = 0

    for i, vulnerability in enumerate(vulnerabilities):
        print(f"\n--- Processing Vulnerability {i+1} ---")

        try:
            cve_number = vulnerability.get("CVE Number", "Unknown")
            nvd_score = vulnerability.get("NVD Score", 0.0)
            node_category = vulnerability.get("Node Category", "Unknown")
            node_name = vulnerability.get("Node Name", "Unknown")
            software_make = vulnerability.get("Software Make", "Unknown")
            software_description = vulnerability.get("Software Description", "Unknown")
            software_version = vulnerability.get("Software Version", "Unknown")

            print(f"Processing: CVE {cve_number}, Node: {node_name}")

            ai_factors = ai_predict_factors(combined_json_data, vulnerability)
            
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
            processed_vulnerabilities += 1

        except Exception as e:
            print(f"Error processing vulnerability: {str(e)}")
            print(f"Vulnerability data: {json.dumps(vulnerability, indent=2)}")

    if processed_vulnerabilities > 0:
        average_cvss = total_score / processed_vulnerabilities
        print(f"\nAverage Environmental CVSS Score: {average_cvss:.2f}")
        print(f"Processed {processed_vulnerabilities} out of {len(vulnerabilities)} vulnerabilities.")
    else:
        print("No vulnerabilities were successfully processed.")

if __name__ == "__main__":
    main()