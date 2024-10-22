from groq import Groq
import os
from typing import Dict, Tuple, Any
import json



# Get the directory of the current script
base_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the full path to the APT group file
apt_group_file_path = os.path.join(base_dir, 'sue_data_1.0', 'json_data', 'apt_group.json')

# Load APT groups dictionary
try:
    with open(apt_group_file_path, 'r') as f:
        apt_groups = json.load(f)
except FileNotFoundError:
    print("Error: data file not found.")
    apt_groups = {}
except json.JSONDecodeError:
    print("Error: Invalid JSON in APT group data file.")
    apt_groups = {}
# try:
#     with open('sue_data_1.0/json_data/apt_group.json', 'r') as f:
#         apt_groups = json.load(f)
# except FileNotFoundError:
#     print("Error: APT group data file not found.")
#     apt_groups = {}
# except json.JSONDecodeError:
#     print("Error: Invalid JSON in APT group data file.")
#     apt_groups = {}

def get_apt_info(given_apt: str) -> Tuple[str, Any]:
    for apt, info in apt_groups.items():
        if apt.lower() == given_apt.lower():
            return apt, info
    return None, None

def analyze_vulnerability_with_apt(cve: str, description: str, apt_name: str, apt_info: Dict, temperature = .6, client = "") -> str:
    prompt = f"""
    Analyze the following vulnerability and APT group information to determine the likelihood of the APT group exploiting this vulnerability:

    Vulnerability:
    - CVE Number: {cve}
    - Description: {description}

    APT Group: {apt_name}
    APT Info: {apt_info}

    Based on the APT group's tactics, techniques, and procedures (TTPs) as well as their common exploitation methods, assess the likelihood of them exploiting this vulnerability. 
    Provide a brief explanation of your assessment and a numerical score from 0 to 1 be precise to 2 decimal points, where:
    0 means the APT group is very unlikely to exploit this vulnerability
    .5 means the APT group is neither likely or unlikely to exploit this vulnerability
    1 means the APT group is very likely to exploit this vulnerability

    Also be harsh with your grading, make any assumptions needed.

    Format your response as:
    Score: [Your numerical score]
    Explanation: [Brief reasoning behind score. No more than 2 sentences]
    """

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="llama-3.1-70b-versatile",
            max_tokens=2000,
            temperature=temperature
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        print(f"Error during API call: {str(e)}")
        return ""

def parse_analysis(analysis: str) -> Tuple[float, str]:
    lines = analysis.split('\n')
    score = 0.0
    explanation = ""
    for line in lines:
        if line.startswith('Score:'):
            try:
                score = round(float(line.split(':')[1].strip()), 2)
            except ValueError:
                score = 0.0
        elif line.startswith('Explanation:'):
            explanation = line.split(':', 1)[1].strip()
    return score, explanation

def analyze_vulnerabilities(vulnerabilities, given_apt: str, client) -> Dict[str, Dict[str, Any]]:
    apt_name, apt_info = get_apt_info(given_apt)
    results = {}

    if not apt_info:
        print(f"APT group '{given_apt}' not found or not provided. Using default values.")
        for cve, description in vulnerabilities.items():
            results[cve] = {
                "apt_score": 0.5,  # Default score
                "reasoning": "No specific APT group analysis available. Using default medium risk score."
            }
            print(f"\nCVE: {cve}")
            print(f"APT Exploitation Likelihood Score: 0.5 (Default)")
            print(f"Reasoning: No specific APT group analysis available. Using default medium risk score.")
            print("-" * 80)
    else:
        print(f"Analyzing vulnerabilities for APT group: {apt_name}")
        for cve, description in vulnerabilities.items():
            analysis = analyze_vulnerability_with_apt(cve, description, apt_name, apt_info, client=client)
            score, explanation = parse_analysis(analysis)
            results[cve] = {
                "apt_score": score,
                "reasoning": explanation
            }
            print(f"\nCVE: {cve}")
            print(f"APT Exploitation Likelihood Score: {score}")
            print(f"Reasoning: {explanation}")
            print("-" * 80)

    return results

def main(vulnerabilities, given_apt, groq_api_path) -> Dict[str, Dict[str, Any]]:
    """
    Main function to analyze vulnerabilities for a given APT group or use default values if no APT is provided.
    
    :param vulnerabilities: List of dictionaries containing CVE numbers and descriptions
    :param given_apt: String name of the APT group to analyze (optional)
    :return: Dictionary with CVE numbers as keys and dictionaries containing apt_score and reasoning as values
    """
    
    with open(groq_api_path) as key_file:
        groq_api_key = key_file.read() # read API key file to variable
    client = Groq(api_key=groq_api_key)
    vulnerabilities_dict = {item['CVE Number']: item['description'] for item in vulnerabilities}
    return analyze_vulnerabilities(vulnerabilities_dict, given_apt, client)

if __name__ == "__main__":
    vuln = [
        {
            "CVE Number": "CVE-2023-20269",
            "description": "A vulnerability in the remote access VPN feature of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct a brute force attack in an attempt to identify valid username and password combinations or an authenticated, remote attacker to establish a clientless SSL VPN session with an unauthorized user."
        },
        {
            "CVE Number": "CVE-2023-20256",
            "description": "Multiple vulnerabilities in the per-user-override feature of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to bypass a configured access control list (ACL) and allow traffic that should be denied to flow through an affected device."
        }
    ]
    cve_dict = {item['CVE Number']: item['description'] for item in vuln}

    try:
        print("Analysis with a specific APT group:")
        output_with_apt = main(cve_dict, "sandworm team")
        print(output_with_apt)

        print("\nAnalysis without a specific APT group (using default values):")
        #output_without_apt = main(cve_dict)
        #print(output_without_apt)
    except Exception as e:
        print(f"An error occurred: {str(e)}")