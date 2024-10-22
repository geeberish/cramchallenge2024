from groq import Groq
import os
from typing import Dict, Tuple, Any
import json



# Get the directory of the current script
base_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the full path to the APT group file
apt_group_file_path = os.path.join(base_dir, 'sue_data', 'json_data', 'apt_group.json')

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
#     with open('sue_data/json_data/apt_group.json', 'r') as f:
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

    # Simplified check: APT info is missing or APT group is explicitly 'None'
    if not apt_info or given_apt == 'None':
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




















"""from groq import Groq
import json

# Initialize Groq client
GROQ_API_KEY = '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'  # Replace with your actual API key
client = Groq(api_key=GROQ_API_KEY)

# Load APT groups dictionary
import json
with open('sue_data/json_data/apt_group.json', 'r') as f:
    apt_groups = json.load(f)

def get_apt_info(given_apt):
    for apt, info in apt_groups.items():
        if apt.lower() == given_apt.lower():
            return apt, info
    return None, None

def analyze_vulnerability_with_apt(cve, description, apt_name, apt_info):
    prompt = f""
    Analyze the following vulnerability and APT group information to determine the likelihood of the APT group exploiting this vulnerability:

    Vulnerability:
    - CVE Number: {cve}
    - Description: {description}

    APT Group: {apt_name}
    APT Info: {apt_info}

    Based on the APT group's tactics, techniques, and procedures (TTPs), assess the likelihood of them exploiting this vulnerability. 
    Provide a brief explanation of your assessment and a numerical score from 0 to 1 be precise to 2 decimal points, where:
    0 means the APT group is very unlikely to exploit this vulnerability
    1 means the APT group is very likely to exploit this vulnerability

    Format your response as:
    Score: [Your numerical score]
    Explanation: [Your brief explanation]
    ""

    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="llama-3.1-70b-versatile",
        max_tokens=2000,
    )

    return chat_completion.choices[0].message.content

def parse_analysis(analysis):
    lines = analysis.split('\n')
    score = 0
    explanation = ""
    for line in lines:
        if line.startswith('Score:'):
            try:
                score = float(line.split(':')[1].strip())
            except ValueError:
                score = 0
        elif line.startswith('Explanation:'):
            explanation = line.split(':', 1)[1].strip()
    return score, explanation

def analyze_vulnerabilities(vulnerabilities, given_apt):
    apt_name, apt_info = get_apt_info(given_apt)
    if not apt_info:
        print(f"APT group '{given_apt}' not found.")
        return {}

    print(f"Analyzing vulnerabilities for APT group: {apt_name}")
    
    results = {}
    for cve, description in vulnerabilities.items():
        analysis = analyze_vulnerability_with_apt(cve, description, apt_name, apt_info)
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

def main(vulnerabilities, given_apt):
    ""
    Main function to analyze vulnerabilities for a given APT group.
    
    :param vulnerabilities: Dictionary with CVE numbers as keys and descriptions as values
    :param given_apt: String name of the APT group to analyze
    :return: Dictionary with CVE numbers as keys and dictionaries containing apt_score and reasoning as values
    ""
    return analyze_vulnerabilities(vulnerabilities, given_apt)

if __name__ == "__main__":
    # This block will only run if the script is executed directly
    # You can add test code here if needed

    vuln = [{"Node Category": "boundary defense and system administrator rack", "Node Name": "Firewall", "Software Make": "Cisco", "Software Description": "FirePower 4125 Next Generation Firewall with Firepower Threat Defense (FTD) Software", "Software Version": "6.6.7", "CVE Number": "CVE-2023-20269", "NVD Score": 9.1, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "impact_integ": "HIGH", "cvss_version": "3.1", "user_interaction": "NONE", "base_score": 9.1, "impact_conf": "HIGH", "impact_score": 5.2, "privilege_required": "NONE", "attack_vector": "NETWORK", "impact_avail": "NONE", "scope_changed": "UNCHANGED", "exploitability_score": 3.9, "base_severity": "CRITICAL", "attack_complexity": "LOW", "description": "A vulnerability in the remote access VPN feature of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct a brute force attack in an attempt to identify valid username and password combinations or an authenticated, remote attacker to establish a clientless SSL VPN session with an unauthorized user. This vulnerability is due to improper separation of authentication, authorization, and accounting (AAA) between the remote access VPN feature and the HTTPS management and site-to-site VPN features. An attacker could exploit this vulnerability by specifying a default connection profile/tunnel group while conducting a brute force attack or while establishing a clientless SSL VPN session using valid credentials. A successful exploit could allow the attacker to achieve one or both of the following:  Identify valid credentials that could then be used to establish an unauthorized remote access VPN session. Establish a clientless SSL VPN session (only when running Cisco ASA Software Release 9.16 or earlier).  Notes:  Establishing a client-based remote access VPN tunnel is not possible as these default connection profiles/tunnel groups do not and cannot have an IP address pool configured. This vulnerability does not allow an attacker to bypass authentication. To successfully establish a remote access VPN session, valid credentials are required, including a valid second factor if multi-factor authentication (MFA) is configured.  Cisco will release software updates that address this vulnerability. There are workarounds that address this vulnerability."}, {"Node Category": "boundary defense and system administrator rack", "Node Name": "Firewall", "Software Make": "Cisco", "Software Description": "FirePower 4125 Next Generation Firewall with Firepower Threat Defense (FTD) Software", "Software Version": "6.6.7", "CVE Number": "CVE-2023-20256", "NVD Score": 5.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", "impact_integ": "LOW", "cvss_version": "3.1", "user_interaction": "NONE", "base_score": 5.8, "impact_conf": "NONE", "impact_score": 1.4, "privilege_required": "NONE", "attack_vector": "NETWORK", "impact_avail": "NONE", "scope_changed": "CHANGED", "exploitability_score": 3.9, "base_severity": "MEDIUM", "attack_complexity": "LOW", "description": "Multiple vulnerabilities in the per-user-override feature of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to bypass a configured access control list (ACL) and allow traffic that should be denied to flow through an affected device. These vulnerabilities are due to a logic error that could occur when the affected software constructs and applies per-user-override rules. An attacker could exploit these vulnerabilities by connecting to a network through an affected device that has a vulnerable configuration. A successful exploit could allow the attacker to bypass the interface ACL and access resources that would should be protected."}]
    cve_dict = {item['CVE Number']: item['description'] for item in vuln}

    output = main(cve_dict, "sandworm team")
    print(output)"""