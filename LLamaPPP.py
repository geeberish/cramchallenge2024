import json
from groq import Groq

# Groq API configuration
GROQ_API_KEY = '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'  # Replace with your actual API key
client = Groq(api_key=GROQ_API_KEY)

def generate(system_message, user_message, temperature=0.7):
    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message}
    ]
    chat_completion = client.chat.completions.create(
        messages=messages,
        model="llama-3.1-70b-versatile",
        temperature=temperature
    )
    return chat_completion.choices[0].message.content

def chunk_data(data, chunk_size=1000):
    """Split data into chunks of approximately equal size."""
    if isinstance(data, dict):
        return [json.dumps(dict(list(data.items())[i:i+chunk_size])) for i in range(0, len(data), chunk_size)]
    elif isinstance(data, list):
        return [json.dumps(data[i:i+chunk_size]) for i in range(0, len(data), chunk_size)]
    else:
        raise ValueError("Data must be either a dictionary or a list")

def analyze_security_measures(best_practices, system_summaries):
    system_message = """
    You are a cybersecurity expert tasked with analyzing a system's security measures against best practices.
    Compare the provided system summaries to the security best practices and evaluate the system in three areas:
    1. Physical Security
    2. Personnel
    3. Policies

    For each area:
    1. Provide a score between 0 and 1 (where 0 is the worst and 1 is the best).
    2. Provide a brief explanation for the score.
    3. Recommend the three most important fixes or improvements based on the security best practices.

    Be precise in your scoring and provide clear reasoning for each score and recommendation.

    Format your response as follows:

    Physical Security Score: [score]
    Physical Security Explanation: [explanation]
    Physical Security Recommendations:
    1. [recommendation 1]
    2. [recommendation 2]
    3. [recommendation 3]

    Personnel Score: [score]
    Personnel Explanation: [explanation]
    Personnel Recommendations:
    1. [recommendation 1]
    2. [recommendation 2]
    3. [recommendation 3]

    Policies Score: [score]
    Policies Explanation: [explanation]
    Policies Recommendations:
    1. [recommendation 1]
    2. [recommendation 2]
    3. [recommendation 3]
    """

    best_practices_chunks = chunk_data(best_practices)
    system_summaries_chunks = chunk_data(system_summaries)

    results = {
        'physical_security': {'score': 0, 'explanation': '', 'recommendations': []},
        'personnel': {'score': 0, 'explanation': '', 'recommendations': []},
        'policies': {'score': 0, 'explanation': '', 'recommendations': []}
    }

    for bp_chunk, ss_chunk in zip(best_practices_chunks, system_summaries_chunks):
        user_message = f"""
        Security Best Practices Chunk:
        {bp_chunk}

        System Summaries Chunk:
        {ss_chunk}

        Based on the above information, please provide scores, explanations, and recommendations for physical security, personnel, and policies.
        """

        ai_response = generate(system_message, user_message)
        chunk_results = parse_ai_response(ai_response)

        # Aggregate results
        for category in results:
            results[category]['score'] += chunk_results[category]['score']
            results[category]['explanation'] += chunk_results[category]['explanation'] + ' '
            results[category]['recommendations'].extend(chunk_results[category]['recommendations'])

    # Average scores and deduplicate recommendations
    num_chunks = len(best_practices_chunks)
    for category in results:
        results[category]['score'] /= num_chunks
        results[category]['explanation'] = results[category]['explanation'].strip()
        results[category]['recommendations'] = list(set(results[category]['recommendations']))[:3]
    #print(results)
    return results

def parse_ai_response(response):
    import re

    categories = ['Physical Security', 'Personnel', 'Policies']
    results = {}

    for category in categories:
        category_key = category.lower().replace(' ', '_')
        results[category_key] = {}

        # Extract score
        score_match = re.search(fr"{category} Score: (0\.\d+|1\.0)", response, re.IGNORECASE)
        results[category_key]['score'] = float(score_match.group(1)) if score_match else 0.0

        # Extract explanation
        explanation_match = re.search(fr"{category} Explanation: (.+?)(?=\n\n|\Z)", response, re.DOTALL | re.IGNORECASE)
        results[category_key]['explanation'] = explanation_match.group(1).strip() if explanation_match else "No explanation provided."

        # Extract recommendations
        recommendations_match = re.search(fr"{category} Recommendations:(.*?)(?=\n\n|\Z)", response, re.DOTALL | re.IGNORECASE)
        if recommendations_match:
            recommendations = re.findall(r'\d+\.\s*(.+)', recommendations_match.group(1))
            results[category_key]['recommendations'] = recommendations[:3]  # Ensure we only get top 3
        else:
            results[category_key]['recommendations'] = ["No recommendation provided."] * 3

    return results

def load_json_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# This function can be called from other scripts
def get_security_analysis(best_practices_file, system_summaries_file):
    best_practices = load_json_file(best_practices_file)
    system_summaries = load_json_file(system_summaries_file)
    
    results = analyze_security_measures(best_practices, system_summaries)
    
    # Return only the scores
    return {
        'physical_security_score': results['physical_security']['score'],
        'personnel_score': results['personnel']['score'],
        'policies_score': results['policies']['score']
    }

if __name__ == "__main__":
    best_practices_file = 'frameworks/CSF_Best_Practices.json'
    system_summaries_file = 'sue_data/json_data/summaries.json'
    
    results = get_security_analysis(best_practices_file, system_summaries_file)
    
    for category, data in results.items():
        print(f"\n{category.replace('_', ' ').title()}:")
        print(f"Score: {data['score']:.2f}")
        print(f"Explanation: {data['explanation']}")
        print("Recommendations:")
        for i, rec in enumerate(data['recommendations'], 1):
            print(f"{i}. {rec}")















"""import json
from groq import Groq

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

def analyze_security_measures(best_practices, system_summaries):
    system_message = ""
    You are a cybersecurity expert tasked with analyzing a system's security measures against best practices.
    Compare the provided system summaries to the security best practices and evaluate the system in three areas:
    1. Physical Security
    2. Personnel
    3. Policies

    For each area:
    1. Provide a score between 0 and 1 (where 0 is the worst and 1 is the best).
    2. Provide a brief explanation for the score.
    3. Recommend the three most important fixes or improvements based on the security best practices.

    Be precise in your scoring and provide clear reasoning for each score and recommendation.

    Format your response as follows:

    Physical Security Score: [score]
    Physical Security Explanation: [explanation]
    Physical Security Recommendations:
    1. [recommendation 1]
    2. [recommendation 2]
    3. [recommendation 3]

    Personnel Score: [score]
    Personnel Explanation: [explanation]
    Personnel Recommendations:
    1. [recommendation 1]
    2. [recommendation 2]
    3. [recommendation 3]

    Policies Score: [score]
    Policies Explanation: [explanation]
    Policies Recommendations:
    1. [recommendation 1]
    2. [recommendation 2]
    3. [recommendation 3]
    ""

    user_message = f
    Security Best Practices:
    {json.dumps(best_practices, indent=2)}

    System Summaries:
    {json.dumps(system_summaries, indent=2)}

    Based on the above information, please provide scores, explanations, and recommendations for physical security, personnel, and policies.
    "

    ai_response = generate(system_message, user_message)
    return parse_ai_response(ai_response)

def parse_ai_response(response):
    import re

    categories = ['Physical Security', 'Personnel', 'Policies']
    results = {}

    for category in categories:
        category_key = category.lower().replace(' ', '_')
        results[category_key] = {}

        # Extract score
        score_match = re.search(fr"{category} Score: (0\.\d+|1\.0)", response, re.IGNORECASE)
        results[category_key]['score'] = float(score_match.group(1)) if score_match else 0.0

        # Extract explanation
        explanation_match = re.search(fr"{category} Explanation: (.+?)(?=\n\n|\Z)", response, re.DOTALL | re.IGNORECASE)
        results[category_key]['explanation'] = explanation_match.group(1).strip() if explanation_match else "No explanation provided."

        # Extract recommendations
        recommendations_match = re.search(fr"{category} Recommendations:(.*?)(?=\n\n|\Z)", response, re.DOTALL | re.IGNORECASE)
        if recommendations_match:
            recommendations = re.findall(r'\d+\.\s*(.+)', recommendations_match.group(1))
            results[category_key]['recommendations'] = recommendations[:3]  # Ensure we only get top 3
        else:
            results[category_key]['recommendations'] = ["No recommendation provided."] * 3

    return results

def load_json_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# This function can be called from other scripts
def get_security_analysis(best_practices_file, system_summaries_file):
    best_practices = load_json_file(best_practices_file)
    system_summaries = load_json_file(system_summaries_file)
    
    return analyze_security_measures(best_practices, system_summaries)

if __name__ == "__main__":
    best_practices_file = 'frameworks/CSF_Best_Practices.json'
    system_summaries_file = 'sue_data/json_data/summaries.json'
    
    results = get_security_analysis(best_practices_file, system_summaries_file)
    
    for category, data in results.items():
        print(f"\n{category.replace('_', ' ').title()}:")
        print(f"Score: {data['score']:.2f}")
        print(f"Explanation: {data['explanation']}")
        print("Recommendations:")
        for i, rec in enumerate(data['recommendations'], 1):
            print(f"{i}. {rec}")"""