import json
import re
from groq import Groq
from functools import lru_cache


def generate(system_message, user_message,groq_api_path, temperature=0.7):
    with open(groq_api_path) as key_file:
        groq_api_key = key_file.read() # read API key file to variable

    client = Groq(api_key=groq_api_key)
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

def chunk_data(data, chunk_size=2000):
    """Split data into chunks of approximately equal size."""
    if isinstance(data, dict):
        return [json.dumps(dict(list(data.items())[i:i+chunk_size])) for i in range(0, len(data), chunk_size)]
    elif isinstance(data, list):
        return [json.dumps(data[i:i+chunk_size]) for i in range(0, len(data), chunk_size)]
    else:
        raise ValueError("Data must be either a dictionary or a list")

def analyze_security_measures(best_practices, system_summaries,groq_api_path, max_retries=3):
    
    system_message = """
    You are a cybersecurity expert tasked with analyzing a system's security measures against best practices.
    Compare the provided system summaries to the security best practices and evaluate the system in three areas:
    1. Physical Security
    2. Personnel
    3. Policies

    For each area:
    1. Provide a score between 0 and 1 (where 0 is the worst and 1 is the best) go to 2 decimal points.
    2. Provide a brief explanation for the score.
    3. Recommend the three most important fixes or improvements based on the security best practices.

    Be precise in your scoring and provide clear reasoning for each score and recommendation.

    Format your response as follows:

    Physical Security Score: [score]
    Physical Security Explanation: [explanation, 2 sentences max]
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

        chunk_results = None
        for attempt in range(max_retries):
            ai_response = generate(system_message, user_message, groq_api_path)
            #print(f"AI Response (Attempt {attempt + 1}):", ai_response)  # Debug print
            
            chunk_results = parse_ai_response(ai_response)
            
            # Check if all required fields are present and non-empty
            if all(all(key in chunk_results[category] and chunk_results[category][key] 
                       for key in ['score', 'explanation', 'recommendations']) 
                   for category in results):
                break
        else:
            print(f"Warning: Could not get complete results after {max_retries} attempts.")
            continue  # Skip this chunk if we couldn't get complete results

        if chunk_results:
            # Aggregate results
            for category in results:
                results[category]['score'] += chunk_results[category]['score']
                results[category]['explanation'] += chunk_results[category]['explanation'] + ' '
                results[category]['recommendations'].extend(chunk_results[category]['recommendations'])

    # Average scores and deduplicate recommendations
    num_chunks = len(best_practices_chunks)
    for category in results:
        if num_chunks > 0:
            results[category]['score'] /= num_chunks
        results[category]['explanation'] = results[category]['explanation'].strip()
        results[category]['recommendations'] = list(set(results[category]['recommendations']))[:3]

    #print("Final Results:", results)  # Debug print
    return results

def parse_ai_response(response):
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
        recommendations_match = re.search(fr"{category} Recommendations:(.*?)(?=(?:\n\n[A-Z]|\Z))", response, re.DOTALL | re.IGNORECASE)
        if recommendations_match:
            recommendations = re.findall(r'\d+\.\s*(.+)', recommendations_match.group(1))
            results[category_key]['recommendations'] = recommendations[:3] if recommendations else ["No specific recommendation provided."]
        else:
            results[category_key]['recommendations'] = ["No recommendations found."]

    #print("Parsed Results:", results)  # Debug print
    return results

def load_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

@lru_cache(maxsize=1)
def get_cached_analysis(best_practices_file, system_summaries_file, groq_api_path):
    best_practices = load_json_file(best_practices_file)
    system_summaries = load_json_file(system_summaries_file)
    results = analyze_security_measures(best_practices, system_summaries, groq_api_path)
    return results

def get_security_scores(best_practices_file, system_summaries_file, groq_api_path):
    results = get_cached_analysis(best_practices_file, system_summaries_file, groq_api_path)
    return {
        'physical_security_score': results['physical_security']['score'],
        'personnel_score': results['personnel']['score'],
        'policies_score': results['policies']['score']
    }

def get_explanations(best_practices_file, system_summaries_file,groq_api_path):
    results = get_cached_analysis(best_practices_file, system_summaries_file, groq_api_path)
    return {
        'physical_security_explanation': results['physical_security']['explanation'],
        'personnel_explanation': results['personnel']['explanation'],
        'policies_explanation': results['policies']['explanation']
    }

def get_recommendations(best_practices_file, system_summaries_file,groq_api_path):
    results = get_cached_analysis(best_practices_file, system_summaries_file, groq_api_path)
    return {
        'physical_security_recommendations': results['physical_security']['recommendations'],
        'personnel_recommendations': results['personnel']['recommendations'],
        'policies_recommendations': results['policies']['recommendations']
    }

if __name__ == "__main__":
    best_practices_file = 'frameworks/CSF_Best_Prac_KV.json'
    system_summaries_file = 'sue_data_2.0/json_data/summaries.json'
    
    scores = get_security_scores(best_practices_file, system_summaries_file)
    print("\nScores:", scores)
    
    explanations = get_explanations(best_practices_file, system_summaries_file)
    print("\nExplanations:", explanations)
    
    recommendations = get_recommendations(best_practices_file, system_summaries_file)
    print("\nRecommendations:", recommendations)