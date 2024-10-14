import requests

# Set up the API endpoint for the model
API_URL = "https://api-inference.huggingface.co/models/QuantFactory/WhiteRabbitNeo-8B"
# Replace 'YOUR_HUGGINGFACE_API_TOKEN' with your actual Hugging Face API token
headers = {
    "Authorization": "Bearer YOUR_HUGGINGFACE_API_TOKEN"
}

# Function to generate text and check context window
def check_context_window(max_tokens=2000, increment=100, base_prompt="Once upon a time, in a land far away"):
    for num_tokens in range(increment, max_tokens + 1, increment):
        # Create a long input prompt by repeating the base prompt
        prompt = base_prompt * (num_tokens // len(base_prompt))  # Adjusting the base prompt to reach num_tokens

        # Make a request to the Hugging Face Inference API
        response = requests.post(API_URL, headers=headers, json={"inputs": prompt})

        # Check the response
        if response.status_code == 200:
            generated_text = response.json()
            print(f"Tokens used: {num_tokens}, Generated text: {generated_text[0]['generated_text'][:100]}...")  # Print first 100 characters
        else:
            print(f"Error with {num_tokens} tokens: {response.status_code} - {response.text}")

# Call the function
check_context_window(max_tokens=16384, increment=512)  # You can adjust the max_tokens and increment
