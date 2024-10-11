import os
import pandas as pd
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import torch
#help
# Load token from environment
api_token = "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"

device = 0 if torch.cuda.is_available() else -1  # 0 means the first GPU, -1 means CPU

# Ensure token is available
if api_token is None:
    raise ValueError("Hugging Face API token not found. Please set it in the environment variables.")

# Load Llama 3.2 1B model with authentication
model_name = "meta-llama/Llama-3.2-1B"
tokenizer = AutoTokenizer.from_pretrained(model_name, use_auth_token=api_token)
model = AutoModelForCausalLM.from_pretrained(model_name, use_auth_token=api_token)


# Set up pipeline for text generation
llm_pipeline = pipeline("text-generation", model=model, tokenizer=tokenizer, device=device)

# Function to read CSV or TXT files
def read_file(file_path):
    if file_path.endswith(".csv"):
        df = pd.read_csv(file_path)
        return df.to_string(index=False)
    elif file_path.endswith(".txt"):
        with open(file_path, 'r') as file:
            return file.read()
    else:
        raise ValueError("Unsupported file format. Please use CSV or TXT files.")

# Function to generate a response from the content of the file
def generate_response_from_file(file_path, system_prompt, user_prompt):
    # Read content from file
    file_content = read_file(file_path)

    full_prompt = f"{system_prompt}\nUser: {user_prompt}\n{file_content}"
    
    # Generate response using the Llama model
    response = llm_pipeline(full_prompt, max_new_tokens=100, num_return_sequences=1)
    
    # Return the generated response
    return response[0]['generated_text']

# Example usage
file_path = "sue_data/csv_data/software/server_rack_software.csv"  # Replace with your file
system_prompt = "You are a helpful cybersecurity AI assistant that analyzes vulnerabilities on systems. analyze the user input and the attached file and determine any software vulnerabilities.\n"
user_prompt = "please look at all the software that is running on my server and tell me any vulnerabilities and how to remedy them.; \n"


output = generate_response_from_file(file_path, system_prompt, user_prompt)
print("Generated Response:")
print(output)
