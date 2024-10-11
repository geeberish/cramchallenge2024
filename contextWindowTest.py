import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

model_name = "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B"
tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained(model_name, torch_dtype=torch.float16, device_map="auto")

long_text = "The quick brown fox jumped over the lazy dog" * 300

input_ids = tokenizer.encode(long_text, return_tensors="pt")

num_tokens = input_ids.shape[1]
print(f"number of tokens in input: {num_tokens}")

max_length = min(16384, num_tokens + 50)
output = model.generate(input_ids.to('cuda'), max_length=max_length, do_sample=True)

generated_text = tokenizer.decode(output[0], skip_special_tokens=True)

print(f"Generated Text: {generated_text}")