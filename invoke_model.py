import boto3
import json

# Initialize the SageMaker client with the specified region
def create_sagemaker_client(region):
    return boto3.client('sagemaker-runtime', region_name=region)

# Function to invoke the SageMaker model
def invoke_model(input_data, endpoint_name, region):
    sagemaker_client = create_sagemaker_client(region)  # Create the client in the desired region

    # Convert input data to JSON string
    payload = json.dumps(input_data)

    # Invoke the endpoint
    response = sagemaker_client.invoke_endpoint(
        EndpointName=endpoint_name,
        ContentType='application/json',
        Body=payload
    )

    # Parse the response
    response_body = response['Body'].read().decode('utf-8')
    return json.loads(response_body)

# Function to load JSON file content and pass it to the model
def load_and_invoke_model(file_path, endpoint_name, region):
    with open(file_path, 'r') as f:
        input_data = json.load(f)
    
    return invoke_model(input_data, endpoint_name, region)