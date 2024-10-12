import boto3
import json

# Initialize the SageMaker client
sagemaker_client = boto3.client('sagemaker-runtime')

# Function to invoke the SageMaker model
def invoke_model(input_data, endpoint_name):
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

# Function to load multiple JSON file contents and pass to the model
def load_and_invoke_model(input_data, endpoint_name):
    # Invoke the model with the combined data from multiple files
    return invoke_model(input_data, endpoint_name)
