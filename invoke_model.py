import boto3
import json
from botocore.exceptions import ClientError, BotoCoreError

# Initialize the SageMaker client with the specified region
def create_sagemaker_client(region):
    return boto3.client('sagemaker-runtime', region_name=region)

# Function to invoke the SageMaker model
def invoke_model(input_data, endpoint_name, region):
    sagemaker_client = create_sagemaker_client(region)  # Create the client in the desired region

    # Convert input data to JSON string
    payload = json.dumps(input_data)

    try:
        # Invoke the endpoint
        response = sagemaker_client.invoke_endpoint(
            EndpointName=endpoint_name,
            ContentType='application/json',
            Body=payload
        )

        # Parse the response
        response_body = response['Body'].read().decode('utf-8')
        return json.loads(response_body)

    except ClientError as e:
        # Handle client errors (e.g., endpoint not found, access denied)
        print(f"Client error: {e.response['Error']['Message']}")
        raise e
    except BotoCoreError as e:
        # Handle other boto3 errors
        print(f"Boto3 error: {str(e)}")
        raise e
    except Exception as e:
        # Catch any other exceptions
        print(f"Unexpected error occurred: {str(e)}")
        raise e

# Function to load JSON file content and pass it to the model
def load_and_invoke_model(file_path, endpoint_name, region):
    try:
        with open(file_path, 'r') as f:
            input_data = json.load(f)
        
        # Invoke the model with the loaded JSON data
        return invoke_model(input_data, endpoint_name, region)
    
    except json.JSONDecodeError:
        print(f"Error: Failed to decode JSON from the file {file_path}.")
        raise
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        raise
    except Exception as e:
        print(f"Unexpected error while reading the file: {str(e)}")
        raise
