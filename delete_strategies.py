import boto3
from botocore.exceptions import ClientError
from rich.console import Console

console = Console()

def delete_lambda_function(resource_id):
    client = boto3.client('lambda')
    try:
        client.delete_function(FunctionName=resource_id)
        console.print(f"[green]Successfully deleted Lambda function {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting Lambda function {resource_id}: {e}"

def delete_iam_role(resource_id):
    client = boto3.client('iam')
    try:
        client.delete_role(RoleName=resource_id)
        console.print(f"[green]Successfully deleted IAM role {resource_id}[/green]")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return f"IAM role {resource_id} does not exist"
        return f"Error deleting IAM role {resource_id}: {e}"

def delete_iam_policy(resource_id):
    client = boto3.client('iam')
    try:
        client.delete_policy(PolicyArn=resource_id)
        console.print(f"[green]Successfully deleted IAM policy {resource_id}[/green]")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return f"IAM policy {resource_id} does not exist"
        return f"Error deleting IAM policy {resource_id}: {e}"

def delete_cloudwatch_log_resource_policy(resource_id):
    client = boto3.client('logs')
    try:
        client.delete_resource_policy(policyName=resource_id)
        console.print(f"[green]Successfully deleted Cloudwatch Log Resource Policy {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting Cloudwatch Log Resource Policy {resource_id}: {e}"

def delete_log_group(resource_id):
    client = boto3.client('logs')
    try:
        client.delete_log_group(logGroupName=resource_id)
        console.print(f"[green]Successfully deleted Log Group {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting Log Group {resource_id}: {e}"

def delete_events_rule(resource_id):
    client = boto3.client('events')
    try:
        client.delete_rule(Name=resource_id)
        console.print(f"[green]Successfully deleted Events Rule {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting Events Rule {resource_id}: {e}"

def delete_ssm_parameter(resource_id):
    client = boto3.client('ssm')
    try:
        client.delete_parameter(Name=resource_id)
        console.print(f"[green]Successfully deleted SSM Parameter {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting SSM Parameter {resource_id}: {e}"

def delete_sqs_queue(resource_id):
    client = boto3.client('sqs')
    try:
        client.delete_queue(QueueUrl=resource_id)
        console.print(f"[green]Successfully deleted SQS Queue {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting SQS Queue {resource_id}: {e}"

def delete_events_event_bus(resource_id):
    client = boto3.client('events')
    try:
        client.delete_event_bus(Name=resource_id)
        console.print(f"[green]Successfully deleted Event Bus {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting Event Bus {resource_id}: {e}"

def delete_log_retention(resource_id):
    client = boto3.client('logs')
    try:
        client.delete_log_group(logGroupName=resource_id)
        console.print(f"[green]Successfully deleted Log Group for Log Retention {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting Log Group for Log Retention {resource_id}: {e}"

def delete_dynamodb_table(resource_id):
    client = boto3.client('dynamodb')
    try:
        client.delete_table(TableName=resource_id)
        console.print(f"[green]Successfully deleted DynamoDB Table {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting DynamoDB Table {resource_id}: {e}"

def delete_ec2_security_group(resource_id):
    client = boto3.client('ec2')
    try:
        client.delete_security_group(GroupId=resource_id)
        console.print(f"[green]Successfully deleted EC2 Security Group {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting EC2 Security Group {resource_id}: {e}"

def delete_cloudfront_function(resource_id):
    client = boto3.client('cloudfront')
    try:
        # Get the function's current configuration and ETag
        response = client.describe_function(Name=resource_id)
        etag = response['ETag']

        # Delete the function
        client.delete_function(Name=resource_id, IfMatch=etag)
        console.print(f"[green]Successfully deleted CloudFront function {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting CloudFront function {resource_id}: {e}"

def delete_cloudfront_distribution(resource_id):
    client = boto3.client('cloudfront')
    try:
        # Get the distribution's current configuration and ETag
        response = client.get_distribution_config(Id=resource_id)
        etag = response['ETag']
        config = response['DistributionConfig']

        # Update the distribution configuration to disable it
        config['Enabled'] = False
        client.update_distribution(
            Id=resource_id,
            IfMatch=etag,
            DistributionConfig=config
        )

        # Wait until the distribution is disabled
        waiter = client.get_waiter('distribution_deployed')
        waiter.wait(Id=resource_id)

        # Get the new ETag after the distribution is disabled
        response = client.get_distribution_config(Id=resource_id)
        etag = response['ETag']

        # Delete the distribution
        client.delete_distribution(Id=resource_id, IfMatch=etag)
        console.print(f"[green]Successfully deleted CloudFront distribution {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting CloudFront distribution {resource_id}: {e}"

def delete_lambda_layer_version(resource_id):
    client = boto3.client('lambda')
    try:
        console.print(f'attempting to delete {resource_id}')
        # Assuming resource_id contains both LayerName and VersionNumber, e.g., "layer-name:1"
        layer_name, version_number = resource_id.split(':')
        client.delete_layer_version(
            LayerName=layer_name,
            VersionNumber=int(version_number)
        )
        console.print(f"[green]Successfully deleted Lambda Layer Version {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting Lambda Layer Version {resource_id}: {e}"