import boto3
import typer
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from natsort import natsorted
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from delete_strategies import (
    delete_lambda_function, delete_iam_role, delete_iam_policy,
    delete_cloudwatch_log_resource_policy, delete_log_group, delete_events_rule,
    delete_ssm_parameter, delete_sqs_queue, delete_events_event_bus,
    delete_log_retention, delete_dynamodb_table, delete_ec2_security_group,
    delete_cloudfront_function, delete_lambda_layer_version, delete_cloudfront_distribution,
    delete_vpc, delete_subnet, delete_nat_gateway
)
from custom_strategies import (
    delete_sourcemap_uploader,
)


console = Console()

filters = {
    'active': [
        'CREATE_COMPLETE',
        'DELETE_FAILED',
        'ROLLBACK_COMPLETE',
        'ROLLBACK_FAILED',
        'UPDATE_COMPLETE',
        'UPDATE_ROLLBACK_COMPLETE',
    ],
    'complete': [
        'CREATE_COMPLETE',
        'UPDATE_COMPLETE',
        'UPDATE_ROLLBACK_COMPLETE',
    ],
    'failed': [
        'DELETE_FAILED',
        'ROLLBACK_COMPLETE',
        'ROLLBACK_FAILED',

    ],
    'deleted': [
        'DELETE_COMPLETE'
    ],
}


def create_client_cacher():
    clients = {}

    def get_client(service_name):
        if service_name not in clients:
            clients[service_name] = boto3.client(service_name)
        return clients[service_name]

    return get_client

get_client = create_client_cacher()

def get_stacks_by_status(status_filter='failed'):
    client = boto3.client('cloudformation')
    paginator = client.get_paginator('list_stacks')
    try:
        stacks = []

        stack_status_filter = filters[status_filter]
        stack_pager = paginator.paginate(StackStatusFilter=stack_status_filter)

        for page in stack_pager:
            for stack in page['StackSummaries']:
                stacks.append(stack)

        return stacks
    except (NoCredentialsError, PartialCredentialsError) as e:
        console.print(f"[bold red]Error: Invalid AWS security token. {e}[/bold red]")
        raise typer.Exit(code=1)
    except ClientError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise typer.Exit(code=1)

def show_stack_resources(stack_name):
    client = client = get_client('cloudformation')
    return client.describe_stack_resources(StackName=stack_name)['StackResources']

def delete_resource(resource_type, resource_id):
    error = None
    try:
        if resource_type == 'AWS::Lambda::Function':
            error = delete_lambda_function(resource_id)
        elif resource_type == 'AWS::IAM::Role':
            error = delete_iam_role(resource_id)
        elif resource_type == 'AWS::IAM::Policy':
            error = delete_iam_policy(resource_id)
        elif resource_type == 'Custom::CloudwatchLogResourcePolicy':
            error = delete_cloudwatch_log_resource_policy(resource_id)
        elif resource_type == 'AWS::Logs::LogGroup':
            error = delete_log_group(resource_id)
        elif resource_type == 'AWS::Events::Rule':
            error = delete_events_rule(resource_id)
        elif resource_type == 'AWS::SSM::Parameter':
            error = delete_ssm_parameter(resource_id)
        elif resource_type == 'AWS::SQS::Queue':
            error = delete_sqs_queue(resource_id)
        elif resource_type == 'AWS::Events::EventBus':
            error = delete_events_event_bus(resource_id)
        elif resource_type == 'Custom::LogRetention':
            error = delete_log_retention(resource_id)
        elif resource_type == 'AWS::DynamoDB::Table':
            error = delete_dynamodb_table(resource_id)
        elif resource_type == 'AWS::EC2::SecurityGroup':
            error = delete_ec2_security_group(resource_id)
        elif resource_type == 'Custom::SourcemapUploader':
            error = delete_sourcemap_uploader(resource_id)
        elif resource_type == 'AWS::CloudFront::Function':
            error = delete_cloudfront_function(resource_id)
        elif resource_type == 'AWS::Lambda::LayerVersion':
            error = delete_lambda_layer_version(resource_id)
        elif resource_type == 'AWS::CloudFront::Distribution':
            error = delete_cloudfront_distribution(resource_id)
        elif resource_type == 'AWS::EC2::VPC':
            error = delete_vpc(resource_id)
        elif resource_type == 'AWS::EC2::Subnet':
            error = delete_subnet(resource_id)
        elif resource_type == 'AWS::EC2::NatGateway':
            error = delete_nat_gateway(resource_id)
        else:
            console.print(f"\n[bold red]Unsupported or unknown resource type {resource_type} for resource {resource_id}[/bold red]")
            raise typer.Exit(code=1)

        return error
    except ClientError as e:
        console.print(f"\n[bold red]Error deleting resource {resource_id}: {e}[/bold red]")
        raise typer.Exit(code=1)


def delete_stack_resources(stack_name):
    client = get_client('cloudformation')
    resources = show_stack_resources(stack_name)
    resources_to_delete = {res['PhysicalResourceId']:res['ResourceType'] for res in resources if res['ResourceStatus'] != 'DELETE_COMPLETE'}

    errors = []

    with Progress() as progress:
        task = progress.add_task(f"Deleting resources in stack {stack_name}", total=len(resources_to_delete))

        for resource_id, resource_type in resources_to_delete.items():
            error = delete_resource(resource_type, resource_id)
            if error:
                errors.append(error.replace('An error occurred', ''))
            progress.advance(task)

    try:
        client.delete_stack(StackName=stack_name)
        console.print(f"Stack {stack_name} deletion initiated.")
    except ClientError as e:
        errors.append(f"Error deleting stack {stack_name}: {e}")

    if errors:
        console.print("[bold red]Errors encountered during deletion:[/bold red]")
        for error in errors:
            console.print(f"[bold red]{error}[/bold red]")

app = typer.Typer()

@app.command()
def main():
    stacks = get_stacks_by_status()

    if not stacks:
        console.print("No stacks in DELETE_FAILED state found.")
        return

    console.print("Stacks in DELETE_FAILED state:")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Index", style="dim", width=6)
    table.add_column("Stack Name")
    table.add_column("Status")
    table.add_column("Stack ID")

    sorted_stacks = natsorted(stacks, key=lambda stack: stack['StackName'].lower())
    for index, stack in enumerate(sorted_stacks, start=1):
        table.add_row(str(index), stack['StackName'], stack['StackStatus'], stack['StackId'])

    console.print(table)

    stack_index = typer.prompt("Enter the index of the stack to delete [0 to exit]", type=int)
    if stack_index < 0 or stack_index > len(sorted_stacks):
        console.print("Invalid index.")
        return

    if stack_index == 0:
        console.print('Quitting.')
        return

    stack_name = sorted_stacks[stack_index - 1]['StackName']

    resources = show_stack_resources(stack_name)
    if not resources:
        console.print(f"No resources found in stack {stack_name}.")
        return

    console.print(f"Resources in stack {stack_name}:")
    resource_table = Table(show_header=True, header_style="bold magenta")
    resource_table.add_column("Logical ID")
    resource_table.add_column("Physical ID")
    resource_table.add_column("Resource Type")
    resource_table.add_column("Status")
    resource_table.add_column("Description")

    for resource in resources:
        resource_table.add_row(
            resource['LogicalResourceId'],
            resource['PhysicalResourceId'],
            resource['ResourceType'],
            resource['ResourceStatus'],
            resource.get('Description', 'No description provided')
        )

    console.print(resource_table)

    confirm = typer.confirm(f"Do you want to delete the resources in stack {stack_name}?")
    if confirm:
        delete_stack_resources(stack_name)
    else:
        console.print("Deletion cancelled.")

if __name__ == "__main__":
    app()
