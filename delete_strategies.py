import boto3
import re

from botocore.exceptions import ClientError
from rich.console import Console

console = Console()

placeholder_cache_policy_id = '658327ea-f89d-4fab-a63d-7e88639e58f6'  # Replace this with your default/placeholder cache policy ID


def get_arn_pattern(resource):
    return rf'^arn:aws:iam::[0-9]{{12}}:{resource}/[a-zA-Z0-9-_]+$'

def delete_lambda_function(resource_id):
    client = boto3.client('lambda')
    try:
        client.delete_function(FunctionName=resource_id)
        console.print(f"[green]Successfully deleted Lambda function {resource_id}[/green]")
    except ClientError as e:
        return f"Error deleting Lambda function {resource_id}: {e}"

def delete_iam_role(resource_id):
    client = boto3.client('iam')

    if len(resource_id) > 64:
        return f"Invalid role name length: {resource_id}. Role name must be 64 characters or fewer."

    try:
        client.delete_role(RoleName=resource_id)
        console.print(f"[green]Successfully deleted IAM role {resource_id}[/green]")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return f"IAM role {resource_id} does not exist"
        return f"Error deleting IAM role {resource_id}: {e}"

def delete_iam_policy(resource_id):
    client = boto3.client('iam')

    arn_pattern = get_arn_pattern('policy')
    if not re.match(arn_pattern, resource_id):
        return f"Invalid ARN format: {resource_id}"

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

def delete_ec2_security_group(resource_arn):
    client = boto3.client('ec2')
    group_id = resource_arn.split('/')[-1]

    try:
        # Detach any network interfaces associated with the security group
        network_interfaces = client.describe_network_interfaces(Filters=[{'Name': 'group-id', 'Values': [group_id]}])
        for ni in network_interfaces['NetworkInterfaces']:
            client.modify_network_interface_attribute(
                NetworkInterfaceId=ni['NetworkInterfaceId'],
                Groups=[]
            )

        # Remove the security group from any running instances
        instances = client.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [group_id]}])
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                existing_groups = [g['GroupId'] for g in instance['SecurityGroups'] if g['GroupId'] != group_id]
                client.modify_instance_attribute(
                    InstanceId=instance_id,
                    Groups=existing_groups
                )

        # Delete any associated rules (this is typically not needed, but included for completeness)
        client.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[])
        client.revoke_security_group_egress(GroupId=group_id, IpPermissions=[])

        # Finally, delete the security group
        client.delete_security_group(GroupId=group_id)
        console.print(f"[green]Successfully deleted EC2 Security Group {group_id}[/green]")
    except ClientError as e:
        return f"Error deleting EC2 Security Group {group_id}: {e}"

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

def delete_vpc(resource_arn):
    client = boto3.client('ec2')
    vpc_id = resource_arn.split('/')[-1]

    try:
        # Detach and delete any internet gateways attached to the VPC
        igw_response = client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
        for igw in igw_response['InternetGateways']:
            client.detach_internet_gateway(InternetGatewayId=igw['InternetGatewayId'], VpcId=vpc_id)
            client.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])

        # Delete any subnets associated with the VPC
        subnets_response = client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for subnet in subnets_response['Subnets']:
            client.delete_subnet(SubnetId=subnet['SubnetId'])

        # Delete any route tables associated with the VPC, excluding the main route table
        rt_response = client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for rt in rt_response['RouteTables']:
            if not rt['Associations'][0]['Main']:
                client.delete_route_table(RouteTableId=rt['RouteTableId'])

        # Delete any network ACLs associated with the VPC, excluding the default network ACL
        acl_response = client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for acl in acl_response['NetworkAcls']:
            if not acl['IsDefault']:
                client.delete_network_acl(NetworkAclId=acl['NetworkAclId'])

        # Delete any security groups associated with the VPC, excluding the default security group
        sg_response = client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for sg in sg_response['SecurityGroups']:
            if sg['GroupName'] != 'default':
                client.delete_security_group(GroupId=sg['GroupId'])

        # Finally, delete the VPC
        client.delete_vpc(VpcId=vpc_id)
        console.print(f"[green]Successfully deleted VPC {vpc_id}[/green]")
    except ClientError as e:
        return f"Error deleting VPC {vpc_id}: {e}"

def delete_subnet(resource_arn):
    client = boto3.client('ec2')
    subnet_id = resource_arn.split('/')[-1]

    try:
        # Detach and delete any network interfaces associated with the subnet
        network_interfaces = client.describe_network_interfaces(Filters=[{'Name': 'subnet-id', 'Values': [subnet_id]}])
        for ni in network_interfaces['NetworkInterfaces']:
            client.delete_network_interface(NetworkInterfaceId=ni['NetworkInterfaceId'])

        # Terminate any instances in the subnet
        instances = client.describe_instances(Filters=[{'Name': 'subnet-id', 'Values': [subnet_id]}])
        instance_ids = [instance['InstanceId'] for reservation in instances['Reservations'] for instance in reservation['Instances']]
        if instance_ids:
            client.terminate_instances(InstanceIds=instance_ids)
            waiter = client.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=instance_ids)

        # Detach any load balancers from the subnet (ELBv2)
        elb_client = boto3.client('elbv2')
        load_balancers = elb_client.describe_load_balancers()
        for lb in load_balancers['LoadBalancers']:
            if lb['VpcId'] == subnet_id:
                elb_client.delete_load_balancer(LoadBalancerArn=lb['LoadBalancerArn'])

        # Disassociate and delete any route tables associated with the subnet
        route_tables = client.describe_route_tables(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])
        for rt in route_tables['RouteTables']:
            for association in rt['Associations']:
                if not association['Main']:
                    client.disassociate_route_table(AssociationId=association['RouteTableAssociationId'])
                    client.delete_route_table(RouteTableId=rt['RouteTableId'])

        # Disassociate any network ACLs associated with the subnet
        network_acls = client.describe_network_acls(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])
        for acl in network_acls['NetworkAcls']:
            for association in acl['Associations']:
                if association['SubnetId'] == subnet_id:
                    client.replace_network_acl_association(
                        AssociationId=association['NetworkAclAssociationId'],
                        NetworkAclId=acl['DefaultNetworkAclId']
                    )

        # Finally, delete the subnet
        client.delete_subnet(SubnetId=subnet_id)
        console.print(f"[green]Successfully deleted EC2 Subnet {subnet_id}[/green]")
    except ClientError as e:
        return f"Error deleting EC2 Subnet {subnet_id}: {e}"

def delete_nat_gateway(resource_arn):
    client = boto3.client('ec2')
    nat_gateway_id = resource_arn.split('/')[-1]

    try:
        # Delete the NAT Gateway
        client.delete_nat_gateway(NatGatewayId=nat_gateway_id)
        console.print(f"[green]Successfully deleted EC2 NAT Gateway {nat_gateway_id}[/green]")
    except ClientError as e:
        return f"Error deleting EC2 NAT Gateway {nat_gateway_id}: {e}"

def delete_cloudfront_cache_policy(resource_arn):
    client = boto3.client('cloudfront')
    cache_policy_id = resource_arn.split('/')[-1]

    try:
        # Get the list of distributions
        distributions = client.list_distributions()

        for distribution in distributions.get('DistributionList', {}).get('Items', []):
            dist_id = distribution['Id']
            dist_response = client.get_distribution_config(Id=dist_id)
            etag = dist_response['ETag']
            distribution_config = dist_response['DistributionConfig']

            # Check and update cache behaviors
            modified = False
            cache_behaviors = distribution_config.get('CacheBehaviors', {}).get('Items', [])
            for cache_behavior in cache_behaviors:
                if cache_behavior.get('CachePolicyId') == cache_policy_id:
                    cache_behavior['CachePolicyId'] = placeholder_cache_policy_id
                    modified = True

            default_cache_behavior = distribution_config.get('DefaultCacheBehavior', {})
            if default_cache_behavior.get('CachePolicyId') == cache_policy_id:
                default_cache_behavior['CachePolicyId'] = placeholder_cache_policy_id
                modified = True

            # Update the distribution if any modifications were made
            if modified:
                client.update_distribution(
                    Id=dist_id,
                    IfMatch=etag,
                    DistributionConfig=distribution_config
                )
                client.get_waiter('distribution_deployed').wait(Id=dist_id)

        # Get the cache policy's current configuration and ETag
        response = client.get_cache_policy(Id=cache_policy_id)
        etag = response['ETag']

        # Delete the cache policy
        client.delete_cache_policy(Id=cache_policy_id, IfMatch=etag)
        console.print(f"[green]Successfully deleted CloudFront Cache Policy {cache_policy_id}[/green]")
    except ClientError as e:
        return f"Error deleting CloudFront Cache Policy {cache_policy_id}: {e}"
    except KeyError as e:
        return f"Error processing CloudFront Cache Policy {cache_policy_id}: Missing key {e}"
