import csv
import boto3
import logging
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def generate_csv(data, filename, fieldnames):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in data:
            writer.writerow(item)

def lambda_handler(event, context):
    logger.info("Event: " + str(event))

    # Assume a role in the organization to retrieve information about all accounts
    sts = boto3.client("sts")
    response = sts.get_caller_identity()
    current_account_id = response["Account"]

    orgs_client = boto3.client("organizations")
    paginator = orgs_client.get_paginator("list_accounts")
    account_iterator = paginator.paginate()

    ec2_csv_data = []
    s3_csv_data = []
    rds_csv_data = []

    for page in account_iterator:
        for account in page["Accounts"]:
            account_id = account["Id"]
            account_name = account["Name"]
            logger.info(f"Processing account: {account_name} ({account_id})")

            if account_id == 'XXXXXXXXX':
                logger.info(f"Skipping processing for account: {account_id}")
                continue

            # Assume a role in the account to perform operations
            assume_role_response = sts.assume_role(
                RoleArn=f"arn:aws:iam::{account_id}:role/org-worker",
                RoleSessionName="AssumedRoleSession"
            )

            # Create a session using the assumed role credentials
            new_session = boto3.Session(
                aws_access_key_id=assume_role_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=assume_role_response['Credentials']['SecretAccessKey'],
                aws_session_token=assume_role_response['Credentials']['SessionToken']
            )

            # Retrieve EC2 instances
            ec2_client = new_session.client('ec2')
            ec2_instances = ec2_client.describe_instances()

            for reservation in ec2_instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_type = instance['InstanceType']
                    instance_state = instance['State']['Name']
                    instance_ip = instance.get('PublicIpAddress', 'N/A')
                    instance_name = ''
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break

                    # Append data to EC2 CSV data list
                    ec2_csv_data.append({
                        'Account Name': account_name,
                        'EC2 Name': instance_name,
                        'Instance Type': instance_type,
                        'State': instance_state
                    })

                    # Print or process the EC2 instance information
                    print(f"Account: {account_name} ({account_id}), EC2 Name: {instance_name}, Type: {instance_type}, State: {instance_state}, IP: {instance_ip}")

            # Retrieve S3 buckets
            s3_client = new_session.client('s3')
            s3_buckets = s3_client.list_buckets()

            for bucket in s3_buckets['Buckets']:
                bucket_name = bucket['Name']
                # Append data to S3 CSV data list
                s3_csv_data.append({
                    'Account Name': account_name,
                    'Bucket Name': bucket_name
                })
           # Retrieve RDS instances
            rds_client = new_session.client('rds')
            rds_instances = rds_client.describe_db_instances()

            for rds_instance in rds_instances['DBInstances']:
                rds_identifier = rds_instance['DBInstanceIdentifier']
                rds_engine = rds_instance['Engine']
                rds_status = rds_instance['DBInstanceStatus']
                rds_endpoint = rds_instance['Endpoint']['Address']
                rds_instance_class = rds_instance['DBInstanceClass']
                rds_allocated_storage = rds_instance['AllocatedStorage']
                # Append data to RDS CSV data list
                rds_csv_data.append({
                    'Account Name': account_name,
                    'RDS Identifier': rds_identifier,
                    'Engine': rds_engine,
                    'Status': rds_status,
                    'Endpoint': rds_endpoint,
                    'Instance Class': rds_instance_class,
                    'Allocated Storage': rds_allocated_storage
                })

    # Generate EC2 CSV file
    ec2_csv_filename = "/tmp/ec2_inventory.csv"
    ec2_fieldnames = ['Account Name',  'EC2 Name', 'Instance Type', 'State', 'IP']
    generate_csv(ec2_csv_data, ec2_csv_filename, ec2_fieldnames)

    # Generate S3 CSV file
    s3_csv_filename = "/tmp/s3_inventory.csv"
    s3_fieldnames = ['Account Name', 'Bucket Name']
    generate_csv(s3_csv_data, s3_csv_filename, s3_fieldnames)

    # Generate RDS CSV file
    rds_csv_filename = "/tmp/rds_inventory.csv"
    rds_fieldnames = ['Account Name', 'RDS Identifier', 'Engine', 'Status', 'Endpoint', 'Instance Class', 'Allocated Storage']
    generate_csv(rds_csv_data, rds_csv_filename, rds_fieldnames)

    # Upload files to S3
    s3_client = boto3.client('s3')
    s3_bucket_name = 'inventory-ec2-s3'
    s3_client.upload_file(ec2_csv_filename, s3_bucket_name, 'ec2_inventory.csv')
    s3_client.upload_file(s3_csv_filename, s3_bucket_name, 's3_inventory.csv')
    s3_client.upload_file(rds_csv_filename, s3_bucket_name, 'rds_inventory.csv')

    return {
        'statusCode': 200,
        'body': json.dumps('CSV files uploaded to S3')
    }
