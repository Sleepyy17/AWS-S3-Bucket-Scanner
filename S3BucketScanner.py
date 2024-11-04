import boto3
from botocore.exceptions import ClientError, ParamValidationError, NoCredentialsError
import argparse
import sys

global first_object_name
global flag_deep_analysis
global perms_allowed
global isAdmin

first_object_name = None
flag_deep_analysis = False
isAdmin = False
perms_allowed = []

def create_s3_client(profile_name='default'):
    session = boto3.Session(profile_name=profile_name)
    return session.client('s3')

def manage_exception(e, bucket_name, operation):
    error_code = e.response['Error']['Code']
    error_messages = {
        'NoSuchBucket': f'Bucket {bucket_name} does not exist',
        'AccessDenied': f'Bucket {bucket_name} denies {operation.upper()} operation',
        'NoSuchKey': f'Object not found in bucket {bucket_name}'
    }
    return {
        'status': 'error', 
        'message': error_messages.get(error_code, f'Unexpected error: {e}')
    }

def check_s3_operation(operation, bucket_name, s3, key=None, body=None):
    global first_object_name
    try:
        if operation == 'list':
            result = s3.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in result and len(result['Contents']) > 0:
                first_object_name = result['Contents'][0]['Key']
            return {
                'status': 'success',
                'message': f"Bucket {bucket_name} has List Buckets permission publicly granted",
            }
        elif operation == 'get':
            s3.get_object(Bucket=bucket_name, Key=key)
            return {
                'status': 'success',
                'message': f"Bucket {bucket_name} has Get Object permission publicly granted"
            }
        elif operation == 'put':
            s3.put_object(Bucket=bucket_name, Key=key, Body=body)
            return {
                'status': 'success',
                'message': f"Bucket {bucket_name} has Put Object permission publicly granted"
            }
        elif operation == 'delete':
            s3.delete_object(Bucket=bucket_name, Key=key)
            return {
                'status': 'success',
                'message': f"Bucket {bucket_name} has Delete Object permission publicly granted"
            }
    except ClientError as e:
        return manage_exception(e, bucket_name, operation)

def check_bucket_permissions(bucket_name, s3):
    global perms_allowed
    perms_allowed = []
    returnStr = []

    resultList = check_s3_operation('list', bucket_name, s3, key='test.txt', body=b'S3 Bucket Scanner Test')
    resultPut = check_s3_operation('put', bucket_name, s3, key='scanner_test123.txt', body=b'S3 Bucket Scanner Test')
    if (resultPut['status'] == 'error' and resultList['status'] == 'success'):
        resultGet = check_s3_operation('get', bucket_name, s3, key=f'{first_object_name}')
    else:
        resultGet = check_s3_operation('get', bucket_name, s3, key='scanner_test123.txt')
    resultDelete = check_s3_operation('delete', bucket_name, s3, key='scanner_test123.txt')

    if (resultList['status'] == 'success'):
        perms_allowed.append('list')
    if (resultGet['status'] == 'success'):
        perms_allowed.append('get')
    if (resultPut['status'] == 'success'):
        perms_allowed.append('put')
    if (resultDelete['status'] == 'success'):
        perms_allowed.append('delete')

    returnStr.append({'status': resultList['status'], 'message': resultList['message']})
    returnStr.append({'status': resultGet['status'], 'message': resultGet['message']})
    returnStr.append({'status': resultPut['status'], 'message': resultPut['message']})
    returnStr.append({'status': resultDelete['status'], 'message': resultDelete['message']})

    return returnStr

def get_all_objects(bucket_name, s3):
    all_objects = []
    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get('Contents', []):
            all_objects.append(obj['Key'])
    return all_objects

def deep_scan_bucket(all_objects, bucket_name, s3):
    
    for obj in all_objects:
        try:
            s3.get_object(Bucket=bucket_name, Key=obj)
            print(f"Object {obj} is publicly accessible")
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print(f"Object {obj} is not publicly accessible")
            else:
                print(f"Error: {e}")
    return


def set_is_admin(bucket_name, s3):
    global isAdmin
    try:
        # Shouldn't screw up anything hopefully
        acl_response = s3.get_bucket_acl(Bucket=bucket_name)
        acl_policy = {
            "Grants": acl_response["Grants"],
            "Owner": acl_response["Owner"]
        }
        s3.put_bucket_acl(Bucket=bucket_name, AccessControlPolicy=acl_policy)
        isAdmin = True
    except ClientError as e:
        isAdmin = False
        if e.response['Error']['Code'] == 'AccessDenied':
            pass
        else:
            print(f"PutBucketAcl: An error occurred - {e}")
    except ParamValidationError as e:
        isAdmin = False
        print(f"ParamValidationError:")
        pass

def get_bucket_acl(bucket_name, s3):
    try:
        response = s3.get_bucket_acl(Bucket=bucket_name)
        return response
    except ClientError as e:
        print(f"Error retrieving bucket ACL: {e}")
        return None

def print_acl_details(acl_response):
    acl_permissions = {}
    for grant in acl_response['Grants']:
        grantee = grant['Grantee']
        permission = grant['Permission']

        if grantee['Type'] == 'CanonicalUser':
            grantee_key = f"Grantee (Account): {grantee.get('DisplayName', 'Unknown')}"
        elif grantee['Type'] == 'Group':
            grantee_key = f"Grantee (Group): {grantee.get('URI').split('/')[-1]}" 

        acl_permissions[grantee_key] = acl_permissions.get(grantee_key, []) + [permission]

    for grantee, permissions in acl_permissions.items():
        permissions_str = ', '.join(permissions)
        print(f"{grantee} - Permissions [{permissions_str}]")

def get_object_acl(object_key, bucket_name, s3):
    try:
        acl_response = s3.get_object_acl(Bucket=bucket_name, Key=object_key)
        print(f"ACL for object {object_key}:")
        
        print_acl_details(acl_response)
    except ClientError as e:
        print(f"Error retrieving ACL for object {object_key}: {e}")

def scan_bucket_permissions(bucket_names, profile_name='default'):
    s3 = create_s3_client(profile_name)


    for bucket in bucket_names:
        print(f"Scanning bucket: {bucket}")
        print("-" * 44)
        try:
            s3.head_bucket(Bucket=bucket)
            print(f"Bucket {bucket} EXISTS")
        except ClientError as e:
            if e.response['Error']['Code'] == '403':
                print(f"Bucket {bucket} EXISTS")
            elif e.response['Error']['Code'] == '404':
                print(f"Bucket {bucket} does not exist")
                continue
            else:
                print(f"Error: {e}")
                continue
        except NoCredentialsError:
            print("Error: Default AWS credentials could not be found. Please provide profile or setup default credentials with 'aws configure'.")
            exit(1)
        print("-" * 44)
        set_is_admin(bucket, s3)
        print(f"Profile is Admin: {isAdmin}")
        print("-" * 44)
        
        if isAdmin:
            bucket_acl = get_bucket_acl(bucket, s3)
            if bucket_acl:
                print_acl_details(bucket_acl)
            print("-" * 44)
            if flag_deep_analysis:
                all_objects = get_all_objects(bucket, s3)
                for i, obj in enumerate(all_objects):
                    get_object_acl(obj, bucket, s3)
                    if i < len(all_objects) - 1:
                        print("")
        else:
            result = check_bucket_permissions(bucket, s3)

            for r in result:
                print(r['message'])
            print("-" * 44)

            if flag_deep_analysis:
                if 'list' in perms_allowed:
                    all_objects = get_all_objects(bucket, s3)
                    deep_scan_bucket(all_objects, bucket, s3)
                else: 
                    print(f"Cannot perform deep scan on {bucket} because LIST permission is not granted")

        print("-" * 44)
        print("\n")

def read_buckets(args):
    bucket_names = []

    if args.buckets:
        bucket_names.extend(args.buckets)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                bucket_names.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"Error: The file {args.file} does not exist.")
            exit(1)
    
    return bucket_names

def main():
    global flag_deep_analysis
    parser = argparse.ArgumentParser(description='Scan S3 buckets for public access')
    parser.add_argument(
        '--buckets', 
        nargs='+', 
        help="List of bucket names separated by spaces."
    )
    parser.add_argument(
        '--file', 
        type=str, 
        help="File with a list of bucket names to scan. Buckets must be separated by newlines."
    )
    parser.add_argument('--profile', type=str, help='AWS profile to use for scanning. Default will be used if not provided.')

    parser.add_argument('--deep', action='store_true', help='Perform deep analysis on buckets iterating over all objects.')
    parser.add_argument('--output', help="File to direct the output to.")

    args = parser.parse_args()

    if args.output:
        sys.stdout = open(args.output, 'w')

    profile_name = "default"
    if args.profile:
        profile_name = args.profile
    if args.deep:
        flag_deep_analysis = True
    if not args.buckets and not args.file:
        parser.error("You must provide either --buckets or --file.")
    
    buckets_to_scan = read_buckets(args)
    
    scan_bucket_permissions(buckets_to_scan, profile_name=profile_name)
    
if __name__ == "__main__":
    main()
