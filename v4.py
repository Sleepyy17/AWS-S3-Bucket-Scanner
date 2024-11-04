import boto3
from botocore.exceptions import ClientError

first_object_name = None

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
    operations = ['list', 'get', 'put', 'delete']
    returnStr = []

    resultList = check_s3_operation('list', bucket_name, s3, key='test.txt', body=b'S3 Bucket Scanner Test')
    resultPut = check_s3_operation('put', bucket_name, s3, key='scanner_test123.txt', body=b'S3 Bucket Scanner Test')
    if (resultPut['status'] == 'error' and resultList['status'] == 'success'):
        resultGet = check_s3_operation('get', bucket_name, s3, key=f'{first_object_name}')
    else:
        resultGet = check_s3_operation('get', bucket_name, s3, key='scanner_test123.txt')
    resultDelete = check_s3_operation('delete', bucket_name, s3, key='scanner_test123.txt')

    returnStr.append({'status': resultList['status'], 'message': resultList['message']})
    returnStr.append({'status': resultGet['status'], 'message': resultGet['message']})
    returnStr.append({'status': resultPut['status'], 'message': resultPut['message']})
    returnStr.append({'status': resultDelete['status'], 'message': resultDelete['message']})

    return returnStr

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
        print("-" * 44)
        result = check_bucket_permissions(bucket, s3)
        for r in result:
            print(r['message'])
        print("-" * 44)
        print("\n")

def main():
    buckets_to_scan = ["nope"]
    scan_bucket_permissions(buckets_to_scan, "testing")

if __name__ == "__main__":
    main()
