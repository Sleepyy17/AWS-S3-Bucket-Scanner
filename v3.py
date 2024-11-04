import boto3
from botocore.exceptions import ClientError
import pprint

session = boto3.Session(profile_name='testing')
s3 = session.client('s3')

def check_list_object(bucket_name):
    print(f"LIST Checking if bucket {bucket_name} has a misconfiguration...\n")

    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        print(f"Bucket {bucket_name} has List Buckets permission publicly granted")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            print(f"The specified bucket {bucket_name} does not exist.")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print(f"Bucket {bucket_name} exists, but dpes not have LIST permissions publicly accessible.")
        else:
            print(f"Something went wrong, could not determine public status for {bucket_name}.\n")
            print(f"Error: {e}")

def check_get_object(bucket_name):
    print(f"GET Checking if bucket {bucket_name} has a misconfiguration...\n")

    file_key = 'SecurityPosterBucketScanner.pdf'
    try:
        response = s3.get_object(Bucket=bucket_name, Key=file_key)
        print(f"Bucket {bucket_name} has Get Object permission publicly granted")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            print(f"The specified bucket {bucket_name} does not exist.")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print(f"Bucket {bucket_name} exists, but does not have GET permissions publicly accessible.")
            print(f"Error: {e}")
        elif e.response['Error']['Code'] == 'NoSuchKey':
            print(f"Bucket {bucket_name} exists, but the object {file_key} does not exist.")
            print(f"Error: {e}")
        else:
            print(f"Something went wrong, could not determine public status for {bucket_name}.\n")
            print(f"Error: {e}")

def check_put_object(bucket_name):
    print(f"PUT Checking if bucket {bucket_name} has a misconfiguration...\n")

    file_key = 'test.txt'
    try:
        response = s3.put_object(Bucket=bucket_name, Key=file_key, Body=b'Hello World!')
        print(f"Bucket {bucket_name} has Put Object permission publicly granted")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            print(f"The specified bucket {bucket_name} does not exist.")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print(f"Bucket {bucket_name} exists, but does not have PUT permissions publicly accessible.")
        else:
            print(f"Something went wrong, could not determine public status for {bucket_name}.\n")
            print(f"Error: {e}")

def check_delete_object(bucket_name):
    print(f"DELETE Checking if bucket {bucket_name} has a misconfiguration...\n")

    file_key = 'test.txt'
    try:
        response = s3.delete_object(Bucket=bucket_name, Key=file_key)
        print(f"Bucket {bucket_name} has Delete Object permission publicly granted")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            print(f"The specified bucket {bucket_name} does not exist.")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print(f"Bucket {bucket_name} exists, but does not have DELETE permissions publicly accessible.")
        elif e.response['Error']['Code'] == 'NoSuchKey':
            print(f"Bucket {bucket_name} exists and has Delete Object permission, but the object {file_key} does not exist.")
        else:
            print(f"Something went wrong, could not determine public status for {bucket_name}.\n")
            print(f"Error: {e}")
        

def main():
    buckets = ["nope"]


    for bucket in buckets:
        print("######################################################################\n")
        check_list_object(bucket)

if __name__ == "__main__":
    main()
