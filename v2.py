import boto3
from botocore.exceptions import ClientError

session = boto3.Session(profile_name='testing')
s3 = session.client('s3')

def check_public_bucket(bucket_name):
    print(f"Checking if bucket {bucket_name} is public...\n")

    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        print(f"Bucket {bucket_name} is publicly accessible")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            print(f"The specified bucket {bucket_name} does not exist.")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print(f"Bucket {bucket_name} exists, but is not publicly accessible.")
        else:
            print(f"Something went wrong, could not determine public status for {bucket_name}.\n")
            print(f"Error: {e}")


def main():
    buckets = ["nope"]

    for bucket in buckets:
        print("######################################################################\n")
        check_public_bucket(bucket)

if __name__ == "__main__":
    main()
