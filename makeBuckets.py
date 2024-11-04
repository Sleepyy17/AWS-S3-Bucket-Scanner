import boto3
import json

session = boto3.Session(profile_name='testing')
s3_client = session.client('s3')
bucket_name = "nope"

try:
    s3_client.create_bucket(Bucket=bucket_name)
    print(f"Bucket '{bucket_name}' created.")
except s3_client.exceptions.BucketAlreadyOwnedByYou:
    print(f"Bucket '{bucket_name}' already exists.")

s3_client.put_public_access_block(
    Bucket=bucket_name,
    PublicAccessBlockConfiguration={
        'BlockPublicAcls': False,
        'IgnorePublicAcls': False,
        'BlockPublicPolicy': False,
        'RestrictPublicBuckets': False
    }
)
print(f"Public access block settings have been disabled for bucket: {bucket_name}")


s3_client.put_bucket_acl(
    Bucket=bucket_name,
    ACL='authenticated-read'
)

policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:GetObject"],
            "Resource": f"arn:aws:s3:::{bucket_name}/Bonzibuddy.jpg"
        },
    ]
}

s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
print(f"Policy added to bucket '{bucket_name}'.")
