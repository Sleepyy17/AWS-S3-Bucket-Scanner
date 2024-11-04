 Hii testing

 Steps:

 Install Boto3

 Install awscli

 Install python3

usage: v5.py [-h] [--buckets BUCKETS [BUCKETS ...]] [--file FILE] [--profile PROFILE] [--deep] [--output OUTPUT]

Scan S3 buckets for public access

options:
  -h, --help            show this help message and exit

  --buckets BUCKETS [BUCKETS ...]
                        List of bucket names separated by spaces.

  --file FILE           File with a list of bucket names to scan. Buckets must be separated by newlines.

  --profile PROFILE     AWS profile to use for scanning. Default will be used if not provided.

  --deep                Perform deep analysis on buckets iterating over all objects.
  
  --output OUTPUT       File to direct the output to.
