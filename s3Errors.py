import boto3
import pprint

client = boto3.client('s3')

exceptions = list(client.exceptions._code_to_exception)
pprint.pprint(exceptions)
