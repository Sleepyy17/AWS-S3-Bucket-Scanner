import subprocess


# provide profile to use, with s3 permissions. (too broad rn safety issue for people using lol)
profile_name = "testing"

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout, result.stderr
    except Exception as e:
        print(f"Error executing command: {command}\n{e}")
        return None, None
    
def log_command():
    pass
    
def check_public_bucket(bucket_name):
    print(f"Checking if bucket {bucket_name} is public...\n")
    command = f"aws s3 --profile {profile_name} ls s3://{bucket_name} --no-sign-request"
    
    stdout, stderr = run_command(command)
    if "AccessDenied" in stderr:
        print(f"Bucket {bucket_name} exists, but is not publicly accessible.")
    elif "NoSuchBucket" in stderr:
        print(f"The specified bucket {bucket_name} does not exist.")
    elif stdout:
        print(f"Bucket {bucket_name} is publicly accessible.")
        #Log
    else:
        print(f"Something went wrong, could not determine public status for {bucket_name}.\n")
        print(f"stdout: {stdout.strip()}\nstderr: {stderr.strip()}\n")

def main():
    buckets = ["nope"]

    for bucket in buckets:
        print("######################################################################\n")
        check_public_bucket(bucket)

if __name__ == "__main__":
    main()
