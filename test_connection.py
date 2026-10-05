import boto3
from botocore.exceptions import ClientError

def test_s3():
    print("Testing S3 access...")
    s3 = boto3.client('s3')
    try:
        response = s3.list_buckets()
        buckets = response['Buckets']
        print(f"  Success — found {len(buckets)} bucket(s)")
        for b in buckets:
            print(f"    - {b['Name']}")
    except ClientError as e:
        print(f"  Failed: {e.response['Error']['Code']}")

if __name__ == "__main__":
    test_s3()