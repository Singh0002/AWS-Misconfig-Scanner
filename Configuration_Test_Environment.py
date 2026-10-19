import os
import json
import boto3
from moto import mock_aws

os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    

def configuration_creation(username, bucket_name, manifest_path="manifest.json"):
    
    iam = boto3.client('iam')
    s3 = boto3.client('s3')
    
    
    iam.create_user(UserName = username)
    s3.create_bucket(Bucket = bucket_name)
    
    
    s3.put_public_access_block(Bucket = bucket_name,
    PublicAccessBlockConfiguration = {
        'BlockPublicAcls': False,
        'IgnorePublicAcls': False,
        'BlockPublicPolicy': False,
        'RestrictPublicBuckets': False}
        )
        
        
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }
        ]
    }
    
    admin_wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DangerousWildcardAdmin",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }
    
    s3.put_bucket_policy (Bucket = bucket_name,Policy = json.dumps(public_policy))
    iam.put_user_policy (UserName = username, PolicyName = "AdminFullAccess", PolicyDocument = json.dumps(admin_wildcard_policy))
    
    
    
    config_data = {"status":"active", "environment":"testing"}
    s3.put_object(Bucket = bucket_name, Key = "config.json", Body = json.dumps(config_data))
    
    
    
    
    
    mfa_response = iam.create_virtual_mfa_device(VirtualMFADeviceName = f"{username}_MFA_Device")
    
    mfa_serial = mfa_response["VirtualMFADevice"]["SerialNumber"]
    iam.enable_mfa_device(
        UserName = username, 
        SerialNumber = mfa_serial, 
        AuthenticationCode1 = "123456", 
        AuthenticationCode2 = "789012")
    
    
    manifest_data = {
        "username": username,
        "bucket_name": bucket_name,
        "policy_name": "AdminFullAccess"
    }
    with open(manifest_path, "w") as f:
        json.dump(manifest_data, f, indent=4)
        
    return manifest_path

if __name__ == "__main__":
    with mock_aws():
        saved_path = configuration_creation(
            username="mock-username", 
            bucket_name="mock-bucket", 
            manifest_path="my_generated_manifest.json"
        )
        print(f"File made: {saved_path}")
    