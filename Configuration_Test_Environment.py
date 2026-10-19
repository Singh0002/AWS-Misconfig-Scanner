import os
import json
import boto3
import datetime
from dateutil.tz import tzutc
from moto import mock_aws
from moto.iam.models import iam_backends

os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    
#Fail test cases for S3 and IAM (Public bucket, HTTP Not enforced, Admin permissions, Versioning suspended, expired access keys, No MFA device)
def configuration_creation(username, bucket_name, manifest_path="manifest.json"):
    
    
    iam = boto3.client('iam')
    s3 = boto3.client('s3')
    
    # Create bucket for S3 and account for IAM
    iam.create_user(UserName = username)
    s3.create_bucket(Bucket = bucket_name)
    
    
    #Make bucket to be public
    s3.put_public_access_block(Bucket = bucket_name,
    PublicAccessBlockConfiguration = {
        'BlockPublicAcls': False,
        'IgnorePublicAcls': False,
        'BlockPublicPolicy': False,
        'RestrictPublicBuckets': False}
        )
    
    # Dummy data dumped into bucket
    config_data = {"status":"active", "environment":"testing"}
    s3.put_object(Bucket = bucket_name, Key = "config.json", Body = json.dumps(config_data))    
        
    # HTTP Not Enforced Policy   
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
    
    #Overly permissive policy
    admin_wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DangerousWildcardAdmin",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }
    

    # Versioning fail case, put http not enforced policy into bucket, put overly permissive policy into account
    s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'Status': 'Suspended'})    
    s3.put_bucket_policy (Bucket = bucket_name,Policy = json.dumps(public_policy))
    iam.put_user_policy (UserName = username, PolicyName = "AdminFullAccess", PolicyDocument = json.dumps(admin_wildcard_policy))
    
    #Create Access Keys
    response = iam.create_access_key(UserName=username)
    key_id = response['AccessKey']['AccessKeyId']
    
    # Access Moto's internal storage backend
    account_id = "123456789012"
    backend = iam_backends[account_id]["global"]
    
    # Find the specific user and their key list in memory
    user = backend.users[username]
    for key in user.access_keys:
        if key.access_key_id == key_id:
            # Backdate the key's creation and usage history to 120 days ago
            past_date = datetime.datetime.now(tzutc()) - datetime.timedelta(days=120)
            key.create_date = past_date
            key.last_used_date = past_date
    
    
    
    #No MFA device activated
    
    #Credentials for S3 and IAM services.
    manifest_data = {
        "username": username,
        "bucket_name": bucket_name,
        "policy_name": "AdminFullAccess",
        "mfa_expected": False
    }
    
    # Dump credentials for S3 and IAM services into a json file
    with open(manifest_path, "w") as f:
        json.dump(manifest_data, f, indent=4)
        
    return manifest_path
    


#Pass test cases for S3 and IAM (Private bucket, HTTP enforced, Restricted permissions, Versioning enabled, non-expired access keys, MFA device)    
def configuration_creation_pass(username, bucket_name, manifest_path="manifest.json"):
    
    iam = boto3.client('iam')
    s3 = boto3.client('s3')
    
    
    iam.create_user(UserName = username)
    s3.create_bucket(Bucket = bucket_name)
    
    
    #Make bucket private
    s3.put_public_access_block(Bucket = bucket_name,
    PublicAccessBlockConfiguration = {
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True}
        )
        
    config_data = {"status":"active", "environment":"testing"}
    s3.put_object(Bucket = bucket_name, Key = "config.json", Body = json.dumps(config_data))
        
        
    # HTTPS Enforced    
    secure_s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnforceHTTPSOnly",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}
            }
        ]
    }
    
    #Restricted permissions 
    admin_restricted_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "LimitedReadAccess",
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:GetObject"],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"]
        }]
    }
    
    
    s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'Status': 'Enabled'})
    s3.put_bucket_policy (Bucket = bucket_name,Policy = json.dumps(secure_s3_policy))
    iam.put_user_policy (UserName = username, PolicyName = "AdminFullAccess", PolicyDocument = json.dumps(admin_restricted_policy))
    iam.create_access_key(UserName=username)
    
    

    
    
    
    #MFA device activated
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
        "policy_name": "AdminRestrictedAccess",
        "mfa_expected": True
    }
    with open(manifest_path, "w") as f:
        json.dump(manifest_data, f, indent=4)
        
    return manifest_path
    
    
    
    
    

if __name__ == "__main__":
    with mock_aws():
        saved_path_pass = configuration_creation_pass(
            username="mock-username-pass", 
            bucket_name="mock-bucket-pass", 
            manifest_path="my_generated_manifest_pass.json"
        )
        saved_path_fail = configuration_creation(
            username="mock-username-fail", 
            bucket_name="mock-bucket-fail", 
            manifest_path="my_generated_manifest_fail.json"
        )
        print(f"File made: {saved_path_fail}")
        print(f"File made: {saved_path_pass}")
    