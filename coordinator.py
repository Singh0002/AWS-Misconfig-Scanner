import os
import json
import csv
import io
from datetime import datetime, timezone
import boto3
from dateutil.tz import tzutc

# Check 5 s3 configurations wildcard principal, acl, public access off, versioning disabled, https not enforced
def check_s3_configs(s3, bucket_name):
    findings = {
        "public_acl_grant": "PASS", #*
        "block_public_access_off": "PASS", #*
        "wildcard_principal_detected": "PASS",
        "versioning_disabled": "PASS", #*
        "https_not_enforced": "FAIL" # Default fallback state
    }
    
    try:
        
        acl = s3.get_bucket_acl(Bucket = bucket_name)
        grants = acl.get('Grants',[])
        for grantees in grants: 
            if grantees.get('Grantee',{}).get('URI',[]) == 'http://amazonaws.com':
                findings["public_acl_grant"] = "FAIL"
    except Exception:
        findings["public_acl_grant"] = "ERROR"

     
    try:
        
        bucket_versioning = s3.get_bucket_versioning(Bucket = bucket_name)
        status = bucket_versioning.get('Status',[])
        if status != 'Enabled':
            findings["versioning_disabled"] = "FAIL"
    except Exception:
        findings["versioning_disabled"] = "ERROR"        
            
    
    try:
        bucket_policy = s3.get_bucket_policy(Bucket = bucket_name)
        statements = json.loads(bucket_policy['Policy']).get('Statement', [])
        
        for s in statements:
            if s.get("Principal") == "*":
                if s.get("Effect") == "Deny":
                    
                    condition = s.get("Condition",{})
                    https_check = condition.get("Bool",{}).get("aws:SecureTransport")
                    
                    if https_check in [False,"false"]:
                        findings["https_not_enforced"] = "PASS"
                        break
                
                elif s.get("Effect") == "Allow":
                    principal = s.get("Principal")
                    
                    if principal == "*":
                        findings["wildcard_principal_detected"] = "FAIL"
                        
                        
                   
        
    except ClientError as e:
        # If the bucket has no policy at all, it's failing HTTPS enforcement
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            findings["https_not_enforced"] = "FAIL"
            findings["wildcard_principal_detected"] = "FAIL"
        else:
            findings["https_not_enforced"] = "ERROR_CHECKING"
            
            

    
    try:  
        pab = s3.get_public_access_block(Bucket = bucket_name)
        configs = pab.get('PublicAccessBlockConfiguration',{})
        if not configs.get('BlockPublicAcls') or not configs.get('BlockPublicPolicy'):
            findings["block_public_access_off"] = "FAIL"
    
    
    except Exception:
        findings["block_public_access_off"] = "FAIL"
        
    
    return findings
     
def check_iam_configs(iam, username, policy_name):
    
    MAX_UNUSED_DAYS = 90
    now = datetime.now(timezone.utc)
    
    """Scans all requested IAM rules for a given target user context."""
    findings = {
        "admin_wildcard_detected": "PASS",
        "user_without_mfa": "FAIL",
        "access_key_unused_90_days": "PASS"
    }
    
    try:
        mfa = iam.list_mfa_devices(UserName = username)
        mfa_devices = mfa.get("MFADevices",[])
    
        if mfa_devices:            
            findings["user_without_mfa"] = "PASS"

    except Exception:
        findings["user_without_mfa"] = "ERROR"  

    
    try: 
        policy_r = iam.get_user_policy(UserName=username, PolicyName=policy_name)
        doc = policy_r['PolicyDocument']
        if isinstance(doc, str):
            doc = json.loads(doc)
        statements = doc.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for s in statements:
            if s.get("Effect") == "Allow" and s.get("Action") == "*" and s.get("Resource") == "*":
                findings["admin_wildcard_detected"] = "FAIL" 
                
    except Exception:
        findings["admin_wildcard_detected"] = "ERROR"      

    
    try:
        access_keys_list = iam.list_access_keys(UserName = username)
        key_data = access_keys_list.get('AccessKeyMetadata',[])

        
        for keys in key_data:
            create_date = keys['CreateDate']
            response = iam.get_access_key_last_used(AccessKeyId = keys.get('AccessKeyId'))
            last_used = response.get('AccessKeyLastUsed',{})
            date = last_used.get('LastUsedDate')
            
            if date:
                days_unused = (now - date).days
            else:
                days_unused = (now - create_date).days
            
            if days_unused > MAX_UNUSED_DAYS:
                findings["access_key_unused_90_days"] = "FAIL" 
                break
    except Exception:
        findings["inactive_access_keys"] = "ERROR_CHECKING"
        
        
    return findings
    
    
def run_scan(manifest_path="manifest.json"):
    if not os.path.exists(manifest_path):
        return {"status": "ERROR", "message": f"Manifest tracking file missing: {manifest_path}"}

    with open(manifest_path, "r") as f:
        meta = json.load(f)
    
    s3 = boto3.client('s3')
    iam = boto3.client('iam')
    
    username = meta.get("username")
    policy_name = meta.get("policy_name")
    bucket_name = meta.get("bucket_name")
    
    s3_reports = check_s3_configs(s3, bucket_name)
    iam_reports = check_iam_configs(iam, username, policy_name)
    
    combined_results = {**s3_reports, **iam_reports}
    
    return {
        "status": "COMPLETED",
        "scan_timestamp": str(datetime.now()),
        "target_resources": {"user": username, "bucket": bucket_name},
        "results": combined_results
    }
    