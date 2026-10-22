import results
import os
import json
import csv
import io
from datetime import datetime, timezone
import boto3
from dateutil.tz import tzutc
from botocore.exceptions import ClientError, NoCredentialsError
import results

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
    
    
def old_run_scan(manifest_path="manifest.json"):
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




RULE_MAP = {  # your key -> (service, rule_id, issue, severity)
    "public_acl_grant":           ("S3", "s3_public_acl", "Bucket ACL grants public access", "High"),
    "block_public_access_off":    ("S3", "s3_block_public_access", "Block Public Access is not fully on", "High"),
    "wildcard_principal_detected":("S3", "s3_wildcard_principal", "Bucket policy allows any principal", "High"),
    "versioning_disabled":        ("S3", "s3_versioning", "Versioning is not enabled", "Medium"),
    "https_not_enforced":         ("S3", "s3_https_only", "HTTPS is not enforced", "Medium"),
    "admin_wildcard_detected":    ("IAM", "iam_admin_wildcard", "Policy grants admin wildcards", "High"),
    "user_without_mfa":           ("IAM", "iam_user_mfa", "User has no MFA device", "High"),
    "access_key_unused_90_days":  ("IAM", "iam_unused_access_key", "Access key unused 90+ days", "Medium"),
}
STATUS = {"PASS": "pass", "FAIL": "fail"}  # anything else -> incomplete


# run_scan connected to app.py 
def run_scan(selected_services, selected_rules, on_progress, manifest_path="manifest.json"):
    
    
    scan = results.new_scan(selected_services)
    scan_id = scan["metadata"]["scan_id"]
    report = old_run_scan(manifest_path)    # uses previous testing scan data for new run_scan function for scanner on app.py
    
    
    if report.get("status") != "COMPLETED":
        raise RuntimeError(report.get("message", "Scan failed"))    
        
    resources = report["target_resources"]
    items = [(k, v) for k, v in report["results"].items()
             if k in RULE_MAP and RULE_MAP[k][1] in selected_rules and RULE_MAP[k][0] in selected_services]
             
             
    for i, (key, value) in enumerate(items, 1):
        service, rule_id, issue, severity = RULE_MAP[key]
        resource = resources["bucket"] if service == "S3" else resources["user"]
        on_progress(i, len(items), f"Checking {rule_id}")
        status = STATUS.get(value, "incomplete")
        check = results.make_check(scan_id, service, resource, rule_id, status,
                                   reason=None if status != "incomplete" else "Check could not complete.")
        scan["checks"].append(check)
        if status == "fail":
            finding = results.make_finding(check, issue, severity)
            scan["findings"].append(finding)
            scan["explanations"].append(results.make_explanation(finding["finding_id"], "pending"))
    scan["metadata"]["scan_status"] = "completed"
    return scan
    