from botocore.exceptions import BotoCoreError, ClientError
from collectors.common import read_setting, error_code
import json


"""Reads bucket ACLs, public access settings, versioning, and policies.
Returns records and errors without changing AWS settings."""

def list_buckets(s3):
    bucket_names = []
    for page in s3.get_paginator("list_buckets").paginate():
        for b in page["Buckets"]:
            bucket_names.append(b["Name"])
            
    return bucket_names
    
    
    
def read_acl(s3, bucket_name):
    status, value, code = read_setting(
        lambda: s3.get_bucket_acl(Bucket=bucket_name))
    
    if status == "available":
        value = {"Owner": value.get("Owner"), "Grants": value.get("Grants", [])}
        
    return {"status": status, "value": value, "code": code}


def read_public_access_block(s3, bucket_name):
    status, value, code = read_setting(
        lambda: s3.get_public_access_block(Bucket=bucket_name), 
        missing_codes=("NoSuchPublicAccessBlockConfiguration",))
    
    if status == "available":
        value = value.get("PublicAccessBlockConfiguration", {})
        
    return {"status": status, "value": value, "code": code}
    
def read_policy(s3, bucket_name):
    status, value, code = read_setting(
        lambda: s3.get_bucket_policy(Bucket=bucket_name), 
        missing_codes=("NoSuchBucketPolicy",))
    
    if status == "available":
        try:
            value = json.loads(value["Policy"])
        except (KeyError, TypeError, ValueError):
            return {"status": "failed", "value": None, "code": "InvalidPolicyJSON"}
            
            
    return {"status": status, "value": value, "code": code}

def read_versioning(s3, bucket_name):
    status, value, code = read_setting(
        lambda: s3.get_bucket_versioning(Bucket=bucket_name))
    if status == "available":
        value = {"Status": value.get("Status")}
        
    return {"status": status, "value": value, "code": code}    


SETTINGS = [
    ("acl", read_acl, "get_bucket_acl"),
    ("public_access_block", read_public_access_block, "get_public_access_block"),
    ("versioning", read_versioning, "get_bucket_versioning"),
    ("policy", read_policy, "get_bucket_policy"),
]

    
def collect_s3(aws_session):
    s3 = aws_session.client("s3")
    records, errors = [], []
    
    try:
        bucket_names = list_buckets(s3)
    except (BotoCoreError, ClientError) as e:
        return {"records": [], "errors": [
            {"operation": "list_buckets", "resource_id": None,
             "message": error_code(e)}]}
             
             
    for bn in bucket_names:
        record = {"service": "S3", "resource_id": bn}
        
        for field, helper, operation in SETTINGS:
            setting = helper(s3, bn)
            record[field] = {"status": setting["status"], "value": setting["value"]}

            # only this function records errors,, the helpers just report status
            if setting["status"] == "failed":
                errors.append({"operation": operation, "resource_id": bn,
                               "message": setting["code"]})
        records.append(record)


    return {"records": records, "errors": errors}
