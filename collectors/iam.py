"""collectors/iam.py

Reads, for every IAM user: inline policies, attached managed policies,
and MFA devices.
Read-only calls only: list_users, list_user_policies, get_user_policy,
list_attached_user_policies, get_policy, get_policy_version, list_mfa_devices.

Returns {"records": [...], "errors": [...]}

Record shape (one per user). Every field is always present:
    {
        "service": "IAM",
        "resource_id": "<username>",
        "inline_policies": {
            "status": "available" | "failed",
            "value": [{"name": ..., "document": {...}}] or None
        },
        "attached_policies": {
            "status": ...,
            "value": [{"name": ..., "arn": ..., "document": {...}}] or None
        },
        "mfa_devices": {
            "status": ...,
            "value": {"DeviceCount": int} or None
        },
    }

What the statuses mean:
    available - AWS answered, value holds the data. A user with no policies
                or no MFA device is "available" with an empty list or a
                count of 0. IAM list calls never report "missing".
    failed    - we could not find out (denied, throttled, network);
                rules must treat this as incomplete, never as a pass

Notes for the rules:
    - Policy documents are already parsed into dictionaries, so the wildcard
      rule can read "Statement" directly.
    - If any step of reading a user's policies fails, the whole setting is
      "failed", so a half-read list can never look like a pass.
    - Policies a user inherits through groups are not collected.

Error shape (one per failed setting, or one if the user listing fails):
    {"operation": "<api call name>", "resource_id": "<user or None>",
     "message": "<error code only>"}
"""


from botocore.exceptions import BotoCoreError, ClientError
from collectors.common import read_setting, error_code
import json

def list_users(iam):
    user_names = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            user_names.append(user["UserName"])
            
    return user_names

def read_login(iam, username):
    status, value, code = read_setting(
        lambda: iam.get_login_profile(UserName=username),
        missing_codes=("NoSuchEntity",),
    )
    return {"status": status, "value": value, "code": code}
    
def get_access_keys(iam, username):
    access_keys = []
    paginator = iam.get_paginator("list_access_keys")
    for page in paginator.paginate(UserName=username):
        for item in page["AccessKeyMetadata"]:
            key_id = item["AccessKeyId"]
            used = iam.get_access_key_last_used(AccessKeyId=key_id)["AccessKeyLastUsed"]
            last_used = used.get("LastUsedDate")
            access_keys.append({"accesskeyid": key_id[-4:],
                                "status": item["Status"], 
                                "keyused": "Used" if last_used else "Never-Used",
                                "lastuseddate": last_used.isoformat() if last_used else None,
                                "created": item["CreateDate"].isoformat()})
            
    return access_keys

def get_mfa_devices(iam, username):
    count = 0 
    paginator = iam.get_paginator("list_mfa_devices")
    for page in paginator.paginate(UserName=username):
        count += len(page["MFADevices"])
    return{"DeviceCount": count} 
    
    
    
def get_attached_policies(iam, username):
    policies = []
    paginator = iam.get_paginator("list_attached_user_policies")
    for page in paginator.paginate(UserName=username):
        for item in page["AttachedPolicies"]:
            arn = item["PolicyArn"]
            version_id = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            policies.append({"name": item["PolicyName"], "arn": arn,
                             "document": version["PolicyVersion"]["Document"]})
    return policies
    
    
    

def get_inline_policies(iam,username):
    policies = []
    paginator = iam.get_paginator("list_user_policies")
    for page in paginator.paginate(UserName=username):
        for name in page["PolicyNames"]:
            response = iam.get_user_policy(UserName=username, PolicyName=name)
            policies.append({"name": name, "document": response["PolicyDocument"]})
    return policies
    
def get_password_policy(iam):
    pass_policy = iam.get_account_password_policy()["PasswordPolicy"]
    return{"passwordlength": pass_policy.get("MinimumPasswordLength"),
                    "requiresymbols": pass_policy.get("RequireSymbols",False),
                    "requirenumbers": pass_policy.get("RequireNumbers",False),
                    "requireuppercase": pass_policy.get("RequireUppercaseCharacters",False),
                    "requirelowercase": pass_policy.get("RequireLowercaseCharacters",False),
                    "maxage": pass_policy.get("MaxPasswordAge"),
                    "passwordreuse": pass_policy.get("PasswordReusePrevention")
                    }
                    
                    
                    
def get_root_mfa(iam):
    mfa = iam.get_account_summary()["SummaryMap"]
    return{"mfaenablend": mfa.get("AccountMFAEnabled", 0)}

def read_root_mfa(iam):
    status, value, code = read_setting(lambda: get_root_mfa(iam))
    return {"status": status, "value": value, "code": code}
    
def read_password_policy(iam):
    status, value, code = read_setting(lambda: get_password_policy(iam), missing_codes=("NoSuchEntity",))
    return {"status": status, "value": value, "code": code}
    
    
def read_inline_policies(iam, username):
    status, value, code = read_setting(lambda: get_inline_policies(iam, username))
    return {"status": status, "value": value, "code": code}


def read_attached_policies(iam, username):
    status, value, code = read_setting(lambda: get_attached_policies(iam, username))
    return {"status": status, "value": value, "code": code}


def read_mfa_devices(iam, username):
    status, value, code = read_setting(lambda: get_mfa_devices(iam, username))
    return {"status": status, "value": value, "code": code}
    
def read_access_keys(iam, username):
    status, value, code = read_setting(lambda: get_access_keys(iam, username))
    return {"status": status, "value": value, "code": code}

    
    
SETTINGS = [
    ("inline_policies", read_inline_policies, "get_user_policy"),
    ("attached_policies", read_attached_policies, "get_policy_version"),
    ("mfa_devices", read_mfa_devices, "list_mfa_devices"),
    ("access_keys", read_access_keys, "get_access_key_last_used"),
]


        
    
def collect_iam(aws_session):
    iam = aws_session.client("iam")
    records, errors = [], []
    
    mfa_setting = read_root_mfa(iam)
    records.append({"service": "IAM",
        "resource_id": "RootMFA",
        "root_mfa": {
            "status": mfa_setting["status"],
            "value": mfa_setting["value"]}
    })
    
    if mfa_setting["status"] == "failed":
        errors.append({
            "operation": "get_account_summary",
            "resource_id": None,
            "message": mfa_setting["code"]
        })
    
    pw_setting = read_password_policy(iam)
    records.append({"service": "IAM",
        "resource_id": "AccountPasswordPolicy",
        "password_policy": {
            "status": pw_setting["status"],
            "value": pw_setting["value"]}
    })
    
    if pw_setting["status"] == "failed":
        errors.append({
            "operation": "get_account_password_policy",
            "resource_id": None,
            "message": pw_setting["code"]
        })
    
    try:
        usernames = list_users(iam)
    except (BotoCoreError, ClientError) as e:
        errors.append(
            {"operation": "list_users", "resource_id": None,
             "message": error_code(e)})
        return {"records": records, "errors": errors}
            
             
             
    for us in usernames:
        record = {"service": "IAM", "resource_id": us}
        
        for field, helper, operation in SETTINGS:
            setting = helper(iam, us)
            record[field] = {"status": setting["status"], "value": setting["value"]}

            # only this function records errors; the helpers just report status
            if setting["status"] == "failed":
                errors.append({"operation": operation, "resource_id": us,
                               "message": setting["code"]})
        records.append(record)


    return {"records": records, "errors": errors}


