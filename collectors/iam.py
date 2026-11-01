"""collectors/iam.py

Reads, for every IAM user: inline policies, attached managed policies,
MFA devices and access keys. Also reads the account password policy once.
Read-only calls only: list_users, list_user_policies, get_user_policy,
list_attached_user_policies, get_policy, get_policy_version, list_mfa_devices,
list_access_keys, get_access_key_last_used, get_account_password_policy.

Returns {"records": [...], "errors": [...], "password_policy": {...}}

The password policy is for the whole account, so it's kept out of the user
records:
    "password_policy": {
        "status": "available" | "missing" | "failed",
        "value": <get_account_password_policy()["PasswordPolicy"]> or None
    }
"missing" means the account has no password policy at all.

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
        "access_keys": {
            "status": ...,
            "value": [{"AccessKeyId": <last 4 characters>, "Status": "Active" | "Inactive",
                       "CreateDate": <datetime>, "LastUsedDate": <datetime> or None}] or None
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
    - Field names and dates are kept as AWS returns them, because the rules
      in detection/iam_rules.py read those names and count days between dates.
    - Only the last 4 characters of an access key ID are kept, never the whole ID.

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

    
def get_access_keys(iam, username):
    access_keys = []
    paginator = iam.get_paginator("list_access_keys")
    for page in paginator.paginate(UserName=username):
        for item in page["AccessKeyMetadata"]:
            key_id = item["AccessKeyId"]
            used = iam.get_access_key_last_used(AccessKeyId=key_id)["AccessKeyLastUsed"]
            last_used = used.get("LastUsedDate")
            # AWS names and real dates, so the unused key rule can count days
            access_keys.append({"AccessKeyId": key_id[-4:],
                                "Status": item["Status"],
                                "CreateDate": item["CreateDate"],
                                "LastUsedDate": last_used})
            
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
    # kept as AWS returns it (MinimumPasswordLength, RequireSymbols, ...)
    return iam.get_account_password_policy()["PasswordPolicy"]


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
    
    pw_setting = read_password_policy(iam)
    if pw_setting["status"] == "failed":
        errors.append({"operation": "get_account_password_policy",
                       "resource_id": None, "message": pw_setting["code"]})
    password_policy = {"status": pw_setting["status"], "value": pw_setting["value"]}

    
    try:
        usernames = list_users(iam)
    except (BotoCoreError, ClientError) as e:
        errors.append(
            {"operation": "list_users", "resource_id": None,
             "message": error_code(e)})
        return {"records": [], "errors": errors, "password_policy": password_policy}
            
             
             
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


    return {"records": records, "errors": errors, "password_policy": password_policy}
