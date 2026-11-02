"""Fake AWS, fake Anthropic and sample scans shared by the tests (design doc 5.1).

Nothing here talks to the internet. FakeAWS is a pretend account that only
answers read calls (get_ and list_). Any other call, like put_bucket_policy,
fails the test right away, so we'd know if the scanner ever tried to change
something in AWS.
"""

import itertools
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from botocore.exceptions import ClientError

import results

ACCOUNT_ID = "123456789012"
# made up, but shaped like a real AWS secret so the leak checks mean something
DUMMY_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYDUMMYSECRET"

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
PRIVATE_ACL = [{"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"}]
PUBLIC_ACL = [{"Grantee": {"Type": "Group", "URI": ALL_USERS}, "Permission": "READ"}]
BLOCK_ALL = {"BlockPublicAcls": True, "IgnorePublicAcls": True,
             "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
STRONG_PASSWORDS = {"MinimumPasswordLength": 14, "RequireUppercaseCharacters": True,
                    "RequireLowercaseCharacters": True, "RequireNumbers": True, "RequireSymbols": True}
ADMIN_POLICY = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
READ_ONLY_POLICY = {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}


def days_ago(days):
    return datetime.now(timezone.utc) - timedelta(days=days)


def https_policy(name):
    """A bucket policy that blocks plain HTTP."""
    return {"Statement": [{"Sid": "HttpsOnly", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                           "Resource": ["arn:aws:s3:::" + name, "arn:aws:s3:::" + name + "/*"],
                           "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}


def public_policy(name):
    """A bucket policy that lets anyone download files, with no condition."""
    return {"Statement": [{"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
                           "Action": "s3:GetObject", "Resource": "arn:aws:s3:::" + name + "/*"}]}


def good_bucket(name):
    """Passes all 5 S3 rules."""
    return {"name": name, "acl": PRIVATE_ACL, "block": BLOCK_ALL, "versioning": "Enabled",
            "policy": https_policy(name)}


def bad_bucket(name):
    """Fails all 5 S3 rules."""
    return {"name": name, "acl": PUBLIC_ACL, "block": None, "versioning": None,
            "policy": public_policy(name)}


# every fake key gets its own whole ID, shaped like a real one (AKIA + 16)
KEY_NUMBERS = itertools.count(1)


def access_key(status="Active", created=400, last_used=5):
    """last_used=None means AWS has no record of the key being used."""
    key_id = "AKIA" + str(next(KEY_NUMBERS)).zfill(16)
    return {"AccessKeyId": key_id, "Status": status, "CreateDate": days_ago(created),
            "LastUsedDate": days_ago(last_used) if last_used is not None else None}


def good_user(name):
    """Passes the 3 per-user IAM rules."""
    return {"name": name, "inline": [], "attached": [("ReadOnly", READ_ONLY_POLICY)],
            "mfa": 1, "keys": [access_key()]}


def bad_user(name):
    """Fails the 3 per-user IAM rules."""
    return {"name": name, "inline": [("Everything", ADMIN_POLICY)], "attached": [],
            "mfa": 0, "keys": [access_key(last_used=120)]}


class FakeAWS:
    """A pretend AWS account for every client (sts, s3, s3control, iam).

    fail maps a call name, or (call name, bucket or user), to an error code
    like "AccessDenied" or to an exception to raise instead.
    page_size is how many items each page of a list holds, so small numbers
    test that every page gets read.
    """

    def __init__(self, buckets=(), users=(), password_policy=STRONG_PASSWORDS, root_mfa=1,
                 fail=None, page_size=1):
        self.buckets = {b["name"]: b for b in buckets}
        self.users = {u["name"]: u for u in users}
        self.password_policy = password_policy
        self.root_mfa = root_mfa
        self.fail = fail or {}
        self.page_size = page_size
        self.calls = []

    def __getattr__(self, name):
        # only reached for calls we didn't write below, which are never read calls
        raise AssertionError("The scanner tried to call " + name + ", which isn't a read-only call.")

    def call(self, name, resource=None):
        self.calls.append(name)
        error = self.fail.get((name, resource), self.fail.get(name))
        if isinstance(error, str):
            raise ClientError({"Error": {"Code": error, "Message": "details " + DUMMY_SECRET}}, name)
        if error is not None:
            raise error

    def pages(self, name, items, resource=None):
        self.call(name, resource)
        size = self.page_size
        return [items[i:i + size] for i in range(0, len(items), size)] or [[]]

    def get_paginator(self, name):
        return SimpleNamespace(paginate=lambda **kwargs: self.paginate(name, kwargs.get("UserName")))

    def paginate(self, name, user_name):
        user = self.users.get(user_name)
        if name == "list_buckets":
            return [{"Buckets": [{"Name": n} for n in page]} for page in self.pages(name, list(self.buckets))]
        if name == "list_users":
            return [{"Users": [{"UserName": n} for n in page]} for page in self.pages(name, list(self.users))]
        if name == "list_user_policies":
            names = [p[0] for p in user["inline"]]
            return [{"PolicyNames": page} for page in self.pages(name, names, user_name)]
        if name == "list_attached_user_policies":
            attached = [{"PolicyName": p[0], "PolicyArn": "arn:aws:iam::aws:policy/" + p[0]} for p in user["attached"]]
            return [{"AttachedPolicies": page} for page in self.pages(name, attached, user_name)]
        if name == "list_mfa_devices":
            devices = [{"SerialNumber": "device"}] * user["mfa"]
            return [{"MFADevices": page} for page in self.pages(name, devices, user_name)]
        if name == "list_access_keys":
            keys = [{k: key[k] for k in ("AccessKeyId", "Status", "CreateDate")} for key in user["keys"]]
            return [{"AccessKeyMetadata": page} for page in self.pages(name, keys, user_name)]
        raise AssertionError("No fake paginator for " + name)

    # the setup checks in test_connection.py call these directly, not through a paginator
    def list_buckets(self):
        self.call("list_buckets")
        return {"Buckets": [{"Name": n} for n in self.buckets]}

    def list_users(self, MaxItems=None):
        self.call("list_users")
        return {"Users": [{"UserName": n} for n in list(self.users)[:MaxItems]]}

    # sts
    def get_caller_identity(self):
        self.call("get_caller_identity")
        return {"Account": ACCOUNT_ID}

    # s3 and s3control
    def get_bucket_acl(self, Bucket):
        self.call("get_bucket_acl", Bucket)
        return {"Owner": {"ID": "owner"}, "Grants": self.buckets[Bucket]["acl"]}

    def get_public_access_block(self, Bucket=None, AccountId=None):
        if AccountId:
            # the account-wide setting, which these tests leave off
            self.call("get_account_public_access_block")
            raise ClientError({"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}, "get_public_access_block")
        self.call("get_public_access_block", Bucket)
        if self.buckets[Bucket]["block"] is None:
            raise ClientError({"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}, "get_public_access_block")
        return {"PublicAccessBlockConfiguration": self.buckets[Bucket]["block"]}

    def get_bucket_versioning(self, Bucket):
        self.call("get_bucket_versioning", Bucket)
        status = self.buckets[Bucket]["versioning"]
        return {"Status": status} if status else {}

    def get_bucket_policy(self, Bucket):
        self.call("get_bucket_policy", Bucket)
        if self.buckets[Bucket]["policy"] is None:
            raise ClientError({"Error": {"Code": "NoSuchBucketPolicy"}}, "get_bucket_policy")
        return {"Policy": json.dumps(self.buckets[Bucket]["policy"])}

    # iam
    def get_account_summary(self):
        self.call("get_account_summary")
        return {"SummaryMap": {"AccountMFAEnabled": self.root_mfa}}

    def get_account_password_policy(self):
        self.call("get_account_password_policy")
        if self.password_policy is None:
            raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "get_account_password_policy")
        return {"PasswordPolicy": self.password_policy}

    def get_user_policy(self, UserName, PolicyName):
        self.call("get_user_policy", UserName)
        return {"PolicyDocument": dict(self.users[UserName]["inline"])[PolicyName]}

    def get_policy(self, PolicyArn):
        self.call("get_policy")
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        self.call("get_policy_version")
        for user in self.users.values():
            for name, document in user["attached"]:
                if PolicyArn.endswith("/" + name):
                    return {"PolicyVersion": {"Document": document}}

    def get_access_key_last_used(self, AccessKeyId):
        self.call("get_access_key_last_used")
        for user in self.users.values():
            for key in user["keys"]:
                if key["AccessKeyId"] == AccessKeyId:
                    used = {"LastUsedDate": key["LastUsedDate"]} if key["LastUsedDate"] else {}
                    return {"AccessKeyLastUsed": used}


class FakeSession:
    """Stands in for a boto3 session. Every client is the same FakeAWS."""

    def __init__(self, aws):
        self.aws = aws

    def client(self, name):
        return self.aws


def good_reply(request):
    """Explains every finding it was sent, the way a working AI would."""
    batch = json.loads(request["messages"][0]["content"])
    return json.dumps({"explanations": [
        {"finding_id": f["finding_id"], "risk_explanation": "Anyone could get in.",
         "recommended_steps": ["Open the AWS console", "Turn the setting on"]} for f in batch]})


class FakeAI:
    """Stands in for anthropic.Anthropic. reply is text, or a function of the request."""

    def __init__(self, reply=good_reply, error=None, stop_reason="end_turn"):
        self.reply, self.error, self.stop_reason = reply, error, stop_reason
        self.requests = []
        self.messages = self

    def create(self, **request):
        self.requests.append(request)
        if self.error:
            raise self.error
        text = self.reply(request) if callable(self.reply) else self.reply
        return SimpleNamespace(stop_reason=self.stop_reason,
                               content=[SimpleNamespace(type="text", text=text)])


def sample_scan(resource="public-bucket", explanation_text="Anyone on the internet can read it."):
    """A small saved-style scan: 2 findings, 1 pass, 1 incomplete, 1 error, 1 explanation."""
    scan = results.new_scan(["S3", "IAM"], ACCOUNT_ID)
    scan_id = scan["metadata"]["scan_id"]
    acl = results.make_check(scan_id, "S3", resource, "s3_public_acl", "fail",
                             {"public_grants": [{"group": "All Users", "permission": "READ"}]})
    mfa = results.make_check(scan_id, "IAM", "alice", "iam_user_mfa", "fail", {"mfa_devices": 0})
    versioning = results.make_check(scan_id, "S3", resource, "s3_versioning", "pass")
    policy = results.make_check(scan_id, "S3", resource, "s3_https_only", "incomplete",
                                reason="Couldn't read the bucket policy (AccessDenied).")
    scan["checks"] = [acl, mfa, versioning, policy]
    scan["findings"] = [results.make_finding(acl, "Bucket ACL grants access to everyone", "High"),
                        results.make_finding(mfa, "User has no MFA device", "High")]
    scan["explanations"] = [
        results.make_explanation(scan["findings"][0]["finding_id"], "available", explanation_text,
                                 ["Remove the All Users grant"]),
        results.make_explanation(scan["findings"][1]["finding_id"], "unavailable")]
    scan["errors"] = [results.make_error(scan_id, "collection", "get_bucket_policy", "AccessDenied", resource)]
    scan["metadata"]["scan_status"] = "completed"
    scan["metadata"]["coverage_status"] = "incomplete"
    return scan
