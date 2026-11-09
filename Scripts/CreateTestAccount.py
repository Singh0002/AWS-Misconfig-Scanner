"""Builds and removes the known-good and known-bad resources in the AWS TEST account
(E-7 S-1-6, E-8 S-14-3, E-6 S-13-1).

Run it with an ADMIN profile of a throwaway test account. Never use the read-only
scanner profile, and never run it against a real account.

    set AWS_PROFILE=cg-admin                                  (Windows cmd)
    export AWS_PROFILE=cg-admin                               (Ubuntu)

    python scripts/create_test_account.py create [--open-account-block]
    python scripts/create_test_account.py password weak       (8 characters, should fail)
    python scripts/create_test_account.py password strong     (14 characters, should pass)
    python scripts/create_test_account.py cleanup

What "create" makes (10 buckets and 9 users; the scanner user is the 10th):
    bucket public-acl   ACL grants All Users READ              -> s3_public_acl fails
    bucket wildcard     policy allows * with no condition      -> s3_wildcard_principal fails
    bucket suspended    versioning suspended, otherwise secure -> s3_versioning fails
    bucket nopolicy     secure, but no bucket policy           -> s3_https_only fails
    buckets secure-1..6 everything secure                      -> all five S3 rules pass
    user admin          AdministratorAccess                    -> iam_admin_wildcard fails
    users nomfa, 1..7   limited read policy, no MFA            -> iam_user_mfa fails

Not done by this script (do by hand):
    - Root MFA: turn it on in the console to test the Pass case.
    - A user WITH an MFA device: enable a virtual MFA app on one user (real codes are needed).
    - An access key older than 90 days: a new account can't have one. Say so in the test record.
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError

PREFIX = "cg-test"
REGION = "us-east-1"
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
BLOCK_ON = {"BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
BLOCK_OFF = {flag: False for flag in BLOCK_ON}
LIMITED = {"Version": "2012-10-17",
           "Statement": [{"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetObject"], "Resource": "*"}]}
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
USER_NAMES = [PREFIX + "-admin", PREFIX + "-nomfa"] + [f"{PREFIX}-user-{n}" for n in range(1, 8)]


def https_policy(bucket):
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "HttpsOnly", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}


def public_policy(bucket):
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
        "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}]}


def new_bucket(s3, name, acls=False):
    args = {"Bucket": name}
    if acls:
        # new buckets turn ACLs off by default, so this lets the ACL case exist
        args["ObjectOwnership"] = "BucketOwnerPreferred"
    try:
        s3.create_bucket(**args)
    except ClientError as error:
        if error.response["Error"]["Code"] != "BucketAlreadyOwnedByYou":
            raise


def make_secure(s3, name, versioning="Enabled", policy=True):
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=BLOCK_ON)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    if versioning == "Suspended":
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Suspended"})
    if policy:
        s3.put_bucket_policy(Bucket=name, Policy=json_text(https_policy(name)))


def json_text(value):
    import json
    return json.dumps(value)


def create_buckets(s3, account):
    base = f"{PREFIX}-{account}-"
    name = base + "public-acl"
    new_bucket(s3, name, acls=True)
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=BLOCK_OFF)
    s3.put_bucket_acl(Bucket=name, GrantRead=f"uri={ALL_USERS}")

    name = base + "wildcard"
    new_bucket(s3, name)
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=BLOCK_OFF)
    s3.put_bucket_policy(Bucket=name, Policy=json_text(public_policy(name)))

    name = base + "suspended"
    new_bucket(s3, name)
    make_secure(s3, name, versioning="Suspended")

    name = base + "nopolicy"
    new_bucket(s3, name)
    make_secure(s3, name, policy=False)

    for number in range(1, 7):
        name = f"{base}secure-{number}"
        new_bucket(s3, name)
        make_secure(s3, name)
    print("Buckets ready (10).")


def create_users(iam):
    for name in USER_NAMES:
        try:
            iam.create_user(UserName=name)
        except ClientError as error:
            if error.response["Error"]["Code"] != "EntityAlreadyExists":
                raise
        if name.endswith("-admin"):
            iam.attach_user_policy(UserName=name, PolicyArn=ADMIN_ARN)
        else:
            iam.put_user_policy(UserName=name, PolicyName="Limited", PolicyDocument=json_text(LIMITED))
        if not iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            # the secret is thrown away on purpose; the key only has to exist
            iam.create_access_key(UserName=name)
    print(f"Users ready ({len(USER_NAMES)}). The scanner user makes the 10th.")


def set_password_policy(iam, kind):
    if kind == "weak":
        iam.update_account_password_policy(MinimumPasswordLength=8)
    else:
        iam.update_account_password_policy(
            MinimumPasswordLength=14, RequireSymbols=True, RequireNumbers=True,
            RequireUppercaseCharacters=True, RequireLowercaseCharacters=True)
    print("Password policy set to " + kind + ".")


def cleanup(session, account):
    s3, iam = session.client("s3"), session.client("iam")
    for bucket in s3.list_buckets()["Buckets"]:
        if bucket["Name"].startswith(f"{PREFIX}-{account}-"):
            handle = session.resource("s3").Bucket(bucket["Name"])
            handle.object_versions.delete()
            handle.delete()
            print("Deleted bucket " + bucket["Name"])
    for name in USER_NAMES:
        try:
            for policy in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]:
                iam.detach_user_policy(UserName=name, PolicyArn=policy["PolicyArn"])
            for policy_name in iam.list_user_policies(UserName=name)["PolicyNames"]:
                iam.delete_user_policy(UserName=name, PolicyName=policy_name)
            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
            for device in iam.list_mfa_devices(UserName=name)["MFADevices"]:
                iam.deactivate_mfa_device(UserName=name, SerialNumber=device["SerialNumber"])
                iam.delete_virtual_mfa_device(SerialNumber=device["SerialNumber"])
            iam.delete_user(UserName=name)
            print("Deleted user " + name)
        except ClientError as error:
            if error.response["Error"]["Code"] != "NoSuchEntity":
                raise
    # put the account-wide setting back the way a real account should have it
    session.client("s3control").put_public_access_block(
        AccountId=account, PublicAccessBlockConfiguration=BLOCK_ON)
    print("Account-wide Block Public Access is back on.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["create", "password", "cleanup"])
    parser.add_argument("kind", nargs="?", choices=["weak", "strong"])
    parser.add_argument("--open-account-block", action="store_true",
                        help="turn OFF account-wide Block Public Access (test account only)")
    args = parser.parse_args()

    session = boto3.Session(region_name=REGION)
    who = session.client("sts").get_caller_identity()
    account = who["Account"]
    if "scanner" in who["Arn"]:
        sys.exit("That is the read-only scanner profile. Use the admin profile.")
    print("Account " + account + " as " + who["Arn"])
    if input("Type the account ID to confirm this is the TEST account: ").strip() != account:
        sys.exit("Not confirmed. Nothing was changed.")

    if args.action == "create":
        if args.open_account_block:
            session.client("s3control").delete_public_access_block(AccountId=account)
            print("Account-wide Block Public Access is OFF. Run 'cleanup' when you are done.")
        create_buckets(session.client("s3"), account)
        create_users(session.client("iam"))
    elif args.action == "password":
        if not args.kind:
            sys.exit("Say weak or strong.")
        set_password_policy(session.client("iam"), args.kind)
    else:
        cleanup(session, account)


if __name__ == "__main__":
    main()
