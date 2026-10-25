"""The five S3 rules (E-2 S-3-2, S-3-3, S-3-4, S-4-2, S-4-3).

Each rule looks at the settings for one bucket and returns a result dict:

    {"rule_id": "s3_versioning", "resource_id": "my-bucket",
     "status": "pass" | "fail" | "incomplete",
     "evidence": {...},   # what the rule saw, small and secret-free
     "reason": None}      # why the check is incomplete, otherwise None

The rules only decide pass/fail. Turning a result into a check and finding
(results.make_check / make_finding) happens after this, using RULE_INFO for
the issue text and severity.

The bucket dict the collector should pass in:

    {
        "name": "my-bucket",
        "acl": <get_bucket_acl response>,
        "public_access_block": <PublicAccessBlockConfiguration> or None if not set,
        "policy": <bucket policy as a dict or JSON string> or None if not set,
        "versioning": <get_bucket_versioning response>,
        "errors": {"policy": "AccessDenied", ...},  # settings that couldn't be read
    }

A setting listed in "errors" makes the rules that need it incomplete, never
pass. A setting that is None means AWS said it isn't set, which is different
from not being able to read it.
"""

from detection.policy import as_list, has_condition, is_public_principal, statements

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
PUBLIC_GROUPS = {ALL_USERS: "All Users", AUTHENTICATED_USERS: "Authenticated Users"}

BLOCK_PUBLIC_ACCESS_FLAGS = ["BlockPublicAcls", "IgnorePublicAcls",
                             "BlockPublicPolicy", "RestrictPublicBuckets"]

# rule_id -> issue text and severity for the finding
RULE_INFO = {
    "s3_public_acl": ("Bucket ACL grants access to everyone", "High"),
    "s3_block_public_access": ("Block Public Access is not fully turned on", "High"),
    "s3_wildcard_principal": ("Bucket policy allows any principal without a condition", "High"),
    "s3_versioning": ("Versioning is not enabled", "Medium"),
    "s3_https_only": ("Bucket policy does not enforce HTTPS", "Medium"),
}


def make_result(rule_id, bucket, status, evidence=None, reason=None):
    return {
        "rule_id": rule_id,
        "resource_id": bucket["name"],
        "status": status,
        "evidence": evidence or {},
        "reason": reason,
    }


def read_error(rule_id, bucket, setting):
    """The incomplete result for a setting the collector couldn't read."""
    error = bucket.get("errors", {}).get(setting)
    if error is None and setting not in bucket:
        error = "not collected"
    if error is None:
        return None
    return make_result(rule_id, bucket, "incomplete",
                       reason=f"Couldn't read the bucket {setting.replace('_', ' ')} ({error}).")


def check_public_acl(bucket):
    """Rule 1: no ACL grant to All Users or Authenticated Users."""
    incomplete = read_error("s3_public_acl", bucket, "acl")
    if incomplete:
        return incomplete

    public_grants = []
    for grant in (bucket["acl"] or {}).get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("Type") == "Group" and grantee.get("URI") in PUBLIC_GROUPS:
            public_grants.append({"group": PUBLIC_GROUPS[grantee["URI"]],
                                  "permission": grant.get("Permission")})

    if public_grants:
        return make_result("s3_public_acl", bucket, "fail", {"public_grants": public_grants})
    return make_result("s3_public_acl", bucket, "pass")


def check_block_public_access(bucket, account_block=None):
    """Rule 2: all four Block Public Access settings are on.

    account_block is the account-wide setting (s3control
    get_public_access_block). A flag counts as on if either the bucket or the
    account turns it on, because AWS applies whichever is stricter.
    """
    incomplete = read_error("s3_block_public_access", bucket, "public_access_block")
    if incomplete:
        return incomplete

    bucket_block = bucket["public_access_block"] or {}
    account_block = account_block or {}
    flags_off = []
    for flag in BLOCK_PUBLIC_ACCESS_FLAGS:
        if not (bucket_block.get(flag) or account_block.get(flag)):
            flags_off.append(flag)

    if flags_off:
        evidence = {"flags_off": flags_off,
                    "bucket_setting": "set" if bucket["public_access_block"] else "not set"}
        return make_result("s3_block_public_access", bucket, "fail", evidence)
    return make_result("s3_block_public_access", bucket, "pass")


def check_wildcard_principal(bucket):
    """Rule 3: no Allow statement for any principal ("*") without a Condition.

    Allow with NotPrincipal also counts, since it means everyone except
    the listed principals.
    """
    incomplete = read_error("s3_wildcard_principal", bucket, "policy")
    if incomplete:
        return incomplete
    if bucket["policy"] is None:
        return make_result("s3_wildcard_principal", bucket, "pass", {"policy": "not set"})

    risky = []
    for statement in statements(bucket["policy"]):
        if statement.get("Effect") != "Allow" or has_condition(statement):
            continue
        if is_public_principal(statement.get("Principal")) or "NotPrincipal" in statement:
            risky.append({"sid": statement.get("Sid"),
                          "actions": as_list(statement.get("Action"))})

    if risky:
        return make_result("s3_wildcard_principal", bucket, "fail", {"statements": risky})
    return make_result("s3_wildcard_principal", bucket, "pass")


def check_versioning(bucket):
    """Rule 4: versioning is Enabled. Suspended or never set fails."""
    incomplete = read_error("s3_versioning", bucket, "versioning")
    if incomplete:
        return incomplete

    # AWS leaves Status out entirely if versioning was never turned on
    status = (bucket["versioning"] or {}).get("Status", "Never enabled")
    if status == "Enabled":
        return make_result("s3_versioning", bucket, "pass")
    return make_result("s3_versioning", bucket, "fail", {"versioning_status": status})


def denies_insecure_transport(statement):
    """True if the statement denies everyone all S3 actions over plain HTTP."""
    if statement.get("Effect") != "Deny" or not is_public_principal(statement.get("Principal")):
        return False

    actions = as_list(statement.get("Action"))
    if "*" not in actions and "s3:*" not in actions:
        return False

    # the object ARN (bucket/*) or "*" has to be covered, otherwise
    # downloads can still go over HTTP
    resources = as_list(statement.get("Resource"))
    if not any(r == "*" or r.endswith("/*") for r in resources):
        return False

    for operator in ("Bool", "BoolIfExists"):
        conditions = statement.get("Condition", {}).get(operator, {})
        for key, value in conditions.items():
            # AWS condition keys aren't case sensitive
            if key.lower() == "aws:securetransport":
                if any(str(v).lower() == "false" for v in as_list(value)):
                    return True
    return False


def check_https_only(bucket):
    """Rule 5: the bucket policy denies requests that don't use HTTPS."""
    incomplete = read_error("s3_https_only", bucket, "policy")
    if incomplete:
        return incomplete
    if bucket["policy"] is None:
        return make_result("s3_https_only", bucket, "fail", {"policy": "not set"})

    for statement in statements(bucket["policy"]):
        if denies_insecure_transport(statement):
            return make_result("s3_https_only", bucket, "pass", {"sid": statement.get("Sid")})
    return make_result("s3_https_only", bucket, "fail",
                       {"policy": "no Deny statement for aws:SecureTransport false"})


RULES = {
    "s3_public_acl": check_public_acl,
    "s3_block_public_access": check_block_public_access,
    "s3_wildcard_principal": check_wildcard_principal,
    "s3_versioning": check_versioning,
    "s3_https_only": check_https_only,
}


def check_bucket(bucket, selected_rules=None, account_block=None):
    """Runs the selected S3 rules (all of them by default) on one bucket."""
    results = []
    for rule_id, rule in RULES.items():
        if selected_rules is not None and rule_id not in selected_rules:
            continue
        if rule_id == "s3_block_public_access":
            results.append(rule(bucket, account_block))
        else:
            results.append(rule(bucket))
    return results
