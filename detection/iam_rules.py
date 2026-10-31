"""The five IAM rules (E-3 S-5-2, S-5-3, S-5-4, E-3 S-6-2, S-6-3).

Results use the same shape as detection/s3_rules.py:

    {"rule_id": ..., "resource_id": ..., "status": "pass" | "fail" | "incomplete",
     "evidence": {...}, "reason": None}

The user dict the collector should pass in:

    {
        "name": "alice",
        "policies": [   # inline and attached policies, with their documents
            {"name": "AdminFullAccess", "type": "inline", "document": {...}},
        ],
        "mfa_devices": <list_mfa_devices()["MFADevices"]>,
        "access_keys": [   # list_access_keys()["AccessKeyMetadata"], plus each
                           # key's LastUsedDate from get_access_key_last_used
            {"AccessKeyId": ..., "Status": "Active", "CreateDate": <datetime>,
             "LastUsedDate": <datetime> or None},
        ],
        "errors": {"policies": "AccessDenied", ...},  # data that couldn't be read
    }

Two rules are for the whole account instead of one user:
    - root MFA takes the account summary from get_account_summary()
      (either the whole response or just its "SummaryMap")
    - password policy takes get_account_password_policy()["PasswordPolicy"],
      or None if the account has no password policy

The unused access key rule isn't in check_user yet, because the collector
doesn't pass access keys through findings.py until E-3 S-6-4.
"""

from datetime import datetime, timezone

from detection.policy import as_list, has_condition, statements

ADMIN_ACTIONS = {"*", "*:*"}

# a strong password policy needs at least this length and all four of these
PASSWORD_MIN_LENGTH = 14
PASSWORD_REQUIREMENTS = ["RequireUppercaseCharacters", "RequireLowercaseCharacters",
                         "RequireNumbers", "RequireSymbols"]

MAX_UNUSED_DAYS = 90

# rule_id -> issue text and severity for the finding
RULE_INFO = {
    "iam_admin_wildcard": ("Policy allows every action on every resource", "High"),
    "iam_user_mfa": ("User has no MFA device", "High"),
    "iam_root_mfa": ("Root account has no MFA", "High"),
    "iam_password_policy": ("Account password policy is weak or missing", "Medium"),
    "iam_unused_access_key": ("Access key unused for more than 90 days", "Medium"),
}


def make_result(rule_id, resource_id, status, evidence=None, reason=None):
    return {
        "rule_id": rule_id,
        "resource_id": resource_id,
        "status": status,
        "evidence": evidence or {},
        "reason": reason,
    }


def read_error(rule_id, user, field):
    """The incomplete result for user data the collector couldn't read."""
    error = user.get("errors", {}).get(field)
    if error is None and field not in user:
        error = "not collected"
    if error is None:
        return None
    return make_result(rule_id, user["name"], "incomplete",
                       reason=f"Couldn't read the user's {field.replace('_', ' ')} ({error}).")


def is_admin_statement(statement):
    """Allow on every action ("*") for every resource ("*")."""
    if statement.get("Effect") != "Allow":
        return False
    actions = set(as_list(statement.get("Action")))
    return bool(actions & ADMIN_ACTIONS) and "*" in as_list(statement.get("Resource"))


def check_admin_wildcard(user):
    """Rule 6: no policy gives the user every action on every resource.

    A statement with a Condition (for example, only from one IP range) is
    treated as restricted and doesn't fail, but it is listed in the evidence
    so the user can still see it.
    """
    incomplete = read_error("iam_admin_wildcard", user, "policies")
    if incomplete:
        return incomplete

    admin = []
    conditional = []
    for policy in user["policies"]:
        if policy.get("document") is None:
            return make_result("iam_admin_wildcard", user["name"], "incomplete",
                               reason=f"Couldn't read the document for policy {policy.get('name')}.")
        for statement in statements(policy["document"]):
            if not is_admin_statement(statement):
                continue
            entry = {"policy": policy.get("name"), "type": policy.get("type"),
                     "sid": statement.get("Sid")}
            if has_condition(statement):
                conditional.append(entry)
            else:
                admin.append(entry)

    evidence = {}
    if conditional:
        evidence["conditional_admin"] = conditional
    if admin:
        evidence["admin_statements"] = admin
        return make_result("iam_admin_wildcard", user["name"], "fail", evidence)
    return make_result("iam_admin_wildcard", user["name"], "pass", evidence)


def check_user_mfa(user):
    """Rule 7: the user has at least one MFA device."""
    incomplete = read_error("iam_user_mfa", user, "mfa_devices")
    if incomplete:
        return incomplete

    devices = user["mfa_devices"] or []
    if devices:
        return make_result("iam_user_mfa", user["name"], "pass", {"mfa_devices": len(devices)})
    return make_result("iam_user_mfa", user["name"], "fail", {"mfa_devices": 0})


def check_root_mfa(account_summary, error=None):
    """Rule 8: AccountMFAEnabled is 1 in the account summary.

    error is the reason get_account_summary failed, if it did.
    """
    if error is not None or account_summary is None:
        reason = f"Couldn't read the account summary ({error or 'not collected'})."
        return make_result("iam_root_mfa", "root", "incomplete", reason=reason)

    summary = account_summary.get("SummaryMap", account_summary)
    enabled = summary.get("AccountMFAEnabled")
    if enabled is None:
        return make_result("iam_root_mfa", "root", "incomplete",
                           reason="The account summary has no AccountMFAEnabled value.")
    if enabled == 1:
        return make_result("iam_root_mfa", "root", "pass")
    return make_result("iam_root_mfa", "root", "fail", {"AccountMFAEnabled": enabled})


def check_password_policy(policy, error=None):
    """Rule 9: the account password policy is at least 14 characters and
    needs uppercase, lowercase, numbers and symbols.

    error is the reason get_account_password_policy failed, if it did.
    No policy at all fails, because the AWS default has none of these.
    """
    if error is not None:
        return make_result("iam_password_policy", "account", "incomplete",
                           reason=f"Couldn't read the password policy ({error}).")
    if policy is None:
        return make_result("iam_password_policy", "account", "fail", {"policy": "not set"})

    problems = []
    length = policy.get("MinimumPasswordLength") or 0
    if length < PASSWORD_MIN_LENGTH:
        problems.append(f"Minimum length is {length}, should be at least {PASSWORD_MIN_LENGTH}")
    for requirement in PASSWORD_REQUIREMENTS:
        if not policy.get(requirement):
            problems.append(f"{requirement} is off")

    if problems:
        return make_result("iam_password_policy", "account", "fail", {"problems": problems})
    return make_result("iam_password_policy", "account", "pass")


def check_unused_access_keys(user, now=None):
    """Rule 10: no active access key has gone unused for more than 90 days.

    A key that was never used counts from the day it was created. Inactive
    keys are skipped because they can't be used to sign in. now can be set
    so tests get the same answer every day.
    """
    incomplete = read_error("iam_unused_access_key", user, "access_keys")
    if incomplete:
        return incomplete

    now = now or datetime.now(timezone.utc)
    stale = []
    for key in user["access_keys"] or []:
        if key.get("Status") != "Active":
            continue
        since = key.get("LastUsedDate") or key.get("CreateDate")
        if since is None:
            return make_result("iam_unused_access_key", user["name"], "incomplete",
                               reason="An access key has no creation or last used date.")
        days = (now - since).days
        if days > MAX_UNUSED_DAYS:
            # only the last 4 characters, so the evidence never holds a whole key ID
            stale.append({"key_ending": key.get("AccessKeyId", "")[-4:], "days_unused": days,
                          "never_used": key.get("LastUsedDate") is None})

    if stale:
        return make_result("iam_unused_access_key", user["name"], "fail", {"stale_keys": stale})
    return make_result("iam_unused_access_key", user["name"], "pass")


USER_RULES = {
    "iam_admin_wildcard": check_admin_wildcard,
    "iam_user_mfa": check_user_mfa,
}


def check_user(user, selected_rules=None):
    """Runs the selected per-user rules (all of them by default) on one user."""
    results = []
    for rule_id, rule in USER_RULES.items():
        if selected_rules is None or rule_id in selected_rules:
            results.append(rule(user))
    return results
