"""Turns collector records into checks and findings (E-2 S-3-5, E-2 S-4-4, E-3 S-5-5).

The collectors and the rules use slightly different shapes, so to_bucket and
to_user convert a collector record into what the rules expect. A setting the
collector couldn't read goes into "errors", so the rule marks it incomplete.
"""

import results
from collectors import iam, s3
from detection import iam_rules, s3_rules


def read_error(record, field, settings, errors):
    """The error code if the collector couldn't read this setting, otherwise None."""
    if record[field]["status"] != "failed":
        return None
    for name, helper, operation in settings:
        for error in errors:
            if name == field and error["operation"] == operation and error["resource_id"] == record["resource_id"]:
                return error["message"]
    return "unknown error"


def to_bucket(record, errors):
    bucket = {"name": record["resource_id"], "errors": {}}
    for field, helper, operation in s3.SETTINGS:
        # "missing" settings are None, which the rules read as "not set"
        bucket[field] = record[field]["value"]
        error = read_error(record, field, s3.SETTINGS, errors)
        if error:
            bucket["errors"][field] = error
    return bucket


def to_user(record, errors):
    user = {"name": record["resource_id"], "policies": [], "mfa_devices": [], "errors": {}}
    # the admin rule wants inline and attached policies in one list
    for field in ["inline_policies", "attached_policies"]:
        error = read_error(record, field, iam.SETTINGS, errors)
        if error:
            user["errors"]["policies"] = error
            continue
        for policy in record[field]["value"]:
            user["policies"].append({"name": policy["name"], "type": field.replace("_policies", ""), "document": policy["document"]})

    error = read_error(record, "mfa_devices", iam.SETTINGS, errors)
    if error:
        user["errors"]["mfa_devices"] = error
    else:
        # the collector only keeps a count, and the rule only checks the list isn't empty
        user["mfa_devices"] = ["device"] * record["mfa_devices"]["value"]["DeviceCount"]
    return user


def add_results(scan, service, rule_results, rule_info):
    """Adds each rule result to the scan as a check, plus a finding if it failed."""
    for result in rule_results:
        check = results.make_check(scan["metadata"]["scan_id"], service, result["resource_id"],
                                   result["rule_id"], result["status"], result["evidence"], result["reason"])
        scan["checks"].append(check)
        if check["status"] == "fail":
            issue, severity = rule_info[check["rule_id"]]
            scan["findings"].append(results.make_finding(check, issue, severity))
        if check["status"] == "incomplete":
            scan["metadata"]["coverage_status"] = "incomplete"


def add_errors(scan, errors):
    for error in errors:
        scan["errors"].append(results.make_error(scan["metadata"]["scan_id"], "collection",
                                                 error["operation"], error["message"], error["resource_id"]))
        scan["metadata"]["coverage_status"] = "incomplete"


def check_s3(scan, collected, selected_rules=None, account_block=None):
    add_errors(scan, collected["errors"])
    for record in collected["records"]:
        bucket = to_bucket(record, collected["errors"])
        add_results(scan, "S3", s3_rules.check_bucket(bucket, selected_rules, account_block), s3_rules.RULE_INFO)


def check_iam(scan, collected, selected_rules=None, account_summary=None, summary_error=None):
    add_errors(scan, collected["errors"])
    for record in collected["records"]:
        user = to_user(record, collected["errors"])
        add_results(scan, "IAM", iam_rules.check_user(user, selected_rules), iam_rules.RULE_INFO)
    # root MFA is for the whole account, so it runs once instead of per user
    if selected_rules is None or "iam_root_mfa" in selected_rules:
        add_results(scan, "IAM", [iam_rules.check_root_mfa(account_summary, summary_error)], iam_rules.RULE_INFO)
