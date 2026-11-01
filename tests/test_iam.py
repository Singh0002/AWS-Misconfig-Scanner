"""Tests for the IAM collector working together with the rules (E-3 S-5-1, E-3 S-6-1, E-3 S-6-4).

These fake the AWS responses and run them through collect_iam and then
findings.check_iam, the same path a real scan takes. That catches problems
between the two halves, like a record the rules can't read.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

import results
from collectors import iam
from detection import findings

NOW = datetime.now(timezone.utc)
FULL_KEY_ID = "AKIAEXAMPLEKEY12345"
STRONG = {"MinimumPasswordLength": 14, "RequireSymbols": True, "RequireNumbers": True,
          "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True}


def error(code):
    return ClientError({"Error": {"Code": code}}, "call")


def access_key(created_days_ago, status="Active"):
    return {"AccessKeyId": FULL_KEY_ID, "Status": status,
            "CreateDate": NOW - timedelta(days=created_days_ago)}


def fake_session(password_policy=STRONG, keys=None, last_used_days_ago=None, key_error=None):
    """A fake AWS account with one user, alice, who has MFA and no policies.

    password_policy is the policy, or an error code string to raise.
    keys is alice's access keys; last_used_days_ago applies to all of them.
    """
    pages = {
        "list_users": [{"Users": [{"UserName": "alice"}]}],
        "list_user_policies": [{"PolicyNames": []}],
        "list_attached_user_policies": [{"AttachedPolicies": []}],
        "list_mfa_devices": [{"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/alice"}]}],
        "list_access_keys": [{"AccessKeyMetadata": keys or []}],
    }

    def get_paginator(name):
        paginator = MagicMock()
        if name == "list_access_keys" and key_error:
            paginator.paginate.side_effect = error(key_error)
        else:
            paginator.paginate.return_value = pages[name]
        return paginator

    def last_used(AccessKeyId):
        if last_used_days_ago is None:
            return {"AccessKeyLastUsed": {"ServiceName": "N/A"}}
        return {"AccessKeyLastUsed": {"LastUsedDate": NOW - timedelta(days=last_used_days_ago)}}

    client = MagicMock()
    client.get_paginator.side_effect = get_paginator
    client.get_access_key_last_used.side_effect = last_used
    if isinstance(password_policy, str):
        client.get_account_password_policy.side_effect = error(password_policy)
    else:
        client.get_account_password_policy.return_value = {"PasswordPolicy": password_policy}

    session = MagicMock()
    session.client.return_value = client
    return session


def scan(session):
    """Collects the fake account and runs every IAM rule, like a real scan."""
    result = results.new_scan(["IAM"])
    findings.check_iam(result, iam.collect_iam(session), None, {"AccountMFAEnabled": 1})
    return result


def status(scan_result, rule_id):
    for check in scan_result["checks"]:
        if check["rule_id"] == rule_id:
            return check["status"]


class CollectorShapeTests(unittest.TestCase):
    def test_password_policy_is_kept_out_of_the_user_records(self):
        collected = iam.collect_iam(fake_session())
        self.assertEqual([r["resource_id"] for r in collected["records"]], ["alice"])
        self.assertEqual(collected["password_policy"], {"status": "available", "value": STRONG})

    def test_access_keys_keep_aws_names_and_real_dates(self):
        collected = iam.collect_iam(fake_session(keys=[access_key(10)], last_used_days_ago=2))
        key = collected["records"][0]["access_keys"]["value"][0]
        self.assertEqual(set(key), {"AccessKeyId", "Status", "CreateDate", "LastUsedDate"})
        self.assertIsInstance(key["CreateDate"], datetime)
        self.assertIsInstance(key["LastUsedDate"], datetime)

    def test_only_the_last_4_characters_of_a_key_are_kept(self):
        collected = iam.collect_iam(fake_session(keys=[access_key(10)]))
        self.assertEqual(collected["records"][0]["access_keys"]["value"][0]["AccessKeyId"], "2345")
        self.assertNotIn(FULL_KEY_ID, json.dumps(scan(fake_session(keys=[access_key(200)])), default=str))

    def test_no_password_policy_is_missing_not_an_error(self):
        collected = iam.collect_iam(fake_session(password_policy="NoSuchEntity"))
        self.assertEqual(collected["password_policy"]["status"], "missing")
        self.assertEqual(collected["errors"], [])


class FullScanTests(unittest.TestCase):
    def test_scan_runs_every_iam_rule_without_crashing(self):
        rule_ids = {check["rule_id"] for check in scan(fake_session())["checks"]}
        self.assertEqual(rule_ids, {"iam_admin_wildcard", "iam_user_mfa", "iam_unused_access_key",
                                    "iam_root_mfa", "iam_password_policy"})

    def test_password_policy(self):
        self.assertEqual(status(scan(fake_session()), "iam_password_policy"), "pass")
        weak = dict(STRONG, MinimumPasswordLength=8)
        self.assertEqual(status(scan(fake_session(password_policy=weak)), "iam_password_policy"), "fail")
        self.assertEqual(status(scan(fake_session(password_policy="NoSuchEntity")), "iam_password_policy"), "fail")

    def test_unreadable_password_policy_is_incomplete_with_the_error_code(self):
        result = scan(fake_session(password_policy="AccessDenied"))
        self.assertEqual(status(result, "iam_password_policy"), "incomplete")
        self.assertEqual(result["metadata"]["coverage_status"], "incomplete")
        check = [c for c in result["checks"] if c["rule_id"] == "iam_password_policy"][0]
        self.assertIn("AccessDenied", check["reason"])

    def test_unused_access_keys(self):
        self.assertEqual(status(scan(fake_session()), "iam_unused_access_key"), "pass")
        recent = fake_session(keys=[access_key(400)], last_used_days_ago=5)
        self.assertEqual(status(scan(recent), "iam_unused_access_key"), "pass")
        stale = fake_session(keys=[access_key(400)], last_used_days_ago=91)
        self.assertEqual(status(scan(stale), "iam_unused_access_key"), "fail")
        never_used = fake_session(keys=[access_key(120)])
        self.assertEqual(status(scan(never_used), "iam_unused_access_key"), "fail")
        inactive = fake_session(keys=[access_key(400, status="Inactive")])
        self.assertEqual(status(scan(inactive), "iam_unused_access_key"), "pass")

    def test_unreadable_access_keys_are_incomplete(self):
        result = scan(fake_session(key_error="AccessDenied"))
        self.assertEqual(status(result, "iam_unused_access_key"), "incomplete")

    def test_failed_rules_become_findings(self):
        result = scan(fake_session(password_policy="NoSuchEntity", keys=[access_key(120)]))
        issues = {f["issue"] for f in result["findings"]}
        self.assertIn("Account password policy is weak or missing", issues)
        self.assertIn("Access key unused for more than 90 days", issues)

    def test_only_selected_rules_run(self):
        result = results.new_scan(["IAM"])
        findings.check_iam(result, iam.collect_iam(fake_session()), ["iam_password_policy"],
                           {"AccountMFAEnabled": 1})
        self.assertEqual([c["rule_id"] for c in result["checks"]], ["iam_password_policy"])


if __name__ == "__main__":
    unittest.main()
