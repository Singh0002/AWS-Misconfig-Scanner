"""Tests for the five IAM rules: admin wildcard, user MFA, root MFA, password policy and unused keys."""

import json
import unittest
from datetime import datetime, timedelta, timezone

from detection import iam_rules

ADMIN = {"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"}
READ_ONLY = {"Sid": "ReadS3", "Effect": "Allow", "Action": ["s3:Get*", "s3:List*"],
             "Resource": "*"}
MFA_DEVICE = {"UserName": "alice", "SerialNumber": "arn:aws:iam::123456789012:mfa/alice"}


def doc(*statement_list):
    return {"Version": "2012-10-17", "Statement": list(statement_list)}


def make_user(**changes):
    """A user that passes both user rules. Pass keyword arguments to break one."""
    user = {
        "name": "alice",
        "policies": [{"name": "ReadS3", "type": "inline", "document": doc(READ_ONLY)}],
        "mfa_devices": [MFA_DEVICE],
        "errors": {},
    }
    user.update(changes)
    return user


class AdminWildcardTests(unittest.TestCase):
    def test_limited_policy_passes(self):
        self.assertEqual(iam_rules.check_admin_wildcard(make_user())["status"], "pass")

    def test_no_policies_passes(self):
        self.assertEqual(iam_rules.check_admin_wildcard(make_user(policies=[]))["status"], "pass")

    def test_star_action_and_resource_fails(self):
        user = make_user(policies=[{"name": "AdminFullAccess", "type": "inline",
                                    "document": doc(READ_ONLY, ADMIN)}])
        result = iam_rules.check_admin_wildcard(user)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["evidence"]["admin_statements"][0]["policy"], "AdminFullAccess")

    def test_attached_administrator_access_fails(self):
        # the AWS managed AdministratorAccess policy, as get_policy_version returns it
        managed = doc({"Effect": "Allow", "Action": "*", "Resource": "*"})
        user = make_user(policies=[{"name": "AdministratorAccess", "type": "attached",
                                    "document": managed}])
        self.assertEqual(iam_rules.check_admin_wildcard(user)["status"], "fail")

    def test_star_colon_star_and_lists_fail(self):
        statement = {"Effect": "Allow", "Action": ["*:*"], "Resource": ["*"]}
        user = make_user(policies=[{"name": "p", "type": "inline", "document": doc(statement)}])
        self.assertEqual(iam_rules.check_admin_wildcard(user)["status"], "fail")

    def test_one_service_wildcard_passes(self):
        statement = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        user = make_user(policies=[{"name": "p", "type": "inline", "document": doc(statement)}])
        self.assertEqual(iam_rules.check_admin_wildcard(user)["status"], "pass")

    def test_star_action_on_one_resource_passes(self):
        statement = {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::my-bucket/*"}
        user = make_user(policies=[{"name": "p", "type": "inline", "document": doc(statement)}])
        self.assertEqual(iam_rules.check_admin_wildcard(user)["status"], "pass")

    def test_deny_star_passes(self):
        user = make_user(policies=[{"name": "p", "type": "inline",
                                    "document": doc(dict(ADMIN, Effect="Deny"))}])
        self.assertEqual(iam_rules.check_admin_wildcard(user)["status"], "pass")

    def test_condition_restricts_it_but_is_reported(self):
        condition = {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}
        user = make_user(policies=[{"name": "OfficeAdmin", "type": "inline",
                                    "document": doc(dict(ADMIN, Condition=condition))}])
        result = iam_rules.check_admin_wildcard(user)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["evidence"]["conditional_admin"][0]["policy"], "OfficeAdmin")

    def test_document_as_json_string(self):
        user = make_user(policies=[{"name": "p", "type": "inline",
                                    "document": json.dumps(doc(ADMIN))}])
        self.assertEqual(iam_rules.check_admin_wildcard(user)["status"], "fail")

    def test_unreadable_policies_are_incomplete(self):
        user = make_user(errors={"policies": "AccessDenied"})
        result = iam_rules.check_admin_wildcard(user)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("AccessDenied", result["reason"])

    def test_missing_document_is_incomplete_not_pass(self):
        user = make_user(policies=[{"name": "Mystery", "type": "attached", "document": None}])
        self.assertEqual(iam_rules.check_admin_wildcard(user)["status"], "incomplete")


class UserMfaTests(unittest.TestCase):
    def test_with_device_passes(self):
        self.assertEqual(iam_rules.check_user_mfa(make_user())["status"], "pass")

    def test_without_device_fails(self):
        result = iam_rules.check_user_mfa(make_user(mfa_devices=[]))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["resource_id"], "alice")

    def test_unreadable_devices_are_incomplete(self):
        user = make_user(errors={"mfa_devices": "AccessDenied"})
        self.assertEqual(iam_rules.check_user_mfa(user)["status"], "incomplete")

    def test_not_collected_is_incomplete(self):
        user = make_user()
        del user["mfa_devices"]
        self.assertEqual(iam_rules.check_user_mfa(user)["status"], "incomplete")


class RootMfaTests(unittest.TestCase):
    def test_enabled_passes(self):
        result = iam_rules.check_root_mfa({"SummaryMap": {"AccountMFAEnabled": 1}})
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["resource_id"], "root")

    def test_disabled_fails(self):
        self.assertEqual(iam_rules.check_root_mfa({"AccountMFAEnabled": 0})["status"], "fail")

    def test_api_error_is_incomplete(self):
        result = iam_rules.check_root_mfa(None, error="AccessDenied")
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("AccessDenied", result["reason"])

    def test_missing_value_is_incomplete(self):
        self.assertEqual(iam_rules.check_root_mfa({"SummaryMap": {}})["status"], "incomplete")


class CheckUserTests(unittest.TestCase):
    def test_runs_both_user_rules_by_default(self):
        found = [r["rule_id"] for r in iam_rules.check_user(make_user())]
        self.assertEqual(found, ["iam_admin_wildcard", "iam_user_mfa"])

    def test_runs_only_selected_rules(self):
        found = [r["rule_id"] for r in iam_rules.check_user(make_user(), ["iam_user_mfa"])]
        self.assertEqual(found, ["iam_user_mfa"])

    def test_every_rule_has_issue_text_and_severity(self):
        account_rules = {"iam_root_mfa", "iam_password_policy", "iam_unused_access_key"}
        self.assertEqual(set(iam_rules.RULE_INFO), set(iam_rules.USER_RULES) | account_rules)


STRONG_POLICY = {
    "MinimumPasswordLength": 14,
    "RequireUppercaseCharacters": True,
    "RequireLowercaseCharacters": True,
    "RequireNumbers": True,
    "RequireSymbols": True,
}


class PasswordPolicyTests(unittest.TestCase):
    def test_strong_policy_passes(self):
        result = iam_rules.check_password_policy(STRONG_POLICY)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["resource_id"], "account")

    def test_longer_than_minimum_passes(self):
        policy = dict(STRONG_POLICY, MinimumPasswordLength=20)
        self.assertEqual(iam_rules.check_password_policy(policy)["status"], "pass")

    def test_too_short_fails(self):
        result = iam_rules.check_password_policy(dict(STRONG_POLICY, MinimumPasswordLength=8))
        self.assertEqual(result["status"], "fail")
        self.assertIn("Minimum length is 8, should be at least 14", result["evidence"]["problems"])

    def test_length_13_fails_and_14_passes(self):
        short = iam_rules.check_password_policy(dict(STRONG_POLICY, MinimumPasswordLength=13))
        self.assertEqual(short["status"], "fail")
        self.assertEqual(iam_rules.check_password_policy(STRONG_POLICY)["status"], "pass")

    def test_each_missing_requirement_fails(self):
        for requirement in iam_rules.PASSWORD_REQUIREMENTS:
            result = iam_rules.check_password_policy(dict(STRONG_POLICY, **{requirement: False}))
            self.assertEqual(result["status"], "fail", requirement)
            self.assertEqual(result["evidence"]["problems"], [requirement + " is off"])

    def test_requirement_left_out_fails(self):
        # AWS leaves fields out of the response when they were never set
        policy = dict(STRONG_POLICY)
        del policy["RequireSymbols"]
        self.assertEqual(iam_rules.check_password_policy(policy)["status"], "fail")

    def test_weak_policy_lists_every_problem(self):
        result = iam_rules.check_password_policy({"MinimumPasswordLength": 6})
        self.assertEqual(len(result["evidence"]["problems"]), 5)

    def test_no_policy_fails(self):
        result = iam_rules.check_password_policy(None)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["evidence"], {"policy": "not set"})

    def test_unreadable_policy_is_incomplete(self):
        result = iam_rules.check_password_policy(None, error="AccessDenied")
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("AccessDenied", result["reason"])


NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def days_ago(days):
    return NOW - timedelta(days=days)


def key(created_days_ago, last_used_days_ago=None, status="Active", key_id="AKIAEXAMPLE1234"):
    return {"AccessKeyId": key_id, "Status": status, "CreateDate": days_ago(created_days_ago),
            "LastUsedDate": None if last_used_days_ago is None else days_ago(last_used_days_ago)}


def user_with_keys(*keys, **changes):
    user = {"name": "alice", "access_keys": list(keys), "errors": {}}
    user.update(changes)
    return user


class UnusedAccessKeyTests(unittest.TestCase):
    def check(self, user):
        return iam_rules.check_unused_access_keys(user, now=NOW)

    def test_recently_used_key_passes(self):
        self.assertEqual(self.check(user_with_keys(key(400, last_used_days_ago=3)))["status"], "pass")

    def test_89_90_91_days_since_last_use(self):
        self.assertEqual(self.check(user_with_keys(key(400, 89)))["status"], "pass")
        self.assertEqual(self.check(user_with_keys(key(400, 90)))["status"], "pass")
        self.assertEqual(self.check(user_with_keys(key(400, 91)))["status"], "fail")

    def test_never_used_key_counts_from_creation(self):
        self.assertEqual(self.check(user_with_keys(key(90)))["status"], "pass")
        result = self.check(user_with_keys(key(91)))
        self.assertEqual(result["status"], "fail")
        self.assertTrue(result["evidence"]["stale_keys"][0]["never_used"])

    def test_old_key_used_recently_passes(self):
        # the key's age doesn't matter, only how long since it was last used
        self.assertEqual(self.check(user_with_keys(key(1000, last_used_days_ago=1)))["status"], "pass")

    def test_inactive_key_is_skipped(self):
        self.assertEqual(self.check(user_with_keys(key(500, status="Inactive")))["status"], "pass")

    def test_one_stale_key_among_good_ones_fails(self):
        result = self.check(user_with_keys(key(10, 1), key(200, key_id="AKIAEXAMPLE9999")))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(result["evidence"]["stale_keys"]), 1)

    def test_evidence_shows_only_last_four_characters(self):
        result = self.check(user_with_keys(key(200, key_id="AKIAEXAMPLE9999")))
        stale = result["evidence"]["stale_keys"][0]
        self.assertEqual(stale["key_ending"], "9999")
        self.assertNotIn("AKIAEXAMPLE9999", json.dumps(result))

    def test_no_keys_passes(self):
        self.assertEqual(self.check(user_with_keys())["status"], "pass")

    def test_unreadable_keys_are_incomplete(self):
        result = self.check(user_with_keys(errors={"access_keys": "AccessDenied"}))
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("AccessDenied", result["reason"])

    def test_not_collected_is_incomplete(self):
        self.assertEqual(self.check({"name": "alice", "errors": {}})["status"], "incomplete")

    def test_missing_dates_is_incomplete_not_pass(self):
        broken = {"AccessKeyId": "AKIAEXAMPLE1234", "Status": "Active"}
        self.assertEqual(self.check(user_with_keys(broken))["status"], "incomplete")

    def test_uses_todays_date_by_default(self):
        old = {"AccessKeyId": "AKIAEXAMPLE1234", "Status": "Active",
               "CreateDate": datetime(2000, 1, 1, tzinfo=timezone.utc), "LastUsedDate": None}
        self.assertEqual(iam_rules.check_unused_access_keys(user_with_keys(old))["status"], "fail")


try:
    import boto3
    from moto import mock_aws
except ImportError:
    mock_aws = None


@unittest.skipIf(mock_aws is None, "moto isn't installed")
class RealResponseShapeTests(unittest.TestCase):
    """Runs the rules on real boto3 responses from moto's fake AWS."""

    def collect(self, iam, name):
        # a stand-in for Martin's collector (E-3 S-5-1), just enough for this test
        policies = []
        for policy_name in iam.list_user_policies(UserName=name)["PolicyNames"]:
            document = iam.get_user_policy(UserName=name, PolicyName=policy_name)["PolicyDocument"]
            policies.append({"name": policy_name, "type": "inline", "document": document})
        return {"name": name, "policies": policies, "errors": {},
                "mfa_devices": iam.list_mfa_devices(UserName=name)["MFADevices"]}

    def test_bad_and_good_users(self):
        with mock_aws():
            iam = boto3.client("iam", region_name="us-east-1", aws_access_key_id="testing",
                               aws_secret_access_key="testing")

            iam.create_user(UserName="bad-user")
            iam.put_user_policy(UserName="bad-user", PolicyName="AdminFullAccess",
                                PolicyDocument=json.dumps(doc(ADMIN)))

            iam.create_user(UserName="good-user")
            iam.put_user_policy(UserName="good-user", PolicyName="ReadS3",
                                PolicyDocument=json.dumps(doc(READ_ONLY)))
            serial = iam.create_virtual_mfa_device(
                VirtualMFADeviceName="good-user")["VirtualMFADevice"]["SerialNumber"]
            iam.enable_mfa_device(UserName="good-user", SerialNumber=serial,
                                  AuthenticationCode1="123456", AuthenticationCode2="654321")

            bad = iam_rules.check_user(self.collect(iam, "bad-user"))
            good = iam_rules.check_user(self.collect(iam, "good-user"))
            root = iam_rules.check_root_mfa(iam.get_account_summary())

        self.assertEqual({r["status"] for r in bad}, {"fail"}, bad)
        self.assertEqual({r["status"] for r in good}, {"pass"}, good)
        self.assertIn(root["status"], ("pass", "fail"))


if __name__ == "__main__":
    unittest.main()
