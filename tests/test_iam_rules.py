"""Tests for the IAM admin wildcard, user MFA and root MFA rules."""

import json
import unittest

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
        self.assertEqual(set(iam_rules.RULE_INFO), set(iam_rules.USER_RULES) | {"iam_root_mfa"})


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
