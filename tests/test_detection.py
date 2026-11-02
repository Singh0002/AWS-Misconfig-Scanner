"""5.2 Detection tests (FR-DET-1, FR-DET-2, DETECT-1 to DETECT-7).

A passing and a failing case for every S3 and IAM rule, policy conditions,
the 89/90/91 day access key boundary, inactive and never-used keys, missing
data giving incomplete, and failed checks making the right finding.
"""

import json
import unittest

import results
from detection import findings, iam_rules, s3_rules
from collectors import iam, s3
from fakes import (ADMIN_POLICY, BLOCK_ALL, PRIVATE_ACL, PUBLIC_ACL, READ_ONLY_POLICY,
                   STRONG_PASSWORDS, FakeAWS, FakeSession, access_key, bad_bucket, bad_user,
                   good_bucket, https_policy, public_policy)

AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def bucket(**changes):
    """A bucket in the shape the S3 rules read, secure unless changed."""
    b = {"name": "b1", "acl": {"Grants": PRIVATE_ACL}, "public_access_block": BLOCK_ALL,
         "versioning": {"Status": "Enabled"}, "policy": https_policy("b1"), "errors": {}}
    b.update(changes)
    return b


def user(**changes):
    """A user in the shape the IAM rules read, secure unless changed."""
    u = {"name": "u1", "policies": [{"name": "ReadOnly", "type": "attached", "document": READ_ONLY_POLICY}],
         "mfa_devices": ["device"], "access_keys": [access_key()], "errors": {}}
    u.update(changes)
    return u


def with_statement(statement):
    return {"Statement": [statement]}


class S3RuleTests(unittest.TestCase):
    def check(self, rule_id, b, expected):
        result = s3_rules.check_bucket(b, [rule_id])[0]
        self.assertEqual(result["status"], expected)

    def test_public_acl(self):
        self.check("s3_public_acl", bucket(), "pass")
        self.check("s3_public_acl", bucket(acl={"Grants": PUBLIC_ACL}), "fail")
        authenticated = [{"Grantee": {"Type": "Group", "URI": AUTHENTICATED_USERS}, "Permission": "WRITE"}]
        self.check("s3_public_acl", bucket(acl={"Grants": authenticated}), "fail")

    def test_block_public_access(self):
        self.check("s3_block_public_access", bucket(), "pass")
        self.check("s3_block_public_access", bucket(public_access_block=dict(BLOCK_ALL, BlockPublicAcls=False)), "fail")
        self.check("s3_block_public_access", bucket(public_access_block=None), "fail")
        # the account-wide setting covers a bucket that has none of its own
        result = s3_rules.check_block_public_access(bucket(public_access_block=None), BLOCK_ALL)
        self.assertEqual(result["status"], "pass")

    def test_versioning(self):
        self.check("s3_versioning", bucket(), "pass")
        self.check("s3_versioning", bucket(versioning={"Status": "Suspended"}), "fail")
        self.check("s3_versioning", bucket(versioning={}), "fail")

    def test_https_only(self):
        self.check("s3_https_only", bucket(), "pass")
        self.check("s3_https_only", bucket(policy=None), "fail")
        self.check("s3_https_only", bucket(policy=public_policy("b1")), "fail")

    def test_wildcard_principal(self):
        self.check("s3_wildcard_principal", bucket(), "pass")
        self.check("s3_wildcard_principal", bucket(policy=None), "pass")
        self.check("s3_wildcard_principal", bucket(policy=public_policy("b1")), "fail")
        aws_star = with_statement({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:*", "Resource": "*"})
        self.check("s3_wildcard_principal", bucket(policy=aws_star), "fail")

    def test_wildcard_with_a_condition_is_not_a_finding(self):
        # an asterisk alone isn't enough, the condition limits who gets in
        limited = with_statement({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                  "Resource": "arn:aws:s3:::b1/*",
                                  "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}})
        self.check("s3_wildcard_principal", bucket(policy=limited), "pass")
        named = with_statement({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                                "Action": "s3:*", "Resource": "*"})
        self.check("s3_wildcard_principal", bucket(policy=named), "pass")


class IamRuleTests(unittest.TestCase):
    def check(self, rule_id, u, expected):
        result = iam_rules.check_user(u, [rule_id])[0]
        self.assertEqual(result["status"], expected)

    def test_admin_wildcard(self):
        self.check("iam_admin_wildcard", user(), "pass")
        self.check("iam_admin_wildcard", user(policies=[]), "pass")
        admin = [{"name": "Admin", "type": "inline", "document": ADMIN_POLICY}]
        self.check("iam_admin_wildcard", user(policies=admin), "fail")

    def test_admin_wildcard_considers_conditions_and_resources(self):
        conditional = with_statement({"Effect": "Allow", "Action": "*", "Resource": "*",
                                      "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}})
        self.check("iam_admin_wildcard", user(policies=[{"name": "MfaAdmin", "document": conditional}]), "pass")
        one_service = with_statement({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})
        self.check("iam_admin_wildcard", user(policies=[{"name": "S3Admin", "document": one_service}]), "pass")

    def test_user_mfa(self):
        self.check("iam_user_mfa", user(), "pass")
        self.check("iam_user_mfa", user(mfa_devices=[]), "fail")

    def test_root_mfa(self):
        self.assertEqual(iam_rules.check_root_mfa({"SummaryMap": {"AccountMFAEnabled": 1}})["status"], "pass")
        self.assertEqual(iam_rules.check_root_mfa({"SummaryMap": {"AccountMFAEnabled": 0}})["status"], "fail")

    def test_password_policy(self):
        self.assertEqual(iam_rules.check_password_policy(STRONG_PASSWORDS)["status"], "pass")
        self.assertEqual(iam_rules.check_password_policy(None)["status"], "fail")
        short = dict(STRONG_PASSWORDS, MinimumPasswordLength=13)
        self.assertEqual(iam_rules.check_password_policy(short)["status"], "fail")
        for requirement in iam_rules.PASSWORD_REQUIREMENTS:
            with self.subTest(requirement):
                weak = dict(STRONG_PASSWORDS, **{requirement: False})
                self.assertEqual(iam_rules.check_password_policy(weak)["status"], "fail")

    def test_unused_keys_89_90_and_91_days(self):
        for days, expected in [(89, "pass"), (90, "pass"), (91, "fail")]:
            with self.subTest(days=days):
                self.check("iam_unused_access_key", user(access_keys=[access_key(last_used=days)]), expected)

    def test_inactive_keys_are_skipped(self):
        old = access_key(status="Inactive", created=500, last_used=300)
        self.check("iam_unused_access_key", user(access_keys=[old]), "pass")

    def test_never_used_keys_count_from_their_creation_date(self):
        self.check("iam_unused_access_key", user(access_keys=[access_key(created=91, last_used=None)]), "fail")
        self.check("iam_unused_access_key", user(access_keys=[access_key(created=10, last_used=None)]), "pass")
        # no dates at all means AWS didn't confirm anything, so it can't pass
        no_dates = dict(access_key(last_used=None), CreateDate=None)
        self.check("iam_unused_access_key", user(access_keys=[no_dates]), "incomplete")


class IncompleteTests(unittest.TestCase):
    def test_unreadable_data_is_incomplete_for_every_rule(self):
        for rule_id, setting in [("s3_public_acl", "acl"), ("s3_block_public_access", "public_access_block"),
                                 ("s3_versioning", "versioning"), ("s3_https_only", "policy"),
                                 ("s3_wildcard_principal", "policy")]:
            with self.subTest(rule_id):
                result = s3_rules.check_bucket(bucket(errors={setting: "AccessDenied"}), [rule_id])[0]
                self.assertEqual(result["status"], "incomplete")
                self.assertIn("AccessDenied", result["reason"])

        for rule_id, setting in [("iam_admin_wildcard", "policies"), ("iam_user_mfa", "mfa_devices"),
                                 ("iam_unused_access_key", "access_keys")]:
            with self.subTest(rule_id):
                result = iam_rules.check_user(user(errors={setting: "AccessDenied"}), [rule_id])[0]
                self.assertEqual(result["status"], "incomplete")

        self.assertEqual(iam_rules.check_root_mfa(None, "AccessDenied")["status"], "incomplete")
        self.assertEqual(iam_rules.check_password_policy(None, "AccessDenied")["status"], "incomplete")

    def test_data_that_was_never_collected_is_incomplete_not_passed(self):
        b = bucket()
        del b["versioning"]
        self.assertEqual(s3_rules.check_versioning(b)["status"], "incomplete")
        u = user()
        del u["access_keys"]
        self.assertEqual(iam_rules.check_unused_access_keys(u)["status"], "incomplete")

    def test_incomplete_checks_mark_the_scan_coverage_incomplete(self):
        aws = FakeAWS(buckets=[bad_bucket("b1")], fail={"get_bucket_versioning": "AccessDenied"})
        scan = results.new_scan(["S3"])
        findings.check_s3(scan, s3.collect_s3(FakeSession(aws)))
        statuses = {c["rule_id"]: c["status"] for c in scan["checks"]}
        self.assertEqual(statuses["s3_versioning"], "incomplete")
        self.assertEqual(scan["metadata"]["coverage_status"], "incomplete")
        # an incomplete check never makes a finding
        self.assertNotIn("s3_versioning", [f["check_id"].split("/")[2] for f in scan["findings"]])


class FindingTests(unittest.TestCase):
    def scan_everything(self):
        aws = FakeAWS(buckets=[bad_bucket("b1")], users=[bad_user("u1")], password_policy=None, root_mfa=0)
        scan = results.new_scan(["S3", "IAM"])
        session = FakeSession(aws)
        findings.check_s3(scan, s3.collect_s3(session))
        findings.check_iam(scan, iam.collect_iam(session), None, aws.get_account_summary())
        return scan

    def test_failed_checks_make_findings_with_the_right_details(self):
        scan = self.scan_everything()
        rule_info = dict(s3_rules.RULE_INFO, **iam_rules.RULE_INFO)
        self.assertEqual(len(scan["findings"]), 10)
        for finding in scan["findings"]:
            check = [c for c in scan["checks"] if c["check_id"] == finding["check_id"]][0]
            with self.subTest(check["rule_id"]):
                self.assertEqual(check["status"], "fail")
                self.assertIn(check["resource_id"], ["b1", "u1", "root", "account"])
                # the issue and severity come from the rule, nothing else
                self.assertEqual((finding["issue"], finding["severity"]), rule_info[check["rule_id"]])
                self.assertNotEqual(json.loads(check["evidence_json"]), {})

    def test_passing_checks_make_no_findings(self):
        aws = FakeAWS(buckets=[good_bucket("b1")])
        scan = results.new_scan(["S3"])
        findings.check_s3(scan, s3.collect_s3(FakeSession(aws)))
        self.assertEqual({c["status"] for c in scan["checks"]}, {"pass"})
        self.assertEqual(scan["findings"], [])

    def test_only_a_failed_check_can_have_a_finding(self):
        check = results.make_check("scan1", "S3", "b1", "s3_versioning", "pass")
        with self.assertRaises(ValueError):
            results.make_finding(check, "Versioning is not enabled", "Medium")

    def test_evidence_shows_what_the_rule_found(self):
        result = s3_rules.check_public_acl(bucket(acl={"Grants": PUBLIC_ACL}))
        self.assertEqual(result["evidence"], {"public_grants": [{"group": "All Users", "permission": "READ"}]})


HTTPS_STATEMENT = https_policy("b1")["Statement"][0]


class PolicyEdgeCaseTests(unittest.TestCase):
    """Policies that look safe but aren't, or look risky but aren't. These are
    where a rule could quietly call an unsafe bucket or user safe."""

    def status(self, rule_id, b):
        return s3_rules.check_bucket(b, [rule_id])[0]["status"]

    def test_allow_with_not_principal_means_almost_everyone(self):
        # "everyone except this account" is still public
        statement = {"Effect": "Allow", "NotPrincipal": {"AWS": "arn:aws:iam::111122223333:root"},
                     "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b1/*"}
        self.assertEqual(self.status("s3_wildcard_principal", bucket(policy=with_statement(statement))), "fail")

    def test_an_empty_condition_does_not_limit_anyone(self):
        statement = dict(public_policy("b1")["Statement"][0], Condition={})
        self.assertEqual(self.status("s3_wildcard_principal", bucket(policy=with_statement(statement))), "fail")

    def test_deny_for_everyone_is_not_a_wildcard_finding(self):
        # the HTTPS statement is a Deny with Principal "*", which protects the bucket
        self.assertEqual(self.status("s3_wildcard_principal", bucket()), "pass")

    def test_policy_given_as_a_json_string(self):
        self.assertEqual(self.status("s3_wildcard_principal", bucket(policy=json.dumps(public_policy("b1")))), "fail")
        self.assertEqual(self.status("s3_https_only", bucket(policy=json.dumps(https_policy("b1")))), "pass")

    def test_log_delivery_group_is_not_public(self):
        log_delivery = [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                         "Permission": "WRITE"}]
        self.assertEqual(self.status("s3_public_acl", bucket(acl={"Grants": log_delivery})), "pass")

    def test_https_statements_that_only_partly_protect_fail(self):
        partial = {
            "allows instead of denies": dict(HTTPS_STATEMENT, Effect="Allow"),
            "only blocks one action": dict(HTTPS_STATEMENT, Action="s3:PutObject"),
            "only covers the bucket, not its files": dict(HTTPS_STATEMENT, Resource="arn:aws:s3:::b1"),
            "blocks HTTPS instead of HTTP": dict(HTTPS_STATEMENT, Condition={"Bool": {"aws:SecureTransport": "true"}}),
            "only applies to one account": dict(HTTPS_STATEMENT, Principal={"AWS": "arn:aws:iam::111122223333:root"}),
        }
        for name, statement in partial.items():
            with self.subTest(name):
                self.assertEqual(self.status("s3_https_only", bucket(policy=with_statement(statement))), "fail")

    def test_https_condition_written_other_valid_ways_passes(self):
        # AWS treats condition keys case-insensitively and allows BoolIfExists and a real boolean
        statement = dict(HTTPS_STATEMENT, Condition={"BoolIfExists": {"AWS:SecureTransport": False}})
        self.assertEqual(self.status("s3_https_only", bucket(policy=with_statement(statement))), "pass")

    def test_admin_wildcard_written_other_ways(self):
        cases = {
            "*:* in a list fails": ({"Effect": "Allow", "Action": ["*:*"], "Resource": ["*"]}, "fail"),
            "every action on one bucket passes": (
                {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b1/*"}, "pass"),
            "deny everything passes": ({"Effect": "Deny", "Action": "*", "Resource": "*"}, "pass"),
        }
        for name, (statement, expected) in cases.items():
            with self.subTest(name):
                policies = [{"name": "p", "type": "inline", "document": with_statement(statement)}]
                result = iam_rules.check_admin_wildcard(user(policies=policies))
                self.assertEqual(result["status"], expected)

    def test_admin_policy_given_as_a_json_string(self):
        policies = [{"name": "Admin", "type": "inline", "document": json.dumps(ADMIN_POLICY)}]
        self.assertEqual(iam_rules.check_admin_wildcard(user(policies=policies))["status"], "fail")

    def test_conditional_admin_passes_but_is_still_reported(self):
        conditional = with_statement({"Effect": "Allow", "Action": "*", "Resource": "*",
                                      "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}})
        result = iam_rules.check_admin_wildcard(user(policies=[{"name": "OfficeAdmin", "document": conditional}]))
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["evidence"]["conditional_admin"][0]["policy"], "OfficeAdmin")

    def test_policy_whose_text_is_missing_is_incomplete_not_passed(self):
        policies = [{"name": "Mystery", "type": "attached", "document": None}]
        self.assertEqual(iam_rules.check_admin_wildcard(user(policies=policies))["status"], "incomplete")

    def test_root_summary_without_the_mfa_value_is_incomplete(self):
        self.assertEqual(iam_rules.check_root_mfa({"SummaryMap": {}})["status"], "incomplete")

    def test_stale_key_evidence_shows_only_the_last_4_characters(self):
        key = access_key(last_used=200)
        result = iam_rules.check_unused_access_keys(user(access_keys=[key]))
        self.assertEqual(result["evidence"]["stale_keys"][0]["key_ending"], key["AccessKeyId"][-4:])
        self.assertNotIn(key["AccessKeyId"], json.dumps(result, default=str))


if __name__ == "__main__":
    unittest.main()
