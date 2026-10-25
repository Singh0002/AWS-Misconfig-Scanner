"""Tests for the five S3 rules: a passing, failing and unreadable case for each."""

import json
import unittest

import results
from detection import s3_rules

BUCKET_ARN = "arn:aws:s3:::my-bucket"

ALL_ON = {flag: True for flag in s3_rules.BLOCK_PUBLIC_ACCESS_FLAGS}

OWNER_ONLY_ACL = {"Grants": [{
    "Grantee": {"Type": "CanonicalUser", "ID": "abc123"},
    "Permission": "FULL_CONTROL",
}]}

HTTPS_ONLY_STATEMENT = {
    "Sid": "EnforceHTTPS",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [BUCKET_ARN, BUCKET_ARN + "/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
}


def policy(*statement_list):
    return {"Version": "2012-10-17", "Statement": list(statement_list)}


def good_bucket(**changes):
    """A bucket that passes every rule. Pass keyword arguments to break one."""
    bucket = {
        "name": "my-bucket",
        "acl": OWNER_ONLY_ACL,
        "public_access_block": dict(ALL_ON),
        "policy": policy(HTTPS_ONLY_STATEMENT),
        "versioning": {"Status": "Enabled"},
        "errors": {},
    }
    bucket.update(changes)
    return bucket


def public_grant(uri, permission="READ"):
    return {"Grantee": {"Type": "Group", "URI": uri}, "Permission": permission}


class GoodBucketTests(unittest.TestCase):
    def test_good_bucket_passes_every_rule(self):
        for result in s3_rules.check_bucket(good_bucket()):
            self.assertEqual(result["status"], "pass", result["rule_id"])

    def test_check_bucket_runs_only_selected_rules(self):
        found = s3_rules.check_bucket(good_bucket(), ["s3_versioning"])
        self.assertEqual([r["rule_id"] for r in found], ["s3_versioning"])

    def test_every_rule_has_issue_text_and_severity(self):
        self.assertEqual(set(s3_rules.RULE_INFO), set(s3_rules.RULES))

    def test_results_fit_the_shared_format(self):
        scan_id = results.new_scan(["S3"])["metadata"]["scan_id"]
        for result in s3_rules.check_bucket(good_bucket(acl={"Grants": [public_grant(s3_rules.ALL_USERS)]})):
            check = results.make_check(scan_id, "S3", result["resource_id"], result["rule_id"],
                                       result["status"], result["evidence"], result["reason"])
            if check["status"] == "fail":
                issue, severity = s3_rules.RULE_INFO[result["rule_id"]]
                results.make_finding(check, issue, severity)


class PublicAclTests(unittest.TestCase):
    def test_all_users_grant_fails(self):
        bucket = good_bucket(acl={"Grants": [public_grant(s3_rules.ALL_USERS)]})
        result = s3_rules.check_public_acl(bucket)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["evidence"]["public_grants"][0]["group"], "All Users")

    def test_authenticated_users_grant_fails(self):
        bucket = good_bucket(acl={"Grants": [public_grant(s3_rules.AUTHENTICATED_USERS, "WRITE")]})
        self.assertEqual(s3_rules.check_public_acl(bucket)["status"], "fail")

    def test_owner_only_passes(self):
        self.assertEqual(s3_rules.check_public_acl(good_bucket())["status"], "pass")

    def test_log_delivery_group_is_not_public(self):
        log_delivery = "http://acs.amazonaws.com/groups/s3/LogDelivery"
        bucket = good_bucket(acl={"Grants": [public_grant(log_delivery, "WRITE")]})
        self.assertEqual(s3_rules.check_public_acl(bucket)["status"], "pass")

    def test_unreadable_acl_is_incomplete(self):
        bucket = good_bucket(errors={"acl": "AccessDenied"})
        result = s3_rules.check_public_acl(bucket)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("AccessDenied", result["reason"])


class BlockPublicAccessTests(unittest.TestCase):
    def test_all_flags_on_passes(self):
        self.assertEqual(s3_rules.check_block_public_access(good_bucket())["status"], "pass")

    def test_one_flag_off_fails(self):
        block = dict(ALL_ON, RestrictPublicBuckets=False)
        result = s3_rules.check_block_public_access(good_bucket(public_access_block=block))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["evidence"]["flags_off"], ["RestrictPublicBuckets"])

    def test_not_set_fails(self):
        result = s3_rules.check_block_public_access(good_bucket(public_access_block=None))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(result["evidence"]["flags_off"]), 4)

    def test_account_setting_covers_the_bucket(self):
        bucket = good_bucket(public_access_block=None)
        result = s3_rules.check_block_public_access(bucket, account_block=ALL_ON)
        self.assertEqual(result["status"], "pass")

    def test_unreadable_setting_is_incomplete(self):
        bucket = good_bucket(errors={"public_access_block": "AccessDenied"})
        self.assertEqual(s3_rules.check_block_public_access(bucket)["status"], "incomplete")


class WildcardPrincipalTests(unittest.TestCase):
    def public_read(self, **extra):
        statement = {"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
                     "Action": "s3:GetObject", "Resource": BUCKET_ARN + "/*"}
        statement.update(extra)
        return statement

    def test_star_principal_fails(self):
        bucket = good_bucket(policy=policy(self.public_read()))
        result = s3_rules.check_wildcard_principal(bucket)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["evidence"]["statements"][0]["sid"], "PublicRead")

    def test_aws_star_principal_fails(self):
        bucket = good_bucket(policy=policy(self.public_read(Principal={"AWS": ["*"]})))
        self.assertEqual(s3_rules.check_wildcard_principal(bucket)["status"], "fail")

    def test_not_principal_allow_fails(self):
        statement = self.public_read(NotPrincipal={"AWS": "arn:aws:iam::123456789012:root"})
        del statement["Principal"]
        bucket = good_bucket(policy=policy(statement))
        self.assertEqual(s3_rules.check_wildcard_principal(bucket)["status"], "fail")

    def test_condition_restricts_it(self):
        condition = {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}
        bucket = good_bucket(policy=policy(self.public_read(Condition=condition)))
        self.assertEqual(s3_rules.check_wildcard_principal(bucket)["status"], "pass")

    def test_empty_condition_does_not_restrict_it(self):
        bucket = good_bucket(policy=policy(self.public_read(Condition={})))
        self.assertEqual(s3_rules.check_wildcard_principal(bucket)["status"], "fail")

    def test_named_principal_passes(self):
        principal = {"AWS": "arn:aws:iam::123456789012:user/alice"}
        bucket = good_bucket(policy=policy(self.public_read(Principal=principal)))
        self.assertEqual(s3_rules.check_wildcard_principal(bucket)["status"], "pass")

    def test_deny_with_star_principal_passes(self):
        # the HTTPS statement is a Deny for "*" and shouldn't count
        self.assertEqual(s3_rules.check_wildcard_principal(good_bucket())["status"], "pass")

    def test_no_policy_passes(self):
        self.assertEqual(s3_rules.check_wildcard_principal(good_bucket(policy=None))["status"], "pass")

    def test_policy_as_json_string(self):
        bucket = good_bucket(policy=json.dumps(policy(self.public_read())))
        self.assertEqual(s3_rules.check_wildcard_principal(bucket)["status"], "fail")

    def test_unreadable_policy_is_incomplete(self):
        bucket = good_bucket(errors={"policy": "AccessDenied"})
        self.assertEqual(s3_rules.check_wildcard_principal(bucket)["status"], "incomplete")


class VersioningTests(unittest.TestCase):
    def test_enabled_passes(self):
        self.assertEqual(s3_rules.check_versioning(good_bucket())["status"], "pass")

    def test_suspended_fails(self):
        result = s3_rules.check_versioning(good_bucket(versioning={"Status": "Suspended"}))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["evidence"]["versioning_status"], "Suspended")

    def test_never_enabled_fails(self):
        # AWS leaves Status out when versioning was never turned on
        result = s3_rules.check_versioning(good_bucket(versioning={}))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["evidence"]["versioning_status"], "Never enabled")

    def test_unreadable_versioning_is_incomplete(self):
        bucket = good_bucket(errors={"versioning": "AccessDenied"})
        self.assertEqual(s3_rules.check_versioning(bucket)["status"], "incomplete")

    def test_not_collected_is_incomplete(self):
        bucket = good_bucket()
        del bucket["versioning"]
        result = s3_rules.check_versioning(bucket)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("not collected", result["reason"])


class HttpsOnlyTests(unittest.TestCase):
    def https_statement(self, **changes):
        statement = dict(HTTPS_ONLY_STATEMENT)
        statement.update(changes)
        return statement

    def test_deny_insecure_transport_passes(self):
        self.assertEqual(s3_rules.check_https_only(good_bucket())["status"], "pass")

    def test_no_policy_fails(self):
        self.assertEqual(s3_rules.check_https_only(good_bucket(policy=None))["status"], "fail")

    def test_policy_without_https_statement_fails(self):
        read_only = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                     "Action": "s3:GetObject", "Resource": BUCKET_ARN + "/*"}
        self.assertEqual(s3_rules.check_https_only(good_bucket(policy=policy(read_only)))["status"], "fail")

    def test_condition_true_does_not_count(self):
        condition = {"Bool": {"aws:SecureTransport": "true"}}
        bucket = good_bucket(policy=policy(self.https_statement(Condition=condition)))
        self.assertEqual(s3_rules.check_https_only(bucket)["status"], "fail")

    def test_allow_instead_of_deny_does_not_count(self):
        bucket = good_bucket(policy=policy(self.https_statement(Effect="Allow")))
        self.assertEqual(s3_rules.check_https_only(bucket)["status"], "fail")

    def test_only_some_actions_does_not_count(self):
        bucket = good_bucket(policy=policy(self.https_statement(Action="s3:PutObject")))
        self.assertEqual(s3_rules.check_https_only(bucket)["status"], "fail")

    def test_bucket_arn_only_does_not_cover_objects(self):
        bucket = good_bucket(policy=policy(self.https_statement(Resource=BUCKET_ARN)))
        self.assertEqual(s3_rules.check_https_only(bucket)["status"], "fail")

    def test_boolean_false_and_key_case(self):
        condition = {"BoolIfExists": {"AWS:SecureTransport": False}}
        bucket = good_bucket(policy=policy(self.https_statement(Condition=condition)))
        self.assertEqual(s3_rules.check_https_only(bucket)["status"], "pass")

    def test_unreadable_policy_is_incomplete(self):
        bucket = good_bucket(errors={"policy": "AccessDenied"})
        self.assertEqual(s3_rules.check_https_only(bucket)["status"], "incomplete")


try:
    import boto3
    from moto import mock_aws
except ImportError:
    mock_aws = None


@unittest.skipIf(mock_aws is None, "moto isn't installed")
class RealResponseShapeTests(unittest.TestCase):
    """Runs the rules on real boto3 responses from moto's fake AWS, to make
    sure the rules read the same shapes the collector will get."""

    def collect(self, s3, name):
        # a stand-in for Martin's collector (E-2 S-3-1), just enough for this test
        bucket = {"name": name, "errors": {},
                  "acl": s3.get_bucket_acl(Bucket=name),
                  "versioning": s3.get_bucket_versioning(Bucket=name)}
        try:
            bucket["public_access_block"] = s3.get_public_access_block(
                Bucket=name)["PublicAccessBlockConfiguration"]
        except s3.exceptions.ClientError:
            bucket["public_access_block"] = None
        try:
            bucket["policy"] = s3.get_bucket_policy(Bucket=name)["Policy"]
        except s3.exceptions.ClientError:
            bucket["policy"] = None
        return bucket

    def statuses(self, bucket):
        return {r["rule_id"]: r["status"] for r in s3_rules.check_bucket(bucket)}

    def test_bad_and_good_buckets(self):
        with mock_aws():
            s3 = boto3.client("s3", region_name="us-east-1", aws_access_key_id="testing",
                              aws_secret_access_key="testing")

            s3.create_bucket(Bucket="bad-bucket")
            s3.put_public_access_block(Bucket="bad-bucket", PublicAccessBlockConfiguration={
                flag: False for flag in s3_rules.BLOCK_PUBLIC_ACCESS_FLAGS})
            s3.put_bucket_acl(Bucket="bad-bucket", ACL="public-read")
            s3.put_bucket_versioning(Bucket="bad-bucket",
                                     VersioningConfiguration={"Status": "Suspended"})
            s3.put_bucket_policy(Bucket="bad-bucket", Policy=json.dumps(policy({
                "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bad-bucket/*"})))

            s3.create_bucket(Bucket="good-bucket")
            s3.put_public_access_block(Bucket="good-bucket", PublicAccessBlockConfiguration=ALL_ON)
            s3.put_bucket_versioning(Bucket="good-bucket",
                                     VersioningConfiguration={"Status": "Enabled"})
            https = dict(HTTPS_ONLY_STATEMENT, Resource=["arn:aws:s3:::good-bucket",
                                                         "arn:aws:s3:::good-bucket/*"])
            s3.put_bucket_policy(Bucket="good-bucket", Policy=json.dumps(policy(https)))

            bad = self.statuses(self.collect(s3, "bad-bucket"))
            good = self.statuses(self.collect(s3, "good-bucket"))

        self.assertEqual(set(bad.values()), {"fail"}, bad)
        self.assertEqual(set(good.values()), {"pass"}, good)


if __name__ == "__main__":
    unittest.main()
