"""Tests for turning collector records into checks and findings.

E-2 S-4-5: versioning and HTTPS with passing, failing and missing settings.
E-3 S-5-6: the three IAM rules, including policy conditions.
E-2 S-3-5, E-2 S-4-4, E-3 S-5-5: findings and incomplete checks come out right.

The records here have the same shape the collectors return.
"""

import unittest

import results
from detection import findings

HTTPS_ONLY = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*",
                             "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
ADMIN = {"Effect": "Allow", "Action": "*", "Resource": "*"}
READ_ONLY = {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}
FAILED = {"status": "failed", "value": None}


def ok(value):
    return {"status": "available", "value": value}


def scan_bucket(errors=None, **changes):
    """Checks a bucket that passes all five S3 rules. Keyword arguments break one."""
    record = {"service": "S3", "resource_id": "b", "acl": ok({"Grants": []}), "policy": ok(HTTPS_ONLY),
              "public_access_block": ok({"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                         "BlockPublicPolicy": True, "RestrictPublicBuckets": True}),
              "versioning": ok({"Status": "Enabled"})}
    record.update(changes)
    scan = results.new_scan(["S3"])
    findings.check_s3(scan, {"records": [record], "errors": errors or []})
    return scan


def scan_user(mfa_enabled=1, **changes):
    """Checks a user that passes both user rules. Keyword arguments break one."""
    record = {"service": "IAM", "resource_id": "alice", "attached_policies": ok([]),
              "inline_policies": ok([{"name": "ReadS3", "document": READ_ONLY}]),
              "mfa_devices": ok({"DeviceCount": 1})}
    record.update(changes)
    scan = results.new_scan(["IAM"])
    findings.check_iam(scan, {"records": [record], "errors": []}, None, {"AccountMFAEnabled": mfa_enabled})
    return scan


def status(scan, rule_id):
    for check in scan["checks"]:
        if check["rule_id"] == rule_id:
            return check["status"]


class S3Tests(unittest.TestCase):
    def test_versioning(self):
        self.assertEqual(status(scan_bucket(), "s3_versioning"), "pass")
        self.assertEqual(status(scan_bucket(versioning=ok({"Status": "Suspended"})), "s3_versioning"), "fail")
        # the collector gives Status None when versioning was never turned on
        self.assertEqual(status(scan_bucket(versioning=ok({"Status": None})), "s3_versioning"), "fail")
        self.assertEqual(status(scan_bucket(versioning=FAILED), "s3_versioning"), "incomplete")

    def test_https(self):
        self.assertEqual(status(scan_bucket(), "s3_https_only"), "pass")
        self.assertEqual(status(scan_bucket(policy={"status": "missing", "value": None}), "s3_https_only"), "fail")
        self.assertEqual(status(scan_bucket(policy=ok(READ_ONLY)), "s3_https_only"), "fail")

    def test_unreadable_policy_is_incomplete_with_the_error_code(self):
        errors = [{"operation": "get_bucket_policy", "resource_id": "b", "message": "AccessDenied"}]
        scan = scan_bucket(errors, policy=FAILED)
        self.assertEqual(status(scan, "s3_https_only"), "incomplete")
        self.assertIn("AccessDenied", scan["checks"][-1]["reason"])


class IamTests(unittest.TestCase):
    def test_admin_wildcard(self):
        self.assertEqual(status(scan_user(), "iam_admin_wildcard"), "pass")
        admin = ok([{"name": "AdministratorAccess", "arn": "arn", "document": {"Statement": [ADMIN]}}])
        self.assertEqual(status(scan_user(attached_policies=admin), "iam_admin_wildcard"), "fail")
        self.assertEqual(status(scan_user(attached_policies=FAILED), "iam_admin_wildcard"), "incomplete")

    def test_admin_with_condition_passes_but_is_reported(self):
        limited = dict(ADMIN, Condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}})
        scan = scan_user(inline_policies=ok([{"name": "OfficeAdmin", "document": {"Statement": [limited]}}]))
        self.assertEqual(status(scan, "iam_admin_wildcard"), "pass")
        self.assertIn("conditional_admin", scan["checks"][0]["evidence_json"])

    def test_user_mfa(self):
        self.assertEqual(status(scan_user(), "iam_user_mfa"), "pass")
        self.assertEqual(status(scan_user(mfa_devices=ok({"DeviceCount": 0})), "iam_user_mfa"), "fail")
        self.assertEqual(status(scan_user(mfa_devices=FAILED), "iam_user_mfa"), "incomplete")

    def test_root_mfa(self):
        self.assertEqual(status(scan_user(), "iam_root_mfa"), "pass")
        self.assertEqual(status(scan_user(mfa_enabled=0), "iam_root_mfa"), "fail")
        scan = results.new_scan(["IAM"])
        findings.check_iam(scan, {"records": [], "errors": []}, None, None, "AccessDenied")
        self.assertEqual(status(scan, "iam_root_mfa"), "incomplete")


class FindingsTests(unittest.TestCase):
    def test_good_bucket_has_five_checks_and_no_findings(self):
        scan = scan_bucket()
        self.assertEqual(len(scan["checks"]), 5)
        self.assertEqual(scan["findings"], [])
        self.assertEqual(scan["metadata"]["coverage_status"], "complete")

    def test_fail_gets_a_finding_with_issue_and_severity(self):
        finding = scan_bucket(versioning=ok({"Status": "Suspended"}))["findings"][0]
        self.assertEqual((finding["issue"], finding["severity"]), ("Versioning is not enabled", "Medium"))

    def test_incomplete_has_no_finding_and_marks_coverage(self):
        scan = scan_bucket(acl=FAILED)
        self.assertEqual(scan["findings"], [])
        self.assertEqual(scan["metadata"]["coverage_status"], "incomplete")

    def test_collector_errors_are_saved_on_the_scan(self):
        scan = results.new_scan(["S3"])
        error = {"operation": "list_buckets", "resource_id": None, "message": "AccessDenied"}
        findings.check_s3(scan, {"records": [], "errors": [error]})
        self.assertEqual(scan["errors"][0]["stage"], "collection")
        self.assertEqual(scan["metadata"]["coverage_status"], "incomplete")

    def test_only_selected_rules_run(self):
        scan = results.new_scan(["IAM"])
        findings.check_iam(scan, {"records": [], "errors": []}, ["iam_user_mfa"])
        self.assertEqual(scan["checks"], [])


if __name__ == "__main__":
    unittest.main()
