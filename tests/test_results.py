import json
import unittest

import results


class ResultFormatTests(unittest.TestCase):
    def setUp(self):
        self.scan = results.new_scan(["S3"])
        self.scan_id = self.scan["metadata"]["scan_id"]

    def test_new_scan(self):
        meta = self.scan["metadata"]
        self.assertEqual(meta["scan_status"], "running")
        self.assertEqual(json.loads(meta["selected_services"]), ["S3"])
        self.assertEqual(self.scan["checks"], [])

    def test_each_scan_gets_a_new_id(self):
        self.assertNotEqual(self.scan_id, results.new_scan(["S3"])["metadata"]["scan_id"])

    def test_empty_or_unknown_service_rejected(self):
        with self.assertRaises(ValueError):
            results.new_scan([])
        with self.assertRaises(ValueError):
            results.new_scan(["EC2"])

    def test_ids_are_stable(self):
        a = results.make_check(self.scan_id, "S3", "my-bucket", "s3_versioning", "fail")
        b = results.make_check(self.scan_id, "S3", "my-bucket", "s3_versioning", "fail")
        other = results.make_check(self.scan_id, "S3", "other-bucket", "s3_versioning", "fail")
        self.assertEqual(a["check_id"], b["check_id"])
        self.assertNotEqual(a["check_id"], other["check_id"])

    def test_finding_only_for_failed_check(self):
        failed = results.make_check(self.scan_id, "S3", "b", "s3_versioning", "fail")
        passed = results.make_check(self.scan_id, "S3", "b", "s3_public_acl", "pass")
        finding = results.make_finding(failed, "Versioning disabled", "Medium")
        self.assertEqual(finding["check_id"], failed["check_id"])
        with self.assertRaises(ValueError):
            results.make_finding(passed, "Nothing wrong", "Low")

    def test_bad_values_rejected(self):
        with self.assertRaises(ValueError):
            results.make_check(self.scan_id, "S3", "b", "s3_versioning", "done")
        failed = results.make_check(self.scan_id, "S3", "b", "s3_versioning", "fail")
        with self.assertRaises(ValueError):
            results.make_finding(failed, "Versioning disabled", "Critical")

    def test_json_fields(self):
        check = results.make_check(self.scan_id, "IAM", "alice", "iam_user_mfa", "fail",
                                   evidence={"mfa_devices": 0})
        self.assertEqual(json.loads(check["evidence_json"]), {"mfa_devices": 0})
        explanation = results.make_explanation("f-1", "available", "Risky.", ["Turn on MFA."])
        self.assertEqual(json.loads(explanation["recommended_steps_json"]), ["Turn on MFA."])


if __name__ == "__main__":
    unittest.main()
