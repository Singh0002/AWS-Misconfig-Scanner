"""Tests against a real AWS account and the Anthropic API.
Set CLOUDGUARDIAN_LIVE=1 to run these tests."""

import os
import time
import unittest

import coordinator
import results
from ai import client as ai_client
from report.html_report import build_report

LIVE = os.environ.get("CLOUDGUARDIAN_LIVE") == "1"


@unittest.skipUnless(LIVE, "set CLOUDGUARDIAN_LIVE=1 to run against the real test account")
class LiveTests(unittest.TestCase):
    def test_real_scan_finishes_within_5_minutes(self):
        start = time.time()
        scan = coordinator.run_scan(["S3", "IAM"], None, lambda *args: None)
        seconds = time.time() - start
        print(f"\nScanned {len(scan['checks'])} checks in {seconds:.1f} seconds, "
              f"{len(scan['findings'])} findings, {len(scan['errors'])} errors")
        self.assertEqual(scan["metadata"]["scan_status"], "completed")
        self.assertLess(seconds, 5 * 60)
        self.assertIn("<!DOCTYPE html>", build_report(scan))

    @unittest.skipUnless(os.environ.get("ANTHROPIC_API_KEY"), "ANTHROPIC_API_KEY isn't set")
    def test_real_explanation_for_a_known_finding(self):
        scan = results.new_scan(["S3"])
        check = results.make_check(scan["metadata"]["scan_id"], "S3", "test-bucket", "s3_versioning", "fail",
                                   {"versioning_status": "Suspended"})
        scan["checks"].append(check)
        scan["findings"].append(results.make_finding(check, "Versioning is not enabled", "Medium"))
        # the cheapest model, this only checks that the request and reply work
        explanation = ai_client.explain_scan(scan, model="claude-haiku-5-5")[0]
        print("\n" + str(explanation["risk_explanation"]))
        self.assertEqual(explanation["explanation_status"], "available", scan["errors"])


if __name__ == "__main__":
    unittest.main()
