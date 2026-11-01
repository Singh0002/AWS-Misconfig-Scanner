"""5.3 Live integration tests against the real AWS test account and Anthropic.

These are skipped unless you turn them on, because they need real
credentials and the AI one costs a little money:

    set CLOUDGUARDIAN_LIVE=1                  # Windows (cmd)
    $env:CLOUDGUARDIAN_LIVE="1"               # Windows (PowerShell)
    export CLOUDGUARDIAN_LIVE=1               # Ubuntu
    python -m unittest discover tests -p "test_live.py"

Use the read-only test account from Setup. The AI test also needs
ANTHROPIC_API_KEY set.
"""

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
