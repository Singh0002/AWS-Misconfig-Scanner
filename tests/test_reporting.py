"""5.2 Reporting tests (FR-REP-1, OUT-1 to OUT-8, NFR-SEC-1).

The report has to match the scan it came from, new or loaded, and cover
findings, no findings, incomplete checks and unavailable explanations.
Anything from AWS or the AI that looks like HTML has to show up as text.
"""

import os
import tempfile
import unittest

import coordinator
import results
from fakes import DUMMY_SECRET, FakeAWS, FakeSession, bad_bucket, bad_user, sample_scan
from report.html_report import build_report
from storage import db


class ReportContentTests(unittest.TestCase):
    def test_report_has_the_scan_details_and_findings(self):
        scan = sample_scan()
        report = build_report(scan)
        for text in ["123456789012", scan["metadata"]["scan_time"][:10], "S3, IAM",
                     "public-bucket", "Bucket ACL grants access to everyone", "High",
                     "User has no MFA device", "alice"]:
            self.assertIn(text, report)

    def test_report_has_explanations_and_unavailable_ones_say_so(self):
        report = build_report(sample_scan())
        self.assertIn("Anyone on the internet can read it.", report)
        self.assertIn("Remove the All Users grant", report)
        # alice's explanation is unavailable, so a message shows instead
        self.assertIn("No AI explanation for this finding", report.split("(alice)")[-1])

    def test_report_lists_incomplete_checks_and_errors(self):
        report = build_report(sample_scan())
        self.assertIn("Couldn&#x27;t read the bucket policy (AccessDenied).", report)
        self.assertIn("get_bucket_policy", report)

    def test_report_with_no_findings(self):
        scan = results.new_scan(["S3"], "123456789012")
        report = build_report(scan)
        self.assertIn("The selected checks found no issues.", report)

    def test_report_matches_the_scan_after_it_is_saved_and_loaded(self):
        scan = sample_scan()
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "test.db")
            db.init_db(path)
            db.save_scan(scan, path)
            loaded, error = db.load_scan(scan["metadata"]["scan_id"], path)
        self.assertEqual(build_report(loaded), build_report(scan))


class ReportSafetyTests(unittest.TestCase):
    def test_html_in_names_and_ai_text_is_escaped(self):
        scan = sample_scan(resource="<script>alert(1)</script>",
                           explanation_text='<img src=x onerror="alert(2)">')
        report = build_report(scan)
        self.assertNotIn("<script>", report)
        self.assertNotIn("<img", report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report)

    def test_no_secrets_in_the_report(self):
        aws = FakeAWS(buckets=[bad_bucket("b1")], users=[bad_user("u1")],
                      fail={"get_bucket_policy": "AccessDenied"})
        scan = coordinator.run_scan(["S3", "IAM"], None, lambda *args: None, FakeSession(aws))
        report = build_report(scan)
        self.assertIn("AccessDenied", report)
        self.assertNotIn(DUMMY_SECRET, report)
        for key in aws.users["u1"]["keys"]:
            self.assertNotIn(key["AccessKeyId"], report)


class DownloadButtonTests(unittest.TestCase):
    """The Download report button on the Results tab (FR-REP-1)."""

    def setUp(self):
        from unittest import mock

        import streamlit as st
        from streamlit.testing.v1 import AppTest

        st.cache_resource.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"CLOUDGUARDIAN_DB": os.path.join(self.tmp.name, "test.db")})
        self.env.start()
        self.at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"),
                                    default_timeout=30)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def button(self):
        return [b for b in self.at.get("download_button") if b.proto.label == "Download report"][0]

    def test_button_gives_an_html_file_when_a_scan_is_open(self):
        self.at.session_state.scan = sample_scan()
        self.at.run()
        self.assertFalse(self.at.exception)
        self.assertFalse(self.button().proto.disabled)
        self.assertTrue(self.button().proto.url.endswith(".html"))

    def test_button_is_off_with_no_scan(self):
        self.at.run()
        self.assertTrue(self.button().proto.disabled)

    def test_file_name_has_the_scan_time(self):
        from report.html_report import report_file_name

        scan = sample_scan()
        scan["metadata"]["scan_time"] = "2026-11-01T14:30:00+00:00"
        self.assertEqual(report_file_name(scan), "cloudguardian-report-2026-11-01-1430.html")


if __name__ == "__main__":
    unittest.main()
