"""5.2 Interface and coordinator tests (SCAN-1 to SCAN-6, FR-UI-1).

S3-only, IAM-only and combined scans, an empty selection, missing
credentials, no duplicate scans on a rerun, the running flag clearing after
an error, and a new ID for every scan. The page tests run the real app.py
with Streamlit's test runner.
"""

import os
import tempfile
import unittest
from unittest import mock

from botocore.exceptions import NoCredentialsError

import coordinator
import results
import scan_progress
from fakes import FakeAWS, FakeSession, bad_bucket, bad_user
from test_connection import check_aws_credentials

APP = os.path.join(os.path.dirname(__file__), "..", "app.py")


def run(services, aws):
    return coordinator.run_scan(services, None, lambda done, total, message: None, FakeSession(aws))


def services_checked(scan):
    return {check["service"] for check in scan["checks"]}


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.aws = FakeAWS(buckets=[bad_bucket("b1")], users=[bad_user("u1")])

    def test_s3_only_scan(self):
        scan = run(["S3"], self.aws)
        self.assertEqual(services_checked(scan), {"S3"})
        self.assertNotIn("list_users", self.aws.calls)

    def test_iam_only_scan(self):
        scan = run(["IAM"], self.aws)
        self.assertEqual(services_checked(scan), {"IAM"})
        self.assertNotIn("list_buckets", self.aws.calls)

    def test_combined_scan(self):
        scan = run(["S3", "IAM"], self.aws)
        self.assertEqual(services_checked(scan), {"S3", "IAM"})
        self.assertEqual(scan["metadata"]["scan_status"], "completed")

    def test_empty_selection_does_not_start_a_scan(self):
        with self.assertRaises(ValueError):
            run([], self.aws)
        # it stops before asking AWS for anything but who we are
        self.assertNotIn("list_buckets", self.aws.calls)
        self.assertNotIn("list_users", self.aws.calls)

    def test_missing_credentials_stop_the_scan_with_a_clear_message(self):
        aws = FakeAWS(buckets=[bad_bucket("b1")], fail={"get_caller_identity": NoCredentialsError()})
        with self.assertRaises(NoCredentialsError):
            run(["S3"], aws)
        self.assertEqual(aws.calls, ["get_caller_identity"])

        ok, message = check_aws_credentials(FakeSession(aws))
        self.assertFalse(ok)
        self.assertIn("No AWS credentials found", message)

    def test_every_scan_gets_a_new_id(self):
        first = run(["S3"], self.aws)
        second = run(["S3"], self.aws)
        self.assertNotEqual(first["metadata"]["scan_id"], second["metadata"]["scan_id"])
        self.assertTrue(second["checks"][0]["check_id"].startswith(second["metadata"]["scan_id"]))

    def test_second_scan_is_blocked_while_one_is_running(self):
        self.assertFalse(scan_progress.can_start(scan_progress.start()))
        self.assertTrue(scan_progress.can_start(scan_progress.idle()))


class ScanPageTests(unittest.TestCase):
    """The Scan tab in the real app, with a temporary database."""

    def setUp(self):
        import streamlit as st
        from streamlit.testing.v1 import AppTest

        # the app only makes its tables once per run of Python, so make it redo
        # that for this test's new database
        st.cache_resource.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"CLOUDGUARDIAN_DB": os.path.join(self.tmp.name, "test.db")})
        self.env.start()
        self.at = AppTest.from_file(APP, default_timeout=30)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def start_button(self):
        return [b for b in self.at.button if b.label == "Start scan"][0]

    def click_start(self, run_scan):
        with mock.patch.object(coordinator, "run_scan", run_scan):
            self.at.run()
            self.start_button().click().run()

    def test_empty_selection_shows_a_warning(self):
        calls = []
        with mock.patch.object(coordinator, "run_scan", lambda *args: calls.append(args)):
            self.at.run()
            for box in self.at.checkbox:
                if box.key and box.key.startswith("service_"):
                    box.uncheck()
            self.at.run()
            self.start_button().click().run()
        self.assertIn("Pick at least one", self.at.warning[0].value)
        self.assertEqual(calls, [])

    def test_rerun_does_not_start_a_duplicate_scan(self):
        calls = []

        def fake_run_scan(services, rules, on_progress):
            calls.append(services)
            return results.new_scan(services)

        self.click_start(fake_run_scan)
        # click Start once, then the page reruns a few more times on its own
        with mock.patch.object(coordinator, "run_scan", fake_run_scan):
            self.at.run()
            self.at.run()
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.at.session_state.progress["state"], scan_progress.DONE)

    def test_error_clears_the_running_flag(self):
        def broken_run_scan(services, rules, on_progress):
            raise RuntimeError("secret-account-detail")

        self.click_start(broken_run_scan)
        self.assertEqual(self.at.session_state.progress["state"], scan_progress.FAILED)
        self.assertFalse(self.start_button().disabled)
        # only the error type is shown, never the message
        self.assertIn("RuntimeError", self.at.error[0].value)
        self.assertNotIn("secret-account-detail", self.at.error[0].value)

    def test_missing_credentials_show_a_clear_error_on_the_page(self):
        aws = FakeAWS(fail={"get_caller_identity": NoCredentialsError()})
        with mock.patch.object(coordinator, "make_session", return_value=FakeSession(aws)):
            self.at.run()
            self.start_button().click().run()
        self.assertIn("NoCredentialsError", self.at.error[0].value)
        self.assertIn("Nothing in AWS was changed", self.at.error[0].value)
        self.assertFalse(self.start_button().disabled)


if __name__ == "__main__":
    unittest.main()
