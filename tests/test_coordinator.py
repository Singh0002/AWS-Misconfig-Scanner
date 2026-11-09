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
from fakes import ACCOUNT_ID, DUMMY_SECRET, FakeAWS, FakeSession, bad_bucket, bad_user, sample_scan
from test_connection import check_ai_key, check_aws_credentials, check_iam_access, check_s3_access, run_all

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


class SetupCheckTests(unittest.TestCase):
    """test_connection.py (SCAN-6, NFR-SEC-4): clear setup messages that never show a key.

    FakeAWS puts DUMMY_SECRET in every AWS error message, so these fail if a
    message ever passes AWS's text through to the user.
    """

    def check(self, check_function, error_code):
        aws = FakeAWS(fail={"get_caller_identity": error_code, "list_buckets": error_code,
                            "list_users": error_code})
        ok, message = check_function(FakeSession(aws))
        self.assertFalse(ok)
        self.assertNotIn(DUMMY_SECRET, message)
        return message

    def test_working_credentials_show_only_the_account_id(self):
        ok, message = check_aws_credentials(FakeSession(FakeAWS()))
        self.assertTrue(ok)
        self.assertIn("123456789012", message)

    def test_expired_or_wrong_credentials(self):
        for code in ["ExpiredToken", "InvalidClientTokenId", "SignatureDoesNotMatch"]:
            with self.subTest(code):
                self.assertIn("rejected the credentials", self.check(check_aws_credentials, code))

    def test_denied_s3_and_iam_access(self):
        self.assertIn("Access denied", self.check(check_s3_access, "AccessDenied"))
        self.assertIn("Access denied", self.check(check_iam_access, "AccessDenied"))

    def test_working_s3_and_iam_access(self):
        aws = FakeAWS(buckets=[bad_bucket("b1")], users=[bad_user("u1")])
        self.assertEqual(check_s3_access(FakeSession(aws)), (True, "S3 read access works (1 bucket(s))."))
        self.assertTrue(check_iam_access(FakeSession(aws))[0])

    def test_failed_credentials_skip_the_s3_and_iam_checks(self):
        aws = FakeAWS(fail={"get_caller_identity": "ExpiredToken"})
        with mock.patch("test_connection.make_session", return_value=FakeSession(aws)):
            names = [name for name, ok, message in run_all()]
        self.assertEqual(names, ["AWS credentials", "AI key"])
        self.assertNotIn("list_buckets", aws.calls)

    def test_no_ai_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            ok, message = check_ai_key()
        self.assertFalse(ok)
        self.assertIn("ANTHROPIC_API_KEY", message)

    def test_ai_key_set_without_a_request_never_calls_the_api(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"}, clear=True):
            with mock.patch("anthropic.Anthropic") as client:
                ok, message = check_ai_key(make_request=False)
        self.assertTrue(ok)
        client.assert_not_called()
        self.assertNotIn("sk-ant-test-not-real", message)

    def test_rejected_ai_key_message_never_shows_the_key(self):
        import anthropic
        import httpx2

        response = httpx2.Response(401, request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))
        error = anthropic.AuthenticationError("bad key sk-ant-test-not-real", response=response, body=None)
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"}, clear=True):
            with mock.patch("anthropic.Anthropic") as client:
                client.return_value.messages.create.side_effect = error
                ok, message = check_ai_key(make_request=True)
        self.assertFalse(ok)
        self.assertIn("rejected", message)
        self.assertNotIn("sk-ant-test-not-real", message)


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
        self.assertIn("aws configure", self.at.error[0].value)
        self.assertIn("Nothing in AWS was changed", self.at.error[0].value)
        self.assertFalse(self.start_button().disabled)


class SettingsPageTests(unittest.TestCase):
    """The Check connection button on the Settings tab (SCAN-6, NFR-SEC-4)."""

    def setUp(self):
        import streamlit as st
        from streamlit.testing.v1 import AppTest

        st.cache_resource.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"CLOUDGUARDIAN_DB": os.path.join(self.tmp.name, "test.db")})
        self.env.start()
        self.at = AppTest.from_file(APP, default_timeout=30)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def click_check(self, aws):
        with mock.patch.object(coordinator, "make_session", return_value=FakeSession(aws)):
            self.at.run()
            [b for b in self.at.button if b.label == "Check connection"][0].click().run()

    def header(self):
        return "\n".join(m.value for m in self.at.markdown)

    def test_working_connection_shows_each_check_and_the_short_account(self):
        aws = FakeAWS(buckets=[bad_bucket("b1")])
        self.click_check(aws)
        messages = [s.value for s in self.at.success]
        self.assertEqual(len(messages), 3)
        self.assertIn("S3 read access works", messages[1])
        self.assertIn("IAM read access works", messages[2])
        # the account number is shortened everywhere on the page
        self.assertIn("AWS ••••" + ACCOUNT_ID[-4:], self.header())
        self.assertNotIn(ACCOUNT_ID, self.header() + "\n".join(messages))
        # only read calls were made
        for call in aws.calls:
            self.assertTrue(call.startswith(("get_", "list_")), call)

    def test_missing_credentials_say_what_to_fix_without_any_key(self):
        self.click_check(FakeAWS(fail={"get_caller_identity": NoCredentialsError()}))
        self.assertIn("No AWS credentials found", self.at.error[0].value)
        self.assertIn("AWS not connected", self.header())
        self.assertNotIn(DUMMY_SECRET, self.header() + self.at.error[0].value)


def mixed_scan():
    """sample_scan() plus a Medium S3 finding, so there's something to filter."""
    scan = sample_scan()
    check = results.make_check(scan["metadata"]["scan_id"], "S3", "old-bucket", "s3_versioning", "fail",
                               {"versioning_status": "Suspended"})
    scan["checks"].append(check)
    scan["findings"].append(results.make_finding(check, "Versioning is not enabled", "Medium"))
    return scan


class ResultsPageTests(unittest.TestCase):
    """The Results tab in the real app (FR-UI-2): filters and the finding details panel."""

    def setUp(self):
        import streamlit as st
        from streamlit.testing.v1 import AppTest

        st.cache_resource.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"CLOUDGUARDIAN_DB": os.path.join(self.tmp.name, "test.db")})
        self.env.start()
        self.at = AppTest.from_file(APP, default_timeout=30)
        self.at.session_state.scan = mixed_scan()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def shown(self):
        """(severity, resource) for each finding listed, from the headings that open them."""
        listed = []
        for section in self.at.expander:
            if "-badge[" in section.label:
                severity = section.label.split("-badge[")[1].split("]")[0]
                resource = section.label.split("`")[1]
                listed.append((severity, resource))
        return listed

    def counts(self):
        return {m.label.split("[")[-1].rstrip("]"): m.value for m in self.at.metric}

    def page_text(self):
        return "\n".join([m.value for m in self.at.markdown] + [t.value for t in self.at.text]
                         + [i.value for i in self.at.info] + [c.value for c in self.at.caption]
                         + [c.value for c in self.at.code])

    def test_findings_show_most_severe_first(self):
        self.at.run()
        self.assertFalse(self.at.exception)
        self.assertEqual([severity for severity, _ in self.shown()], ["High", "High", "Medium"])

    def test_service_filter(self):
        self.at.session_state.filters = ["IAM", "High", "Medium", "Low"]
        self.at.run()
        self.assertEqual([resource for _, resource in self.shown()], ["alice"])

    def test_severity_filter_changes_the_list_but_not_the_counts(self):
        self.at.session_state.filters = ["S3", "IAM", "Medium"]
        self.at.run()
        self.assertEqual([resource for _, resource in self.shown()], ["old-bucket"])
        counts = self.counts()
        self.assertEqual((counts["High"], counts["Medium"], counts["Low"]), ("2", "1", "0"))

    def test_filters_that_match_nothing_say_so(self):
        self.at.session_state.filters = ["IAM", "Low"]
        self.at.run()
        self.assertIn("No findings match the filters.", self.page_text())

    def test_details_panel_shows_the_finding_and_its_explanation(self):
        self.at.run()
        # the most severe finding is listed first and starts open
        first = [e for e in self.at.expander if "-badge[" in e.label][0]
        self.assertIn("public-bucket", first.label)
        self.assertIn("Bucket ACL grants access to everyone", first.label)
        page = self.page_text()
        self.assertIn("Public grants: group All Users, permission READ", page)
        self.assertIn("Anyone on the internet can read it.", page)
        self.assertIn("1. Remove the All Users grant", page)

    def test_details_panel_says_when_there_is_no_explanation(self):
        scan = mixed_scan()
        scan["explanations"] = []
        self.at.session_state.scan = scan
        self.at.run()
        self.assertFalse(self.at.exception)
        self.assertIn("No AI explanation for this finding.", self.page_text())


if __name__ == "__main__":
    unittest.main()
