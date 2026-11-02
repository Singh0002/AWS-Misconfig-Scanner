"""5.3 Integration tests.

These connect the real modules: collectors -> rules -> storage -> AI ->
report, using the fake AWS account and fake AI. A known misconfiguration
is followed through every step. Then the failure cases: an unreadable
resource, an AI outage and a database that can't be written. The page
tests run the real app.py.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

import anthropic
import boto3
import httpx2

import coordinator
from ai import client as ai_client
from fakes import FakeAI, FakeAWS, FakeSession, bad_bucket, bad_user, good_bucket, good_user
from report.html_report import build_report
from storage import db

APP = os.path.join(os.path.dirname(__file__), "..", "app.py")
REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def scan_account(aws, services=("S3", "IAM")):
    return coordinator.run_scan(list(services), None, lambda *args: None, FakeSession(aws))


def explain(scan, fake):
    with mock.patch("anthropic.Anthropic", return_value=fake):
        return ai_client.explain_scan(scan, api_key="sk-ant-dummy-key")


def finding_for(scan, rule_id):
    for finding in scan["findings"]:
        if finding["check_id"].split("/")[2] == rule_id:
            return finding


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "test.db")
        db.init_db(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def full_workflow(self, aws, services=("S3", "IAM"), fake_ai=None):
        """Scan, save, explain, save the explanations, then load it back."""
        scan = scan_account(aws, services)
        ok, error = db.save_scan(scan, self.path)
        self.assertTrue(ok, error)
        if scan["findings"]:
            scan["explanations"] = explain(scan, fake_ai or FakeAI())
            db.save_explanations(scan["metadata"]["scan_id"], scan["explanations"], self.path)
        loaded, error = db.load_scan(scan["metadata"]["scan_id"], self.path)
        self.assertIsNone(error)
        return scan, loaded

    def test_a_public_bucket_is_followed_through_every_step(self):
        aws = FakeAWS(buckets=[bad_bucket("open-bucket"), good_bucket("safe-bucket")])
        scan, loaded = self.full_workflow(aws, ["S3"])

        finding = finding_for(scan, "s3_public_acl")
        self.assertIn("/open-bucket/", finding["finding_id"])
        self.assertEqual((finding["issue"], finding["severity"]), ("Bucket ACL grants access to everyone", "High"))
        # same finding after saving and loading, with its explanation
        self.assertEqual(finding_for(loaded, "s3_public_acl"), finding)
        explanation = [e for e in loaded["explanations"] if e["finding_id"] == finding["finding_id"]][0]
        self.assertEqual(explanation["explanation_status"], "available")
        # and in the report
        report = build_report(loaded)
        self.assertIn("open-bucket", report)
        self.assertIn("Bucket ACL grants access to everyone", report)
        self.assertIn("Anyone could get in.", report)
        # the safe bucket passed everything and has no findings
        self.assertNotIn("/safe-bucket/", json.dumps(scan["findings"]))

    def test_s3_only_iam_only_and_both(self):
        aws = FakeAWS(buckets=[bad_bucket("b1")], users=[bad_user("u1")])
        for services in [["S3"], ["IAM"], ["S3", "IAM"]]:
            with self.subTest(services):
                scan, loaded = self.full_workflow(aws, services)
                self.assertEqual({c["service"] for c in loaded["checks"]}, set(services))
                self.assertEqual(loaded["findings"], scan["findings"])

    def test_empty_account(self):
        scan, loaded = self.full_workflow(FakeAWS(), ["S3"])
        self.assertEqual(loaded["checks"], [])
        self.assertIn("The selected checks found no issues.", build_report(loaded))

    def test_scan_with_no_failed_checks(self):
        aws = FakeAWS(buckets=[good_bucket("b1")], users=[good_user("u1")])
        fake_ai = FakeAI()
        scan, loaded = self.full_workflow(aws, fake_ai=fake_ai)
        self.assertEqual(loaded["findings"], [])
        self.assertEqual({c["status"] for c in loaded["checks"]}, {"pass"})
        self.assertEqual(fake_ai.requests, [])

    def test_unreadable_resource_stays_incomplete_everywhere(self):
        aws = FakeAWS(buckets=[bad_bucket("b1")], fail={"get_bucket_policy": "AccessDenied"})
        scan, loaded = self.full_workflow(aws, ["S3"])
        statuses = {c["rule_id"]: c["status"] for c in loaded["checks"]}
        self.assertEqual(statuses["s3_https_only"], "incomplete")
        self.assertEqual(statuses["s3_wildcard_principal"], "incomplete")
        # the rules that could still run did
        self.assertEqual(statuses["s3_public_acl"], "fail")
        self.assertEqual(loaded["metadata"]["coverage_status"], "incomplete")
        self.assertIn("Incomplete checks and errors", build_report(loaded))
        self.assertIn("get_bucket_policy", build_report(loaded))

    def test_ai_outage_keeps_the_findings(self):
        aws = FakeAWS(buckets=[bad_bucket("b1")])
        outage = FakeAI(error=anthropic.APIConnectionError(request=REQUEST))
        scan, loaded = self.full_workflow(aws, ["S3"], outage)
        self.assertEqual(len(loaded["findings"]), 5)
        self.assertEqual({e["explanation_status"] for e in loaded["explanations"]}, {"unavailable"})

    def test_saved_scan_reopens_without_aws_or_ai(self):
        scan, loaded = self.full_workflow(FakeAWS(buckets=[bad_bucket("b1")]), ["S3"])
        # after a "restart", nothing may call AWS or the AI again
        with mock.patch.object(coordinator, "run_scan", side_effect=AssertionError("AWS was called")), \
                mock.patch("anthropic.Anthropic", side_effect=AssertionError("AI was called")):
            reopened, error = db.load_scan(scan["metadata"]["scan_id"], self.path)
            self.assertEqual(build_report(reopened), build_report(loaded))

    def test_whole_workflow_only_reads_and_never_runs_a_fix(self):
        aws = FakeAWS(buckets=[bad_bucket("b1")], users=[bad_user("u1")])
        fake_ai = FakeAI()
        self.full_workflow(aws, fake_ai=fake_ai)
        for call in aws.calls:
            self.assertTrue(call.startswith(("get_", "list_")), call)
        # the AI gets no tools, so its steps are only text for the user
        for request in fake_ai.requests:
            self.assertNotIn("tools", request)

    def test_aws_and_anthropic_requests_use_https(self):
        session = boto3.Session(aws_access_key_id="dummy", aws_secret_access_key="dummy", region_name="us-east-1")
        for service in ["sts", "s3", "s3control", "iam"]:
            self.assertTrue(session.client(service).meta.endpoint_url.startswith("https://"), service)
        self.assertTrue(str(anthropic.Anthropic(api_key="dummy").base_url).startswith("https://"))


class AppWorkflowTests(unittest.TestCase):
    """The same failure cases through the real page."""

    def setUp(self):
        import streamlit as st
        from streamlit.testing.v1 import AppTest

        # the app only makes its tables once per run of Python, so make it redo
        # that for this test's new database
        st.cache_resource.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "test.db")
        self.env = mock.patch.dict(os.environ, {"CLOUDGUARDIAN_DB": self.path,
                                                "ANTHROPIC_API_KEY": "sk-ant-dummy-key"})
        self.env.start()
        self.at = AppTest.from_file(APP, default_timeout=30)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def run_scan_on_page(self, aws, fake_ai=None):
        with mock.patch.object(coordinator, "make_session", return_value=FakeSession(aws)), \
                mock.patch("anthropic.Anthropic", return_value=fake_ai or FakeAI()):
            self.at.run()
            [b for b in self.at.button if b.label == "Start scan"][0].click().run()

    def download_button(self):
        return self.at.get("download_button")[0]

    def test_ai_outage_on_the_page(self):
        outage = FakeAI(error=anthropic.APIConnectionError(request=REQUEST))
        self.run_scan_on_page(FakeAWS(buckets=[bad_bucket("b1")]), outage)
        self.assertIn("have no explanation", self.at.warning[0].value)
        self.assertEqual(len(self.at.session_state.scan["findings"]), 5)
        scans, error = db.list_scans()
        self.assertEqual(len(scans), 1)
        self.assertFalse(self.download_button().proto.disabled)

    def test_failed_save_is_reported_and_results_stay(self):
        failed = (False, {"stage": "storage", "operation": "save_scan", "resource_id": None,
                          "message": "database is locked"})
        with mock.patch.object(db, "save_scan", return_value=failed):
            self.run_scan_on_page(FakeAWS(buckets=[bad_bucket("b1")]))
        self.assertIn("couldn't be saved", self.at.warning[0].value)
        self.assertEqual(len(self.at.session_state.scan["findings"]), 5)
        # the report can still be downloaded
        self.assertFalse(self.download_button().proto.disabled)

    def test_saved_scan_opens_on_the_page_without_scanning(self):
        self.run_scan_on_page(FakeAWS(buckets=[bad_bucket("b1")]))
        scan_id = self.at.session_state.scan["metadata"]["scan_id"]

        # a fresh page, like reopening the app later
        from streamlit.testing.v1 import AppTest
        self.at = AppTest.from_file(APP, default_timeout=30)
        with mock.patch.object(coordinator, "run_scan", side_effect=AssertionError("AWS was called")), \
                mock.patch("anthropic.Anthropic", side_effect=AssertionError("AI was called")):
            self.at.run()
            [s for s in self.at.selectbox if s.label == "Scan"][0].select_index(0).run()
            [b for b in self.at.button if b.label == "Open"][0].click().run()
        self.assertEqual(self.at.session_state.scan["metadata"]["scan_id"], scan_id)
        self.assertEqual(len(self.at.session_state.scan["findings"]), 5)
        self.assertFalse(self.download_button().proto.disabled)


if __name__ == "__main__":
    unittest.main()
