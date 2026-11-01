"""Tests for the report's scan details and findings sections (E-4 S-10-2)
and for escaping text before it goes into the HTML (E-4 S-10-4)."""

import json
import unittest

import results
from report import html_report


def make_scan(resource="bad-bucket", issue="Versioning is not enabled", evidence=None):
    scan = results.new_scan(["S3", "IAM"], "123456789012")
    scan_id = scan["metadata"]["scan_id"]
    good = results.make_check(scan_id, "S3", "good-bucket", "s3_versioning", "pass")
    bad = results.make_check(scan_id, "S3", resource, "s3_versioning", "fail",
                             evidence or {"versioning_status": "Suspended"})
    admin = results.make_check(scan_id, "IAM", "admin-user", "iam_admin_wildcard", "fail")
    unread = results.make_check(scan_id, "S3", "locked-bucket", "s3_https_only", "incomplete",
                                reason="Couldn't read the bucket policy (AccessDenied).")
    scan["checks"] += [good, bad, admin, unread]
    scan["findings"].append(results.make_finding(bad, issue, "Medium"))
    scan["findings"].append(results.make_finding(admin, "Policy allows every action on every resource", "High"))
    scan["metadata"]["scan_status"] = "completed"
    return scan


class EscapeTests(unittest.TestCase):
    def test_html_characters_are_escaped(self):
        self.assertEqual(html_report.esc('<script>alert("x")</script>'),
                         "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;")

    def test_ampersand_and_single_quote(self):
        self.assertEqual(html_report.esc("Tom & Jerry's"), "Tom &amp; Jerry&#x27;s")

    def test_none_and_numbers(self):
        self.assertEqual(html_report.esc(None), "")
        self.assertEqual(html_report.esc(42), "42")


class ScanDetailsTests(unittest.TestCase):
    def test_shows_account_time_services_and_status(self):
        scan = make_scan()
        page = html_report.scan_details_html(scan)
        self.assertIn("123456789012", page)
        self.assertIn(html_report.format_time(scan["metadata"]["scan_time"]), page)
        self.assertIn("S3, IAM", page)
        self.assertIn("completed", page)

    def test_counts(self):
        counts = html_report.count_results(make_scan())
        self.assertEqual(counts, {"High": 1, "Medium": 1, "Low": 0, "Passed": 1, "Incomplete": 1})
        self.assertIn("High: 1, Medium: 1, Low: 0, Passed: 1, Incomplete: 1",
                      html_report.scan_details_html(make_scan()))

    def test_incomplete_coverage_gets_a_note(self):
        scan = make_scan()
        self.assertNotIn("never counted as passed", html_report.scan_details_html(scan))
        scan["metadata"]["coverage_status"] = "incomplete"
        self.assertIn("never counted as passed", html_report.scan_details_html(scan))

    def test_unknown_account(self):
        scan = make_scan()
        scan["metadata"]["account_id"] = None
        self.assertIn("unknown", html_report.scan_details_html(scan))


class FindingsTests(unittest.TestCase):
    def test_one_row_per_finding_most_severe_first(self):
        page = html_report.findings_html(make_scan())
        self.assertEqual(page.count('<tr class="severity-'), 2)
        self.assertLess(page.index("admin-user"), page.index("bad-bucket"))

    def test_row_has_service_resource_issue_and_evidence(self):
        page = html_report.findings_html(make_scan())
        for text in ["S3", "bad-bucket", "Versioning is not enabled", "Versioning status: Suspended"]:
            self.assertIn(text, page)

    def test_passed_and_incomplete_checks_are_not_findings(self):
        page = html_report.findings_html(make_scan())
        self.assertNotIn("good-bucket", page)
        self.assertNotIn("locked-bucket", page)

    def test_no_findings_message(self):
        scan = make_scan()
        scan["findings"] = []
        self.assertIn("found no issues", html_report.findings_html(scan))


class ReportEscapingTests(unittest.TestCase):
    """Nothing from AWS or the database can add HTML to the report."""

    ATTACK = '<img src=x onerror="alert(1)">'

    def test_resource_issue_and_evidence_are_escaped(self):
        scan = make_scan(resource=self.ATTACK, issue=self.ATTACK, evidence={"sid": self.ATTACK})
        page = html_report.findings_html(scan)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;", page)

    def test_scan_details_are_escaped(self):
        scan = make_scan()
        scan["metadata"]["account_id"] = self.ATTACK
        scan["metadata"]["selected_services"] = json.dumps([self.ATTACK])
        self.assertNotIn("<img", html_report.scan_details_html(scan))

    def test_unexpected_severity_cannot_break_the_class_attribute(self):
        scan = make_scan()
        scan["findings"][0]["severity"] = 'x" onclick="alert(1)'
        page = html_report.findings_html(scan)
        self.assertNotIn('onclick="', page)



def explained_scan(status="available"):
    """make_scan() plus an AI explanation for the High finding."""
    scan = make_scan()
    admin = scan["findings"][1]
    scan["explanations"].append(results.make_explanation(
        admin["finding_id"], status, "Anyone with this user's keys can do anything.",
        ["Remove the admin policy", "Give only the permissions the user needs"]))
    return scan


class ExplanationsSectionTests(unittest.TestCase):
    def test_available_explanation_shows_text_and_numbered_steps(self):
        page = html_report.explanations_html(explained_scan())
        self.assertIn("Anyone with this user&#x27;s keys can do anything.", page)
        self.assertIn("<ol>", page)
        self.assertIn("<li>Remove the admin policy</li>", page)

    def test_finding_without_explanation_says_so(self):
        page = html_report.explanations_html(explained_scan())
        # the Medium finding has no explanation record
        self.assertIn("No AI explanation for this finding.", page)

    def test_unavailable_explanation_says_the_rule_result_still_counts(self):
        self.assertIn("still correct", html_report.explanations_html(explained_scan("unavailable")))

    def test_ai_text_is_escaped(self):
        scan = make_scan()
        scan["explanations"].append(results.make_explanation(
            scan["findings"][0]["finding_id"], "available", "<script>alert(1)</script>", ["<b>step</b>"]))
        page = html_report.explanations_html(scan)
        self.assertNotIn("<script>", page)
        self.assertNotIn("<b>", page)

    def test_no_findings(self):
        scan = make_scan()
        scan["findings"] = []
        self.assertIn("nothing to explain", html_report.explanations_html(scan))


class IncompleteSectionTests(unittest.TestCase):
    def test_lists_incomplete_checks_with_reason(self):
        page = html_report.incomplete_html(make_scan())
        self.assertIn("locked-bucket", page)
        self.assertIn("Couldn&#x27;t read the bucket policy (AccessDenied).", page)
        self.assertIn("not counted as passed", page)

    def test_lists_scan_errors(self):
        scan = make_scan()
        scan["errors"].append(results.make_error(scan["metadata"]["scan_id"], "AI", "messages.create",
                                                 "APITimeoutError"))
        self.assertIn("APITimeoutError", html_report.incomplete_html(scan))

    def test_none(self):
        scan = make_scan()
        scan["checks"] = [c for c in scan["checks"] if c["status"] != "incomplete"]
        self.assertIn("Every selected check ran", html_report.incomplete_html(scan))


class FullReportTests(unittest.TestCase):
    def test_page_has_every_section(self):
        page = html_report.build_report(explained_scan())
        self.assertTrue(page.startswith("<!DOCTYPE html>"))
        for heading in ["Scan details", "Findings", "Explanations and fix steps",
                        "Incomplete checks and errors"]:
            self.assertIn("<h2>" + heading + "</h2>", page)

    def test_page_has_no_scripts_or_outside_links(self):
        page = html_report.build_report(explained_scan())
        self.assertNotIn("<script", page)
        self.assertNotIn("http://", page)
        self.assertNotIn("https://", page)

    def test_file_name_has_the_scan_time(self):
        scan = make_scan()
        scan["metadata"]["scan_time"] = "2026-11-01T14:30:00+00:00"
        self.assertEqual(html_report.report_file_name(scan), "cloudguardian-report-2026-11-01-1430.html")


class SavedScanReportTests(unittest.TestCase):
    """E-4 S-10-5: a scan reopened from Saved scans gives the same report content."""

    def setUp(self):
        import tempfile
        from storage import db

        self.db = db
        self.tmp = tempfile.TemporaryDirectory()
        self.path = self.tmp.name + "/test.db"
        db.init_db(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_reopened_scan_has_the_same_report(self):
        scan = explained_scan()
        ok, error = self.db.save_scan(scan, self.path)
        self.assertTrue(ok, error)
        ok, error = self.db.save_explanations(scan["metadata"]["scan_id"], scan["explanations"], self.path)
        self.assertTrue(ok, error)
        loaded, error = self.db.load_scan(scan["metadata"]["scan_id"], self.path)
        self.assertIsNone(error)

        original = html_report.build_report(scan)
        reopened = html_report.build_report(loaded)
        for text in ["admin-user", "bad-bucket", "locked-bucket", "<li>Remove the admin policy</li>",
                     "High: 1, Medium: 1, Low: 0, Passed: 1, Incomplete: 1"]:
            self.assertIn(text, original)
            self.assertIn(text, reopened)
        self.assertEqual(len(original), len(reopened))


class DownloadButtonTests(unittest.TestCase):
    """E-4 S-10-5: the Results tab offers the report once a scan is open."""

    def setUp(self):
        import os
        import tempfile
        from streamlit.testing.v1 import AppTest

        self.tmp = tempfile.TemporaryDirectory()
        os.environ["CLOUDGUARDIAN_DB"] = os.path.join(self.tmp.name, "test.db")
        self.at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"),
                                    default_timeout=20)

    def tearDown(self):
        import os
        os.environ.pop("CLOUDGUARDIAN_DB", None)
        self.tmp.cleanup()

    def button(self):
        return [b for b in self.at.get("download_button") if b.proto.label == "Download report"][0]

    def test_button_offers_an_html_file_when_a_scan_is_open(self):
        self.at.session_state.scan = explained_scan()
        self.at.run()
        self.assertFalse(self.at.exception)
        self.assertFalse(self.button().proto.disabled)
        self.assertTrue(self.button().proto.url.endswith(".html"))

    def test_button_is_disabled_with_no_scan(self):
        self.at.run()
        self.assertFalse(self.at.exception)
        self.assertTrue(self.button().proto.disabled)


if __name__ == "__main__":
    unittest.main()
