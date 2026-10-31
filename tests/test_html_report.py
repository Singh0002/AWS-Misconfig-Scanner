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


if __name__ == "__main__":
    unittest.main()
