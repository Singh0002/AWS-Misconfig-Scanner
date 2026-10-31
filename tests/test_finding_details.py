"""Tests for the finding details panel on the Results tab (E-4 S-7-3)."""

import os
import tempfile
import unittest

import finding_details
import results


def make_scan(explanation_status=None, risk_text=None, steps=None):
    """A scan with one failed versioning check, and optionally an AI explanation for it."""
    scan = results.new_scan(["S3"], "123456789012")
    scan_id = scan["metadata"]["scan_id"]
    passed = results.make_check(scan_id, "S3", "good-bucket", "s3_versioning", "pass")
    failed = results.make_check(scan_id, "S3", "bad-bucket", "s3_versioning", "fail",
                                {"versioning_status": "Suspended"})
    finding = results.make_finding(failed, "Versioning is not enabled", "Medium")
    scan["checks"] += [passed, failed]
    scan["findings"].append(finding)
    if explanation_status:
        scan["explanations"].append(results.make_explanation(
            finding["finding_id"], explanation_status, risk_text, steps))
    return scan


class DetailsTests(unittest.TestCase):
    def test_details_match_the_failed_check(self):
        scan = make_scan()
        info = finding_details.details(scan, scan["findings"][0])
        self.assertEqual(info["severity"], "Medium")
        self.assertEqual(info["issue"], "Versioning is not enabled")
        self.assertEqual(info["service"], "S3")
        self.assertEqual(info["resource"], "bad-bucket")
        self.assertEqual(info["rule_id"], "s3_versioning")
        self.assertEqual(info["evidence"], ["Versioning status: Suspended"])

    def test_label(self):
        scan = make_scan()
        self.assertEqual(finding_details.label(scan, scan["findings"][0]),
                         "Medium | S3 | bad-bucket | Versioning is not enabled")

    def test_nested_evidence_reads_as_words(self):
        lines = finding_details.evidence_lines(
            '{"public_grants": [{"group": "All Users", "permission": "READ"}], "never_used": true}')
        self.assertEqual(lines, ["Public grants: group All Users, permission READ", "Never used: yes"])

    def test_bad_evidence_json_shows_nothing(self):
        self.assertEqual(finding_details.evidence_lines("{not json"), [])
        self.assertEqual(finding_details.evidence_lines(None), [])


class ExplanationTests(unittest.TestCase):
    def ai(self, scan):
        return finding_details.details(scan, scan["findings"][0])["explanation"]

    def test_available_shows_text_and_steps(self):
        ai = self.ai(make_scan("available", "Deleted files can't be recovered.",
                               ["Open the bucket", "Turn on versioning"]))
        self.assertEqual(ai["state"], "available")
        self.assertEqual(ai["text"], "Deleted files can't be recovered.")
        self.assertEqual(ai["steps"], ["Open the bucket", "Turn on versioning"])

    def test_pending(self):
        ai = self.ai(make_scan("pending"))
        self.assertEqual(ai["state"], "pending")
        self.assertIn("isn't ready", ai["message"])

    def test_unavailable_says_the_rule_result_still_counts(self):
        ai = self.ai(make_scan("unavailable"))
        self.assertEqual(ai["state"], "unavailable")
        self.assertIn("still correct", ai["message"])

    def test_no_explanation_record(self):
        self.assertEqual(self.ai(make_scan())["state"], "none")

    def test_available_but_empty_is_treated_as_unavailable(self):
        self.assertEqual(self.ai(make_scan("available"))["state"], "unavailable")

    def test_bad_steps_json_keeps_the_text(self):
        scan = make_scan("available", "Some risk.")
        scan["explanations"][0]["recommended_steps_json"] = "{not json"
        ai = self.ai(scan)
        self.assertEqual((ai["state"], ai["text"], ai["steps"]), ("available", "Some risk.", []))


class ResultsTabTests(unittest.TestCase):
    """Runs the real app.py with a scan already open on the Results tab."""

    def setUp(self):
        from streamlit.testing.v1 import AppTest

        self.tmp = tempfile.TemporaryDirectory()
        os.environ["CLOUDGUARDIAN_DB"] = os.path.join(self.tmp.name, "test.db")
        self.at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"),
                                    default_timeout=20)

    def tearDown(self):
        os.environ.pop("CLOUDGUARDIAN_DB", None)
        self.tmp.cleanup()

    def text_on_page(self):
        parts = [m.value for m in self.at.markdown] + [t.value for t in self.at.text]
        parts += [i.value for i in self.at.info]
        return "\n".join(parts)

    def test_picker_and_details_show_for_a_finding(self):
        self.at.session_state.scan = make_scan("available", "Deleted files can't be recovered.",
                                               ["Turn on versioning"])
        self.at.run()
        self.assertFalse(self.at.exception)
        picker = [s for s in self.at.selectbox if s.label == "Finding details"][0]
        self.assertIn("bad-bucket", picker.format_func(picker.value))
        page = self.text_on_page()
        self.assertIn("Versioning is not enabled", page)
        self.assertIn("Versioning status: Suspended", page)
        self.assertIn("Deleted files can't be recovered.", page)
        self.assertIn("1. Turn on versioning", page)

    def test_missing_explanation_shows_a_message_not_an_error(self):
        self.at.session_state.scan = make_scan("unavailable")
        self.at.run()
        self.assertFalse(self.at.exception)
        self.assertIn("still correct", self.text_on_page())

    def test_no_picker_when_there_are_no_findings(self):
        scan = make_scan()
        scan["findings"] = []
        self.at.session_state.scan = scan
        self.at.run()
        self.assertFalse(self.at.exception)
        self.assertEqual([s for s in self.at.selectbox if s.label == "Finding details"], [])


if __name__ == "__main__":
    unittest.main()
