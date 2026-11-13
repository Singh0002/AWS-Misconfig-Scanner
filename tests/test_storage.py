"""5.2 Storage tests (the database requirement, design doc section 6).

Every test uses its own temporary SQLite file, so real scan history is
never touched. Save and load, scans with no findings or missing
explanations, more than one scan, foreign keys, duplicate IDs, rollback,
a busy database, a failed write, and odd text stored as plain data.
"""

import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

import coordinator
import results
from fakes import DUMMY_SECRET, FakeAWS, FakeSession, bad_bucket, bad_user, sample_scan
from storage import db


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "test.db")
        ok, error = db.init_db(self.path)
        self.assertTrue(ok, error)

    def tearDown(self):
        self.tmp.cleanup()

    def save(self, scan):
        ok, error = db.save_scan(scan, self.path)
        self.assertTrue(ok, error)
        return scan["metadata"]["scan_id"]

    def all_rows(self):
        """Every value in every table, as one string."""
        conn = db.connect(self.path)
        text = ""
        for table in ["scans", "checks", "findings", "explanations", "scan_errors"]:
            for row in conn.execute("SELECT * FROM " + table):
                text += json.dumps(list(row)) + "\n"
        conn.close()
        return text

    def test_saved_scan_loads_back_the_same(self):
        scan = sample_scan()
        scan_id = self.save(scan)
        # load_scan opens its own new connection, like after a restart
        loaded, error = db.load_scan(scan_id, self.path)
        self.assertIsNone(error)
        self.assertEqual(loaded, scan)

    def test_scan_with_no_findings_keeps_its_checks(self):
        scan = results.new_scan(["S3"])
        scan["checks"].append(results.make_check(scan["metadata"]["scan_id"], "S3", "b1", "s3_versioning", "pass"))
        loaded, error = db.load_scan(self.save(scan), self.path)
        self.assertEqual(loaded["findings"], [])
        self.assertEqual(len(loaded["checks"]), 1)

    def test_incomplete_checks_and_missing_explanations_are_kept(self):
        scan = sample_scan()
        scan["explanations"] = []
        loaded, error = db.load_scan(self.save(scan), self.path)
        self.assertEqual(loaded["explanations"], [])
        self.assertIn("incomplete", [c["status"] for c in loaded["checks"]])
        self.assertEqual(loaded["metadata"]["coverage_status"], "incomplete")

    def test_explanations_are_saved_later_without_touching_the_findings(self):
        scan = sample_scan()
        scan["explanations"] = []
        scan_id = self.save(scan)
        later = [results.make_explanation(scan["findings"][0]["finding_id"], "available", "Risk.", ["Fix"])]
        ok, error = db.save_explanations(scan_id, later, self.path)
        self.assertTrue(ok, error)
        loaded, error = db.load_scan(scan_id, self.path)
        self.assertEqual(loaded["explanations"], later)
        self.assertEqual(loaded["findings"], scan["findings"])

    def test_errors_are_added_later_to_a_saved_scan(self):
        # the AI runs after the scan is saved, so its errors are added afterwards (E-6 S-12-3)
        scan = sample_scan()
        scan_id = self.save(scan)
        before = len(scan["errors"])
        late = [results.make_error(scan_id, "AI", "messages.create", "APIConnectionError")]
        ok, error = db.save_errors(scan_id, late, self.path)
        self.assertTrue(ok, error)
        loaded, error = db.load_scan(scan_id, self.path)
        self.assertEqual(len(loaded["errors"]), before + 1)
        self.assertEqual(loaded["errors"][-1]["message"], "APIConnectionError")
        self.assertEqual(loaded["findings"], scan["findings"])

    def test_errors_for_an_unknown_or_different_scan_are_refused(self):
        scan_id = self.save(sample_scan())
        ok, error = db.save_errors("made-up", [], self.path)
        self.assertFalse(ok)
        self.assertIn("not found", error["message"])
        ok, error = db.save_errors(scan_id, [results.make_error("other-scan", "AI", "x", "y")], self.path)
        self.assertFalse(ok)
        loaded, error = db.load_scan(scan_id, self.path)
        self.assertNotIn("y", [e["message"] for e in loaded["errors"]])

    def test_several_scans_stay_separate(self):
        first, second = sample_scan("bucket-one"), sample_scan("bucket-two")
        self.save(first)
        self.save(second)
        scans, error = db.list_scans(self.path)
        self.assertEqual(len(scans), 2)
        loaded, error = db.load_scan(first["metadata"]["scan_id"], self.path)
        self.assertEqual(loaded, first)

    def test_deleting_one_scan_leaves_the_other(self):
        first, second = sample_scan(), sample_scan()
        self.save(first)
        self.save(second)
        ok, error = db.delete_scan(first["metadata"]["scan_id"], self.path)
        self.assertTrue(ok, error)
        # its checks, findings, explanations and errors are gone too
        self.assertNotIn(first["metadata"]["scan_id"], self.all_rows())
        loaded, error = db.load_scan(second["metadata"]["scan_id"], self.path)
        self.assertEqual(loaded, second)

    def test_missing_scan_gives_a_not_found_message(self):
        loaded, error = db.load_scan("no-such-scan", self.path)
        self.assertIsNone(loaded)
        self.assertIn("not found", error["message"])

    def test_foreign_keys_are_enforced(self):
        conn = db.connect(self.path)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO checks (check_id, scan_id, service, resource_id, rule_id, status) "
                         "VALUES ('c1', 'no-such-scan', 'S3', 'b1', 's3_versioning', 'pass')")
        conn.close()
        # an explanation for a finding that isn't in the scan is refused too
        scan_id = self.save(sample_scan())
        ok, error = db.save_explanations(scan_id, [results.make_explanation("made-up", "unavailable")], self.path)
        self.assertFalse(ok)

    def test_duplicate_scan_id_is_refused_and_the_first_is_kept(self):
        scan = sample_scan()
        self.save(scan)
        ok, error = db.save_scan(scan, self.path)
        self.assertFalse(ok)
        self.assertEqual(error["stage"], "storage")
        loaded, error = db.load_scan(scan["metadata"]["scan_id"], self.path)
        self.assertEqual(loaded, scan)

    def test_a_failed_save_rolls_everything_back(self):
        scan = sample_scan()
        # a bad severity makes the last insert fail after the others went in
        scan["findings"][1]["severity"] = "Critical"
        ok, error = db.save_scan(scan, self.path)
        self.assertFalse(ok)
        scans, error = db.list_scans(self.path)
        self.assertEqual(scans, [])
        self.assertEqual(self.all_rows(), "")

    def test_busy_database_returns_a_save_error(self):
        locker = sqlite3.connect(self.path)
        locker.execute("BEGIN EXCLUSIVE")
        real_connect = sqlite3.connect
        # wait 0.1 seconds for the lock instead of the usual 5
        with mock.patch("sqlite3.connect", lambda path: real_connect(path, timeout=0.1)):
            ok, error = db.save_scan(sample_scan(), self.path)
        locker.rollback()
        locker.close()
        self.assertFalse(ok)
        self.assertIn("locked", error["message"])

    def test_failed_write_returns_an_error(self):
        # the "folder" is really a file, so the database can't be made there
        blocker = os.path.join(self.tmp.name, "not-a-folder")
        open(blocker, "w").close()
        ok, error = db.init_db(os.path.join(blocker, "test.db"))
        self.assertFalse(ok)
        self.assertEqual(error["operation"], "init_db")

    def test_names_and_ai_text_are_stored_as_plain_data(self):
        tricky = "x'); DROP TABLE scans; --"
        scan = sample_scan(resource=tricky, explanation_text=tricky + " <script>alert(1)</script>")
        loaded, error = db.load_scan(self.save(scan), self.path)
        self.assertEqual(loaded, scan)
        scans, error = db.list_scans(self.path)
        self.assertEqual(len(scans), 1)

    def test_dummy_credentials_never_reach_the_database(self):
        # a real scan where AWS errors carry a secret and users have whole key IDs
        aws = FakeAWS(buckets=[bad_bucket("b1")], users=[bad_user("u1")],
                      fail={"get_bucket_versioning": "AccessDenied"})
        scan = coordinator.run_scan(["S3", "IAM"], None, lambda *args: None, FakeSession(aws))
        self.save(scan)
        text = self.all_rows()
        self.assertNotIn(DUMMY_SECRET, text)
        for key in aws.users["u1"]["keys"]:
            self.assertNotIn(key["AccessKeyId"], text)


if __name__ == "__main__":
    unittest.main()
