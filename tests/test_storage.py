import os
import sqlite3
import tempfile
import unittest

import results
from storage import db

EXPECTED_TABLES = {"scans", "checks", "findings", "explanations", "scan_errors"}


class StorageSchemaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "test.db")
        ok, error = db.init_db(self.path)
        self.assertTrue(ok, error)

    def tearDown(self):
        self.tmp.cleanup()

    def test_creates_five_tables(self):
        conn = db.connect(self.path)
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        names = set()
        for row in rows:
            names.add(row["name"])
        conn.close()
        self.assertEqual(names, EXPECTED_TABLES)

    def test_init_is_repeatable(self):
        ok, error = db.init_db(self.path)
        self.assertTrue(ok, error)

    def test_new_database_is_empty(self):
        scans, error = db.list_scans(self.path)
        self.assertIsNone(error)
        self.assertEqual(scans, [])

    def test_foreign_keys_enforced(self):
        conn = db.connect(self.path)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO checks (check_id, scan_id, service, resource_id, rule_id, status) "
                "VALUES ('c1', 'missing-scan', 'S3', 'bucket', 's3_versioning', 'pass')")
        conn.close()

    def test_rejects_unknown_status(self):
        conn = db.connect(self.path)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO scans (scan_id, scan_time, selected_services, scan_status, coverage_status) "
                "VALUES ('s1', '2026-10-13T00:00:00Z', '[\"S3\"]', 'done', 'complete')")
        conn.close()

    def test_delete_scan_cascades(self):
        conn = db.connect(self.path)
        with conn:
            conn.execute(
                "INSERT INTO scans VALUES ('s1', NULL, '2026-10-13T00:00:00Z', '[\"S3\"]', 'completed', 'complete')")
            conn.execute(
                "INSERT INTO checks VALUES ('c1', 's1', 'S3', 'bucket', 's3_versioning', 'fail', '{}', NULL)")
            conn.execute("INSERT INTO findings VALUES ('f1', 'c1', 'Versioning disabled', 'Medium')")
            conn.execute("INSERT INTO explanations VALUES ('f1', 'pending', NULL, NULL)")
            conn.execute("DELETE FROM scans WHERE scan_id = 's1'")
        for table in ("checks", "findings", "explanations"):
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            self.assertEqual(count, 0, table)
        conn.close()


def sample_scan():
    # small fake S3 scan with one of each: fail, pass, incomplete, and an error
    scan = results.new_scan(["S3"], account_id="123456789012")
    scan_id = scan["metadata"]["scan_id"]
    failed = results.make_check(scan_id, "S3", "public-bucket", "s3_public_acl", "fail",
                                evidence={"grantee": "AllUsers"})
    passed = results.make_check(scan_id, "S3", "public-bucket", "s3_versioning", "pass")
    incomplete = results.make_check(scan_id, "S3", "locked-bucket", "s3_https_only", "incomplete",
                                    reason="Bucket policy could not be read.")
    scan["checks"] = [failed, passed, incomplete]
    scan["findings"] = [results.make_finding(failed, "Bucket ACL allows public read.", "High")]
    scan["errors"] = [results.make_error(scan_id, "collection", "get_bucket_policy",
                                         "AccessDenied", "locked-bucket")]
    scan["metadata"]["scan_status"] = "completed"
    scan["metadata"]["coverage_status"] = "incomplete"
    return scan


class SaveLoadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "test.db")
        db.init_db(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_save_then_load_gives_same_scan(self):
        scan = sample_scan()
        ok, error = db.save_scan(scan, self.path)
        self.assertTrue(ok, error)
        loaded, error = db.load_scan(scan["metadata"]["scan_id"], self.path)
        self.assertIsNone(error)
        self.assertEqual(loaded, scan)

    def test_scan_with_no_findings(self):
        scan = results.new_scan(["IAM"])
        scan_id = scan["metadata"]["scan_id"]
        scan["checks"] = [results.make_check(scan_id, "IAM", "root", "iam_root_mfa", "pass")]
        db.save_scan(scan, self.path)
        loaded, _ = db.load_scan(scan_id, self.path)
        self.assertEqual(loaded["findings"], [])
        self.assertEqual(len(loaded["checks"]), 1)

    def test_failed_save_saves_nothing(self):
        scan = sample_scan()
        scan["findings"][0]["severity"] = "Critical"  # not allowed, so the save should fail
        ok, error = db.save_scan(scan, self.path)
        self.assertFalse(ok)
        self.assertEqual(error["operation"], "save_scan")
        self.assertEqual(db.list_scans(self.path)[0], [])

    def test_duplicate_scan_id_rejected(self):
        scan = sample_scan()
        db.save_scan(scan, self.path)
        ok, _ = db.save_scan(scan, self.path)
        self.assertFalse(ok)

    def test_explanations_saved_later(self):
        scan = sample_scan()
        scan_id = scan["metadata"]["scan_id"]
        finding_id = scan["findings"][0]["finding_id"]
        db.save_scan(scan, self.path)

        ok, error = db.save_explanations(
            scan_id, [results.make_explanation(finding_id, "available", "Anyone can read it.",
                                               ["Remove the public grant."])], self.path)
        self.assertTrue(ok, error)
        loaded, _ = db.load_scan(scan_id, self.path)
        self.assertEqual(loaded["explanations"][0]["explanation_status"], "available")

        # saving a second time should replace it, not add another row
        db.save_explanations(scan_id, [results.make_explanation(finding_id, "unavailable")],
                             self.path)
        loaded, _ = db.load_scan(scan_id, self.path)
        self.assertEqual(len(loaded["explanations"]), 1)
        self.assertEqual(loaded["explanations"][0]["explanation_status"], "unavailable")

    def test_explanation_for_other_scan_rejected(self):
        first, second = sample_scan(), sample_scan()
        db.save_scan(first, self.path)
        db.save_scan(second, self.path)
        other_finding = second["findings"][0]["finding_id"]
        ok, error = db.save_explanations(
            first["metadata"]["scan_id"],
            [results.make_explanation(other_finding, "pending")], self.path)
        self.assertFalse(ok)
        self.assertIn("not in scan", error["message"])

    def test_scans_stay_separate(self):
        first, second = sample_scan(), sample_scan()
        db.save_scan(first, self.path)
        db.save_scan(second, self.path)
        loaded, _ = db.load_scan(first["metadata"]["scan_id"], self.path)
        self.assertEqual(loaded, first)

        ok, _ = db.delete_scan(first["metadata"]["scan_id"], self.path)
        self.assertTrue(ok)
        scans, _ = db.list_scans(self.path)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["scan_id"], second["metadata"]["scan_id"])
        loaded, _ = db.load_scan(second["metadata"]["scan_id"], self.path)
        self.assertEqual(loaded, second)

    def test_missing_scan(self):
        loaded, error = db.load_scan("nope", self.path)
        self.assertIsNone(loaded)
        self.assertIn("not found", error["message"])
        ok, error = db.delete_scan("nope", self.path)
        self.assertFalse(ok)

    def test_resource_names_are_data(self):
        scan = results.new_scan(["S3"])
        scan_id = scan["metadata"]["scan_id"]
        tricky = "bucket'); DROP TABLE scans; --"
        scan["checks"] = [results.make_check(scan_id, "S3", tricky, "s3_versioning", "pass")]
        db.save_scan(scan, self.path)
        loaded, _ = db.load_scan(scan_id, self.path)
        self.assertEqual(loaded["checks"][0]["resource_id"], tricky)


if __name__ == "__main__":
    unittest.main()
