"""5.2 Collector tests (FR-S3-1, FR-IAM-1).

Normal responses, empty lists, more than one page, denied permissions,
throttling and timeouts. A setting AWS says doesn't exist ("missing") has
to come back different from one we couldn't read ("failed"), and the
collectors may only make read-only calls.
"""

import unittest

from botocore.exceptions import ReadTimeoutError

import coordinator
from collectors import iam, s3
from fakes import (DUMMY_SECRET, FakeAWS, FakeSession, bad_bucket, bad_user, good_bucket,
                   good_user)


def collect_s3(aws):
    return s3.collect_s3(FakeSession(aws))


def collect_iam(aws):
    return iam.collect_iam(FakeSession(aws))


class NormalResponseTests(unittest.TestCase):
    def test_s3_reads_every_setting_for_a_bucket(self):
        record = collect_s3(FakeAWS(buckets=[bad_bucket("b1")]))["records"][0]
        self.assertEqual(record["resource_id"], "b1")
        for field in ["acl", "public_access_block", "versioning", "policy"]:
            self.assertIn(record[field]["status"], ["available", "missing"], field)
        self.assertEqual(record["policy"]["value"]["Statement"][0]["Sid"], "PublicRead")

    def test_iam_reads_every_setting_for_a_user(self):
        collected = collect_iam(FakeAWS(users=[bad_user("u1")]))
        record = collected["records"][0]
        self.assertEqual(record["inline_policies"]["value"][0]["name"], "Everything")
        self.assertEqual(record["mfa_devices"]["value"], {"DeviceCount": 0})
        self.assertEqual(record["access_keys"]["value"][0]["Status"], "Active")
        self.assertEqual(collected["password_policy"]["status"], "available")
        self.assertEqual(collected["errors"], [])

    def test_empty_account(self):
        self.assertEqual(collect_s3(FakeAWS()), {"records": [], "errors": []})
        collected = collect_iam(FakeAWS())
        self.assertEqual(collected["records"], [])
        self.assertEqual(collected["errors"], [])

    def test_user_with_nothing_attached_is_available_not_missing(self):
        user = {"name": "empty", "inline": [], "attached": [], "mfa": 0, "keys": []}
        record = collect_iam(FakeAWS(users=[user]))["records"][0]
        self.assertEqual(record["inline_policies"], {"status": "available", "value": []})
        self.assertEqual(record["access_keys"], {"status": "available", "value": []})


class PagingTests(unittest.TestCase):
    def test_every_page_of_buckets_and_users_is_read(self):
        # one item per page, so 3 buckets come back as 3 pages
        aws = FakeAWS(buckets=[good_bucket("b1"), good_bucket("b2"), good_bucket("b3")],
                      users=[good_user("u1"), good_user("u2"), good_user("u3")], page_size=1)
        self.assertEqual([r["resource_id"] for r in collect_s3(aws)["records"]], ["b1", "b2", "b3"])
        self.assertEqual([r["resource_id"] for r in collect_iam(aws)["records"]], ["u1", "u2", "u3"])

    def test_every_page_of_a_users_keys_and_devices_is_read(self):
        user = good_user("u1")
        user["mfa"] = 3
        user["keys"] = [user["keys"][0], bad_user("x")["keys"][0]]
        record = collect_iam(FakeAWS(users=[user], page_size=1))["records"][0]
        self.assertEqual(record["mfa_devices"]["value"], {"DeviceCount": 3})
        self.assertEqual(len(record["access_keys"]["value"]), 2)


class FailedRequestTests(unittest.TestCase):
    def test_denied_throttled_and_timed_out_calls_are_failed(self):
        cases = {"denied": "AccessDenied", "throttled": "Throttling",
                 "timed out": ReadTimeoutError(endpoint_url="https://s3.amazonaws.com")}
        for name, error in cases.items():
            with self.subTest(name):
                aws = FakeAWS(buckets=[good_bucket("b1")], users=[good_user("u1")],
                              fail={"get_bucket_acl": error, "list_mfa_devices": error})
                bucket = collect_s3(aws)
                user = collect_iam(aws)
                self.assertEqual(bucket["records"][0]["acl"], {"status": "failed", "value": None})
                self.assertEqual(user["records"][0]["mfa_devices"], {"status": "failed", "value": None})
                # the other settings still get read
                self.assertEqual(bucket["records"][0]["versioning"]["status"], "available")
                self.assertEqual(bucket["errors"][0]["operation"], "get_bucket_acl")
                self.assertEqual(bucket["errors"][0]["resource_id"], "b1")

    def test_one_bad_bucket_does_not_stop_the_others(self):
        aws = FakeAWS(buckets=[good_bucket("b1"), good_bucket("b2")],
                      fail={("get_bucket_policy", "b1"): "AccessDenied"})
        records = collect_s3(aws)["records"]
        self.assertEqual(records[0]["policy"]["status"], "failed")
        self.assertEqual(records[1]["policy"]["status"], "available")

    def test_listing_that_fails_returns_an_error_not_an_empty_account(self):
        aws = FakeAWS(buckets=[good_bucket("b1")], users=[good_user("u1")],
                      fail={"list_buckets": "AccessDenied", "list_users": "AccessDenied"})
        self.assertEqual(collect_s3(aws)["errors"][0]["operation"], "list_buckets")
        self.assertEqual(collect_iam(aws)["errors"][0]["operation"], "list_users")

    def test_error_records_hold_only_the_error_code(self):
        # the fake puts DUMMY_SECRET in every error message AWS sends back
        aws = FakeAWS(buckets=[good_bucket("b1")], fail={"get_bucket_acl": "AccessDenied"})
        error = collect_s3(aws)["errors"][0]
        self.assertEqual(error["message"], "AccessDenied")
        self.assertNotIn(DUMMY_SECRET, str(error))


class MissingVsFailedTests(unittest.TestCase):
    def test_no_bucket_policy_is_missing_but_denied_is_failed(self):
        missing = good_bucket("b1")
        missing["policy"] = None
        missing["block"] = None
        record = collect_s3(FakeAWS(buckets=[missing]))["records"][0]
        self.assertEqual(record["policy"], {"status": "missing", "value": None})
        self.assertEqual(record["public_access_block"], {"status": "missing", "value": None})

        aws = FakeAWS(buckets=[good_bucket("b1")],
                      fail={"get_bucket_policy": "AccessDenied", "get_public_access_block": "AccessDenied"})
        record = collect_s3(aws)["records"][0]
        self.assertEqual(record["policy"]["status"], "failed")
        self.assertEqual(record["public_access_block"]["status"], "failed")

    def test_no_password_policy_is_missing_but_denied_is_failed(self):
        self.assertEqual(collect_iam(FakeAWS(password_policy=None))["password_policy"]["status"], "missing")
        denied = collect_iam(FakeAWS(fail={"get_account_password_policy": "AccessDenied"}))
        self.assertEqual(denied["password_policy"]["status"], "failed")

    def test_only_the_last_4_characters_of_a_key_id_are_kept(self):
        user = bad_user("u1")
        key = collect_iam(FakeAWS(users=[user]))["records"][0]["access_keys"]["value"][0]
        self.assertEqual(key["AccessKeyId"], user["keys"][0]["AccessKeyId"][-4:])

    def test_no_mfa_device_is_a_count_of_zero_not_a_failure(self):
        record = collect_iam(FakeAWS(users=[bad_user("u1")]))["records"][0]
        self.assertEqual(record["mfa_devices"], {"status": "available", "value": {"DeviceCount": 0}})


class ReadOnlyTests(unittest.TestCase):
    def test_a_full_scan_only_makes_read_calls(self):
        aws = FakeAWS(buckets=[bad_bucket("b1"), good_bucket("b2")], users=[bad_user("u1"), good_user("u2")])
        coordinator.run_scan(["S3", "IAM"], None, lambda *args: None, FakeSession(aws))
        self.assertTrue(aws.calls)
        for call in aws.calls:
            self.assertTrue(call.startswith(("get_", "list_")), call)

    def test_a_write_call_is_rejected(self):
        # proves the fake would catch it if the scanner ever tried to change something
        with self.assertRaises(AssertionError):
            FakeAWS().put_bucket_policy(Bucket="b1", Policy="{}")


if __name__ == "__main__":
    unittest.main()
