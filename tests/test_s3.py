"""Tests for the three S3 public-access rules on collected data (E-2 S-3-6).

These fake the AWS responses and run them through collect_s3 and then the
rules, so they check that the collector and the rules work together. Each
rule has a passing, failing and missing or denied case.
"""

import json
import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

import results
from collectors import s3
from detection import findings

PRIVATE_ACL = {"Grants": [{"Grantee": {"Type": "CanonicalUser", "ID": "abc"}, "Permission": "FULL_CONTROL"}]}
PUBLIC_ACL = {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                          "Permission": "READ"}]}
ALL_ON = {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                             "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
ONE_OFF = {"PublicAccessBlockConfiguration": {"BlockPublicAcls": False, "IgnorePublicAcls": True,
                                              "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
PUBLIC_READ = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}


def policy(statement):
    return {"Policy": json.dumps({"Statement": [statement]})}


def fake_call(response):
    """A fake AWS call. A string is an error code to raise, anything else is the response."""
    if isinstance(response, str):
        return MagicMock(side_effect=ClientError({"Error": {"Code": response}}, "call"))
    return MagicMock(return_value=response)


def fake_session(client):
    session = MagicMock()
    session.client.return_value = client
    return session


def scan_bucket(rule_id, acl=PRIVATE_ACL, block=ALL_ON, bucket_policy="NoSuchBucketPolicy"):
    """Collects and checks one fake bucket, then returns the status for rule_id."""
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [{"Buckets": [{"Name": "b"}]}]
    client.get_bucket_acl = fake_call(acl)
    client.get_public_access_block = fake_call(block)
    client.get_bucket_policy = fake_call(bucket_policy)
    client.get_bucket_versioning = fake_call({"Status": "Enabled"})

    scan = results.new_scan(["S3"])
    findings.check_s3(scan, s3.collect_s3(fake_session(client)))
    for check in scan["checks"]:
        if check["rule_id"] == rule_id:
            return check["status"]


class PublicAccessTests(unittest.TestCase):
    def test_public_acl(self):
        self.assertEqual(scan_bucket("s3_public_acl"), "pass")
        self.assertEqual(scan_bucket("s3_public_acl", acl=PUBLIC_ACL), "fail")
        self.assertEqual(scan_bucket("s3_public_acl", acl="AccessDenied"), "incomplete")

    def test_block_public_access(self):
        self.assertEqual(scan_bucket("s3_block_public_access"), "pass")
        self.assertEqual(scan_bucket("s3_block_public_access", block=ONE_OFF), "fail")
        missing = "NoSuchPublicAccessBlockConfiguration"
        self.assertEqual(scan_bucket("s3_block_public_access", block=missing), "fail")
        self.assertEqual(scan_bucket("s3_block_public_access", block="AccessDenied"), "incomplete")

    def test_wildcard_principal(self):
        self.assertEqual(scan_bucket("s3_wildcard_principal"), "pass")
        self.assertEqual(scan_bucket("s3_wildcard_principal", bucket_policy=policy(PUBLIC_READ)), "fail")
        limited = dict(PUBLIC_READ, Condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}})
        self.assertEqual(scan_bucket("s3_wildcard_principal", bucket_policy=policy(limited)), "pass")
        self.assertEqual(scan_bucket("s3_wildcard_principal", bucket_policy="AccessDenied"), "incomplete")

    def test_denied_bucket_list_is_recorded_not_crashed(self):
        client = MagicMock()
        client.get_paginator.return_value.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "ListBuckets")
        collected = s3.collect_s3(fake_session(client))
        self.assertEqual(collected["records"], [])
        self.assertEqual(collected["errors"][0]["message"], "AccessDenied")


if __name__ == "__main__":
    unittest.main()
