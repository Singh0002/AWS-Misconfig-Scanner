"""Tests for the setup checks in test_connection.py. No real AWS or AI calls."""

import os
import unittest
from unittest import mock

from botocore.exceptions import ClientError

import test_connection as tc


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "Operation")


class FakeSession:
    """Stands in for a boto3 Session. clients maps a service to a fake client."""

    def __init__(self, clients):
        self.clients = clients

    def client(self, service):
        return self.clients[service]


class TestAwsChecks(unittest.TestCase):
    def test_missing_credentials_gives_clear_message(self):
        env = {"AWS_EC2_METADATA_DISABLED": "true", "AWS_CONFIG_FILE": os.devnull,
               "AWS_SHARED_CREDENTIALS_FILE": os.devnull}
        with mock.patch.dict(os.environ, env, clear=True):
            ok, message = tc.check_aws_credentials(tc.make_session(region="us-east-1"))
        self.assertFalse(ok)
        self.assertIn("aws configure", message)

    def test_credentials_ok_shows_account_only(self):
        sts = mock.Mock()
        sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "secret-arn"}
        ok, message = tc.check_aws_credentials(FakeSession({"sts": sts}))
        self.assertTrue(ok)
        self.assertIn("123456789012", message)
        self.assertNotIn("secret-arn", message)

    def test_expired_credentials(self):
        sts = mock.Mock()
        sts.get_caller_identity.side_effect = client_error("ExpiredToken")
        ok, message = tc.check_aws_credentials(FakeSession({"sts": sts}))
        self.assertFalse(ok)
        self.assertIn("expired", message)

    def test_s3_access_denied(self):
        s3 = mock.Mock()
        s3.list_buckets.side_effect = client_error("AccessDenied")
        ok, message = tc.check_s3_access(FakeSession({"s3": s3}))
        self.assertFalse(ok)
        self.assertIn("read-only", message)

    def test_s3_ok(self):
        s3 = mock.Mock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "a"}, {"Name": "b"}]}
        ok, message = tc.check_s3_access(FakeSession({"s3": s3}))
        self.assertTrue(ok)
        self.assertIn("2 bucket", message)

    def test_iam_access_denied(self):
        iam = mock.Mock()
        iam.list_users.side_effect = client_error("AccessDenied")
        ok, _ = tc.check_iam_access(FakeSession({"iam": iam}))
        self.assertFalse(ok)

    def test_iam_ok_only_reads(self):
        iam = mock.Mock()
        iam.list_users.return_value = {"Users": []}
        ok, _ = tc.check_iam_access(FakeSession({"iam": iam}))
        self.assertTrue(ok)
        iam.list_users.assert_called_once_with(MaxItems=1)

    def test_run_all_skips_s3_and_iam_when_credentials_fail(self):
        sts = mock.Mock()
        sts.get_caller_identity.side_effect = client_error("InvalidClientTokenId")
        with mock.patch.object(tc, "make_session", return_value=FakeSession({"sts": sts})):
            with mock.patch.dict(os.environ, {}, clear=True):
                results = tc.run_all()
        self.assertEqual([r[0] for r in results], ["AWS credentials", "AI key"])


class TestAiKeyCheck(unittest.TestCase):
    def test_no_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            ok, message = tc.check_ai_key()
        self.assertFalse(ok)
        self.assertIn("ANTHROPIC_API_KEY", message)

    def test_key_set_without_request_does_not_call_the_api(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-not-real"}, clear=True):
            with mock.patch("anthropic.Anthropic") as client:
                ok, message = tc.check_ai_key()
        self.assertTrue(ok)
        client.assert_not_called()
        self.assertNotIn("sk-test-not-real", message)

    def test_rejected_key_message_has_no_key_in_it(self):
        import anthropic

        error = anthropic.AuthenticationError(
            "bad key sk-test-not-real", response=mock.Mock(status_code=401, headers={}), body=None
        )
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-not-real"}, clear=True):
            with mock.patch("anthropic.Anthropic") as client:
                client.return_value.messages.create.side_effect = error
                ok, message = tc.check_ai_key(make_request=True)
        self.assertFalse(ok)
        self.assertIn("rejected", message)
        self.assertNotIn("sk-test-not-real", message)


if __name__ == "__main__":
    unittest.main()
