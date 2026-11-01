"""Tests for the AI explanations with malformed, missing and failed replies (E-4 S-9-5).

No real AI is called. A fake client stands in for Anthropic, so these run
offline and cost nothing. The rule for every failure: the finding stays as
it is and its explanation is just marked unavailable.
"""

import json
import os
import unittest
from types import SimpleNamespace
from unittest import mock

import anthropic
import httpx2

import results
from ai import client as ai_client
from ai import formatter


def make_scan(count=2, evidence=None):
    scan = results.new_scan(["IAM"], "123456789012")
    scan_id = scan["metadata"]["scan_id"]
    for number in range(count):
        check = results.make_check(scan_id, "IAM", f"user{number}", "iam_user_mfa", "fail",
                                   evidence or {"mfa_devices": 0})
        scan["checks"].append(check)
        scan["findings"].append(results.make_finding(check, "User has no MFA device", "High"))
    return scan


def good_reply(request):
    """Explains every finding it was sent, the way a working AI would."""
    batch = json.loads(request["messages"][0]["content"])
    return json.dumps({"explanations": [
        {"finding_id": f["finding_id"], "risk_explanation": "A stolen password is enough to sign in.",
         "recommended_steps": ["  Open IAM  ", "Assign an MFA device", " "]} for f in batch]})


class FakeClient:
    """Stands in for anthropic.Anthropic. reply is text or a function of the request."""

    def __init__(self, reply=good_reply, error=None, stop_reason="end_turn"):
        self.reply, self.error, self.stop_reason = reply, error, stop_reason
        self.requests = []
        self.messages = self

    def create(self, **request):
        self.requests.append(request)
        if self.error:
            raise self.error
        text = self.reply(request) if callable(self.reply) else self.reply
        return SimpleNamespace(stop_reason=self.stop_reason,
                               content=[SimpleNamespace(type="text", text=text)])


def explain(scan, fake, api_key="sk-ant-test-not-real"):
    with mock.patch("anthropic.Anthropic", return_value=fake):
        return ai_client.explain_scan(scan, api_key=api_key, model="claude-opus-5-5")


def statuses(explanations):
    return [e["explanation_status"] for e in explanations]


REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


class WorkingReplyTests(unittest.TestCase):
    def test_every_finding_gets_its_explanation(self):
        scan = make_scan()
        explanations = explain(scan, FakeClient())
        self.assertEqual(statuses(explanations), ["available", "available"])
        self.assertEqual([e["finding_id"] for e in explanations],
                         [f["finding_id"] for f in scan["findings"]])

    def test_steps_are_trimmed_and_blank_ones_dropped(self):
        explanation = explain(make_scan(1), FakeClient())[0]
        self.assertEqual(json.loads(explanation["recommended_steps_json"]),
                         ["Open IAM", "Assign an MFA device"])

    def test_findings_are_sent_in_batches_of_five(self):
        fake = FakeClient()
        explanations = explain(make_scan(7), fake)
        self.assertEqual(len(fake.requests), 2)
        self.assertEqual(statuses(explanations), ["available"] * 7)

    def test_rules_results_are_not_changed(self):
        scan = make_scan()
        before = json.dumps([scan["checks"], scan["findings"]])
        explain(scan, FakeClient())
        self.assertEqual(json.dumps([scan["checks"], scan["findings"]]), before)


class BadReplyTests(unittest.TestCase):
    def test_not_json(self):
        self.assertEqual(statuses(explain(make_scan(), FakeClient("{not json"))), ["unavailable"] * 2)

    def test_wrong_shape(self):
        self.assertEqual(statuses(explain(make_scan(), FakeClient('{"answers": []}'))), ["unavailable"] * 2)

    def test_one_finding_left_out(self):
        def half(request):
            batch = json.loads(request["messages"][0]["content"])[:1]
            return json.dumps({"explanations": [{"finding_id": f["finding_id"], "risk_explanation": "Risk.",
                                                 "recommended_steps": ["Fix it"]} for f in batch]})
        self.assertEqual(statuses(explain(make_scan(), FakeClient(half))), ["available", "unavailable"])

    def test_explanation_for_a_finding_we_did_not_send_is_ignored(self):
        reply = json.dumps({"explanations": [{"finding_id": "made-up", "risk_explanation": "Risk.",
                                              "recommended_steps": ["Fix it"]}]})
        explanations = explain(make_scan(1), FakeClient(reply))
        self.assertEqual(statuses(explanations), ["unavailable"])
        self.assertNotIn("made-up", [e["finding_id"] for e in explanations])

    def test_empty_explanation_or_bad_steps(self):
        def broken(request):
            first, second = json.loads(request["messages"][0]["content"])
            return json.dumps({"explanations": [
                {"finding_id": first["finding_id"], "risk_explanation": "  ", "recommended_steps": []},
                {"finding_id": second["finding_id"], "risk_explanation": "Risk.", "recommended_steps": [1, 2]}]})
        self.assertEqual(statuses(explain(make_scan(), FakeClient(broken))), ["unavailable"] * 2)

    def test_refusal_or_cut_off_reply(self):
        for stop_reason in ["refusal", "max_tokens"]:
            explanations = explain(make_scan(), FakeClient(stop_reason=stop_reason))
            self.assertEqual(statuses(explanations), ["unavailable"] * 2, stop_reason)


class FailedRequestTests(unittest.TestCase):
    def check_failure(self, error):
        scan = make_scan()
        explanations = explain(scan, FakeClient(error=error))
        self.assertEqual(statuses(explanations), ["unavailable"] * 2)
        self.assertEqual(scan["errors"][-1]["stage"], "AI")
        return scan["errors"][-1]["message"]

    def test_timeout(self):
        self.assertEqual(self.check_failure(anthropic.APITimeoutError(request=REQUEST)), "APITimeoutError")

    def test_no_connection(self):
        message = self.check_failure(anthropic.APIConnectionError(request=REQUEST))
        self.assertEqual(message, "APIConnectionError")

    def test_rejected_key_records_only_the_error_type(self):
        response = httpx2.Response(401, request=REQUEST)
        error = anthropic.AuthenticationError("invalid x-api-key sk-ant-secret", response=response, body=None)
        message = self.check_failure(error)
        self.assertEqual(message, "AuthenticationError")
        self.assertNotIn("sk-ant-secret", message)

    def test_rate_limited(self):
        response = httpx2.Response(429, request=REQUEST)
        error = anthropic.RateLimitError("slow down", response=response, body=None)
        self.assertEqual(self.check_failure(error), "RateLimitError")

    def test_no_key_at_all(self):
        scan = make_scan()
        with mock.patch.dict(os.environ, {}, clear=True):
            explanations = ai_client.explain_scan(scan, api_key=None, model="claude-opus-5-5")
        self.assertEqual(statuses(explanations), ["unavailable"] * 2)
        self.assertEqual(scan["errors"][-1]["message"], "No API key set.")


class WhatGetsSentTests(unittest.TestCase):
    def sent(self, scan):
        fake = FakeClient()
        explain(scan, fake)
        return fake.requests[0]["messages"][0]["content"]

    def test_account_id_is_not_sent(self):
        self.assertNotIn("123456789012", self.sent(make_scan()))

    def test_secret_fields_and_whole_key_ids_are_removed(self):
        scan = make_scan(1, {"secret_value": "hunter2", "note": "key AKIAABCDEFGHIJKLMNOP found"})
        sent = self.sent(scan)
        self.assertNotIn("hunter2", sent)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", sent)
        self.assertIn("[removed]", sent)

    def test_api_key_is_never_in_the_request(self):
        fake = FakeClient()
        explain(make_scan(), fake, api_key="sk-ant-should-not-appear")
        self.assertNotIn("sk-ant-should-not-appear", json.dumps(fake.requests, default=str))

    def test_reply_must_follow_the_json_schema(self):
        fake = FakeClient()
        explain(make_scan(), fake)
        self.assertEqual(fake.requests[0]["output_config"]["format"]["type"], "json_schema")


class FormatterTests(unittest.TestCase):
    def test_no_reply_marks_everything_unavailable(self):
        self.assertEqual(statuses(formatter.parse_reply(None, ["a", "b"])), ["unavailable"] * 2)

    def test_keeps_the_order_of_the_findings(self):
        reply = json.dumps({"explanations": [
            {"finding_id": "b", "risk_explanation": "B.", "recommended_steps": ["x"]},
            {"finding_id": "a", "risk_explanation": "A.", "recommended_steps": ["y"]}]})
        self.assertEqual([e["finding_id"] for e in formatter.parse_reply(reply, ["a", "b"])], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
