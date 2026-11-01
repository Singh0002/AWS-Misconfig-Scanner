"""5.2 AI processing tests (FR-AI-1, FR-AI-2, AI-1 to AI-6, NFR-SEC-1).

No real AI is called. FakeAI stands in for Anthropic, so these run offline
and cost nothing. JSON formatting, secret removal, valid explanations,
unknown or duplicate finding IDs, missing fields, malformed replies, rate
limits and timeouts. Whatever happens, the finding and its severity never
change and a failure just marks the explanation unavailable.
"""

import json
import os
import unittest
from unittest import mock

import anthropic
import httpx2

import results
from ai import client as ai_client
from fakes import ACCOUNT_ID, DUMMY_SECRET, FakeAI

REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def make_scan(count=2, evidence=None):
    scan = results.new_scan(["IAM"], ACCOUNT_ID)
    scan_id = scan["metadata"]["scan_id"]
    for number in range(count):
        check = results.make_check(scan_id, "IAM", "user" + str(number), "iam_user_mfa", "fail",
                                   evidence or {"mfa_devices": 0})
        scan["checks"].append(check)
        scan["findings"].append(results.make_finding(check, "User has no MFA device", "High"))
    return scan


def explain(scan, fake, api_key="sk-ant-dummy-key"):
    with mock.patch("anthropic.Anthropic", return_value=fake):
        return ai_client.explain_scan(scan, api_key=api_key, model="claude-opus-5-5")


def statuses(explanations):
    return [e["explanation_status"] for e in explanations]


def reply(*items):
    return json.dumps({"explanations": list(items)})


def item(finding_id, text="Risk.", steps=("Fix it",)):
    return {"finding_id": finding_id, "risk_explanation": text, "recommended_steps": list(steps)}


class RequestTests(unittest.TestCase):
    def sent(self, scan, api_key="sk-ant-dummy-key"):
        fake = FakeAI()
        explain(scan, fake, api_key)
        return fake.requests[0]

    def test_findings_are_sent_as_json(self):
        request = self.sent(make_scan(1))
        batch = json.loads(request["messages"][0]["content"])
        self.assertEqual(set(batch[0]), {"finding_id", "service", "resource", "rule", "issue", "severity", "evidence"})
        self.assertEqual(request["output_config"]["format"]["type"], "json_schema")

    def test_secrets_are_removed_before_sending(self):
        evidence = {"secret_access_key": DUMMY_SECRET, "session_token": "dummy-token",
                    "note": "key AKIAABCDEFGHIJKLMNOP was found"}
        sent = json.dumps(self.sent(make_scan(1, evidence), api_key="sk-ant-must-not-appear"), default=str)
        for secret in [DUMMY_SECRET, "dummy-token", "AKIAABCDEFGHIJKLMNOP", "sk-ant-must-not-appear", ACCOUNT_ID]:
            self.assertNotIn(secret, sent)

    def test_the_model_gets_no_tools(self):
        # so it can only answer with text and can't change anything in AWS
        self.assertNotIn("tools", self.sent(make_scan(1)))

    def test_no_findings_means_no_request(self):
        fake = FakeAI()
        self.assertEqual(explain(make_scan(0), fake), [])
        self.assertEqual(fake.requests, [])

    def test_big_scans_are_split_into_smaller_requests(self):
        fake = FakeAI()
        explanations = explain(make_scan(7), fake)
        self.assertEqual(len(fake.requests), 2)
        self.assertEqual(statuses(explanations), ["available"] * 7)


class ReplyTests(unittest.TestCase):
    def test_valid_explanations_are_matched_to_their_findings(self):
        scan = make_scan()
        explanations = explain(scan, FakeAI())
        self.assertEqual([e["finding_id"] for e in explanations], [f["finding_id"] for f in scan["findings"]])
        self.assertEqual(statuses(explanations), ["available", "available"])
        self.assertEqual(json.loads(explanations[0]["recommended_steps_json"]),
                         ["Open the AWS console", "Turn the setting on"])

    def test_unknown_finding_id_is_ignored(self):
        explanations = explain(make_scan(1), FakeAI(reply(item("made-up-id"))))
        self.assertEqual(statuses(explanations), ["unavailable"])
        self.assertNotIn("made-up-id", [e["finding_id"] for e in explanations])

    def test_duplicate_finding_id_still_gives_one_explanation(self):
        scan = make_scan(1)
        finding_id = scan["findings"][0]["finding_id"]
        explanations = explain(scan, FakeAI(reply(item(finding_id, "First."), item(finding_id, "Second."))))
        self.assertEqual(len(explanations), 1)
        self.assertEqual(explanations[0]["explanation_status"], "available")

    def test_missing_or_wrong_fields_are_unavailable(self):
        scan = make_scan(3)
        ids = [f["finding_id"] for f in scan["findings"]]
        broken = reply({"finding_id": ids[0], "recommended_steps": ["Fix it"]},  # no explanation
                       item(ids[1], text="   "),                               # blank explanation
                       {"finding_id": ids[2], "risk_explanation": "Risk.", "recommended_steps": [1, 2]})
        self.assertEqual(statuses(explain(scan, FakeAI(broken))), ["unavailable"] * 3)

    def test_one_finding_left_out_of_the_reply(self):
        scan = make_scan()
        first = scan["findings"][0]["finding_id"]
        self.assertEqual(statuses(explain(scan, FakeAI(reply(item(first))))), ["available", "unavailable"])

    def test_malformed_replies_are_unavailable(self):
        for name, fake in [("not json", FakeAI("{not json")), ("wrong shape", FakeAI('{"answers": []}')),
                           ("refused", FakeAI(stop_reason="refusal")), ("cut off", FakeAI(stop_reason="max_tokens"))]:
            with self.subTest(name):
                self.assertEqual(statuses(explain(make_scan(), fake)), ["unavailable"] * 2)

    def test_reply_cannot_change_the_finding_or_severity(self):
        scan = make_scan(1)
        before = json.dumps([scan["checks"], scan["findings"]])
        # the AI tries to downgrade the finding
        sneaky = json.dumps({"explanations": [dict(item(scan["findings"][0]["finding_id"]),
                                                   severity="Low", status="pass")]})
        explain(scan, FakeAI(sneaky))
        self.assertEqual(json.dumps([scan["checks"], scan["findings"]]), before)


class FailedRequestTests(unittest.TestCase):
    def check_failure(self, error):
        scan = make_scan()
        before = json.dumps(scan["findings"])
        explanations = explain(scan, FakeAI(error=error))
        self.assertEqual(statuses(explanations), ["unavailable"] * 2)
        self.assertEqual(json.dumps(scan["findings"]), before)
        self.assertEqual(scan["errors"][-1]["stage"], "AI")
        return scan["errors"][-1]["message"]

    def test_rate_limit(self):
        error = anthropic.RateLimitError("slow down", response=httpx2.Response(429, request=REQUEST), body=None)
        self.assertEqual(self.check_failure(error), "RateLimitError")

    def test_timeout(self):
        self.assertEqual(self.check_failure(anthropic.APITimeoutError(request=REQUEST)), "APITimeoutError")

    def test_outage(self):
        self.assertEqual(self.check_failure(anthropic.APIConnectionError(request=REQUEST)), "APIConnectionError")

    def test_rejected_key_only_records_the_error_type(self):
        error = anthropic.AuthenticationError("invalid x-api-key sk-ant-secret",
                                              response=httpx2.Response(401, request=REQUEST), body=None)
        self.assertEqual(self.check_failure(error), "AuthenticationError")

    def test_no_key(self):
        scan = make_scan()
        with mock.patch.dict(os.environ, {}, clear=True):
            explanations = ai_client.explain_scan(scan, api_key=None)
        self.assertEqual(statuses(explanations), ["unavailable"] * 2)
        self.assertEqual(scan["errors"][-1]["message"], "No API key set.")

    def test_timeout_and_retry_limits_are_set(self):
        with mock.patch("anthropic.Anthropic", return_value=FakeAI()) as made:
            ai_client.explain_scan(make_scan(1), api_key="sk-ant-dummy-key")
        self.assertEqual(made.call_args.kwargs["timeout"], 30)
        self.assertEqual(made.call_args.kwargs["max_retries"], 1)


if __name__ == "__main__":
    unittest.main()
