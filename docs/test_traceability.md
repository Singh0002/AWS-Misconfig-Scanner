# CloudGuardian requirements-to-tests traceability (E-8 S-15-3)

Maps each requirement to the automated tests that check it. The tests follow
section 5 of the design doc: one file per module (5.2) and the integration
tests (5.3). They share the fake AWS account and fake AI in `tests/fakes.py`,
and run with:

```
python -m unittest discover tests
```

Status as of 11/13/2026: **144 tests, all passing**. The 2 live tests in
`test_live.py` are skipped unless `CLOUDGUARDIAN_LIVE=1` is set, because they
need the real AWS test account and an Anthropic key.

The requirement IDs come from the requirement list in our Agile planning document.

## Covered by automated tests

| Requirement IDs | Requirement | Tests (file.Class) | Tests | Status |
|---|---|---|---|---|
| DETECT-1 to DETECT-7, FR-DET-1, DOM-4 | The 5 S3 rules: public ACL, Block Public Access (bucket or account), wildcard principal, versioning, HTTPS | test_detection.S3RuleTests | 6 | Pass |
| FR-IAM-1, FR-DET-2, DOM-4 | The 5 IAM rules: admin wildcard, user MFA, root MFA, password policy (13 vs 14 characters, each character type), unused keys (89, 90, 91 days; inactive and never-used keys) | test_detection.IamRuleTests | 8 | Pass |
| DETECT-1 to DETECT-7, FR-DET-2 | Policies that look safe but aren't, or look risky but aren't: "everyone except", empty conditions, HTTPS rules that only partly protect, other ways of writing wildcards and conditions | test_detection.PolicyEdgeCaseTests | 13 | Pass |
| NFR-SAFE-3, OUT-6 | Settings that can't be read, or were never collected, are incomplete, never passed | test_detection.IncompleteTests, test_integration.WorkflowTests | 3 + 1 | Pass |
| FR-DET-3, DETECT-3 to DETECT-7 | Failed checks become findings with the rule's issue and severity; passing checks make none | test_detection.FindingTests | 4 | Pass |
| SCAN-4, SCAN-5, FR-S3-1, FR-IAM-1, DOM-3 | Collectors read every setting, every page, and tell "not set" apart from "couldn't read" | test_collectors (NormalResponseTests, PagingTests, FailedRequestTests, MissingVsFailedTests) | 14 | Pass |
| E-6 S-13-3, NFR-PERF-1 | A scan doesn't ask AWS for the same thing twice: account settings once per scan, and a policy shared by several users is downloaded once | test_collectors.RepeatedRequestTests | 3 | Pass |
| E-6 S-12-2 | Temporary AWS errors are retried a limited number of times, with a time limit on every call | test_coordinator.RetryTests | 1 | Pass |
| NFR-SAFE-1 | The scanner only makes read calls to AWS | test_collectors.ReadOnlyTests, test_integration.WorkflowTests | 2 + 1 | Pass |
| SCAN-1 to SCAN-3, FR-UI-1 | S3, IAM or both; an empty selection doesn't start a scan; one scan at a time; a finished scan or an opened saved scan goes straight to the Results tab, a failed scan stays on Scan | test_coordinator.CoordinatorTests, test_coordinator.ScanPageTests | 7 + 7 | Pass |
| SCAN-6, NFR-SEC-4, OUT-7 | Clear setup errors for missing, expired or denied credentials and the AI key, with no keys shown | test_coordinator.SetupCheckTests | 8 | Pass |
| FR-UI-2, OUT-2 to OUT-5 | Results tab: findings most severe first, service and severity filters, finding details with the AI explanation or a clear message | test_coordinator.ResultsPageTests | 6 | Pass |
| SCAN-6, NFR-SEC-4, FR-AI-1 | Settings tab: Check connection shows each check, shortens the account number, only makes read calls and gives a clear error with no keys; AWS and API key setup help and the AI hallucination warning are shown; dark mode, button color and reset change the theme | test_coordinator.SettingsPageTests | 4 | Pass |
| AI-1 to AI-6, FR-AI-1, FR-AI-2, NFR-SEC-1 | AI explanations: only finding data is sent with secrets removed; bad, missing or failed replies are unavailable and never change a finding | test_ai (RequestTests, ReplyTests, FailedRequestTests) | 18 | Pass |
| OUT-1 (course database outline), NFR-SEC-1 | Save, reopen, list and delete scans; a failed save rolls back; no credentials stored; AI errors are added to a saved scan | test_storage.StorageTests | 16 | Pass |
| OUT-1, FR-REP-1, NFR-SEC-1 | Report has the scan details, findings, explanations and incomplete checks; matches a reopened scan; HTML is escaped; no secrets; Download report button | test_reporting (ReportContentTests, ReportSafetyTests, DownloadButtonTests) | 10 | Pass |
| All of the above together | A known misconfiguration followed through collectors, rules, storage, AI and report; AI outage, failed save and unreadable resources; HTTPS for AWS and Anthropic | test_integration (WorkflowTests, AppWorkflowTests) | 12 | Pass |

## Not covered by the automated tests yet

| Requirement IDs | Requirement | Planned test | Owner | Sprint |
|---|---|---|---|---|
| NFR-PERF-1 | A scan of 10 buckets and 10 users finishes within 5 minutes | test_live.LiveTests on the real test account (written, needs the account) | Martin | 4 |
| All detection requirements | All 10 rules give the expected result on the real test account | System test on the test account (E-8 S-14) | Martin | 4 |
| NFR-SEC-1 to NFR-SEC-3 | No secrets in logs or the UI in real use | Credential-leak sweep (E-6 S-11) | Zach | 4 |
| Portability (6.4) | Installs and runs on Windows and Ubuntu | Clean install check (E-8 S-14, S-16) | Ajay, Martin | 4-5 |
| Acceptance | 2-3 classmates complete setup, scan, report and saved-scan review | User acceptance test (E-8 S-14) | Ajay | 4 |
